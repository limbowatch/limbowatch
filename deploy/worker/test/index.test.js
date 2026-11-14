// The Worker against an in-memory R2 bucket: every nginx behaviour the site and old watchers rely on
// (docs/HOSTING_PLAN.md, step 2). No network.
import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import worker from "../src/index.js";
import {
  SECURITY_HEADERS,
  UNSATISFIABLE,
  contentType,
  corsAllowed,
  keyFor,
  parseCrcMap,
  parseRange,
  resetCrcCache,
} from "../src/serve.js";

const ZIP = new Uint8Array(1000).map((_, i) => i % 251);

async function seed() {
  const files = {
    "index.html": "<h1>home</h1>",
    "tracker/index.html": "<h1>tracker</h1>",
    "advisory/GHSA-2225-fc9v-43cv/index.html": "<h1>advisory</h1>",
    "feed/all.zip": ZIP,
    "feed/index.json": '{"count":1}',
    "feed/GHSA-2225-fc9v-43cv.json": '{"id":"GHSA-2225-fc9v-43cv"}',
    "osv/PyPI/all.zip": ZIP,
    "osv/limbo-db.zip": ZIP,
    "osv/crc32c.map": '"/osv/PyPI/all.zip" "crc32c=XpwhcQ==";\n"/osv/npm/all.zip" "crc32c=AAAAAA==";\n',
    "metrics.json": "{}",
    "press/limbo.csv": "a,b\n1,2\n",
    "assets/site.css": "body{}",
    "sitemap.xml": "<urlset/>",
    "feed/limbo.atom": "<feed/>",
    "robots.txt": "User-agent: *\n",
  };
  for (const [k, v] of Object.entries(files)) await env.SITE.put(k, v);
}

const call = (path, init = {}, host = "limbo.watch") => worker.fetch(new Request(`https://${host}${path}`, init), env);

function expectSecurityHeaders(res) {
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) expect(res.headers.get(k), k).toBe(v);
}

beforeEach(async () => {
  resetCrcCache();
  await seed();
});

describe("module", () => {
  it("exports only the handler: the runtime refuses any other named export of the main module", async () => {
    expect(Object.keys(await import("../src/index.js"))).toEqual(["default"]);
  });
});

describe("paths", () => {
  it("maps URL paths to keys", () => {
    expect(keyFor("/")).toBe("index.html");
    expect(keyFor("/tracker/")).toBe("tracker/index.html");
    expect(keyFor("/feed/all.zip")).toBe("feed/all.zip");
    expect(keyFor("/a%20b.txt")).toBe("a b.txt");
    expect(keyFor("/%E0%A4%A")).toBeNull();
    expect(keyFor("/a/%2e%2e/index.html")).toBeNull();
    expect(keyFor("/a%00")).toBeNull();
    expect(keyFor("//evil.example")).toBeNull();
    expect(keyFor("/%2Fevil.example")).toBeNull();
  });

  it("serves index.html for / and directories, with a query string", async () => {
    for (const [path, body] of [["/", "<h1>home</h1>"], ["/tracker/", "<h1>tracker</h1>"], ["/tracker/?fix=yes", "<h1>tracker</h1>"]]) {
      const res = await call(path);
      expect(res.status).toBe(200);
      expect(await res.text()).toBe(body);
      expect(res.headers.get("Content-Type")).toBe("text/html");
      expect(res.headers.get("Cache-Control")).toBe("max-age=300");
      expectSecurityHeaders(res);
    }
  });

  it("redirects a directory without its slash, keeping the query, to a relative https location", async () => {
    for (const [path, loc] of [["/tracker", "/tracker/"], ["/tracker?fix=yes", "/tracker/?fix=yes"], ["/advisory/GHSA-2225-fc9v-43cv", "/advisory/GHSA-2225-fc9v-43cv/"]]) {
      const res = await call(path);
      expect(res.status).toBe(301);
      expect(res.headers.get("Location")).toBe(loc);
      expectSecurityHeaders(res);
    }
  });

  it("answers 404 with the security headers and no cache time", async () => {
    // (`..` and `%2e%2e` segments are resolved by the URL parser before the Worker sees the path, as nginx does)
    for (const path of ["/nope", "/nope/", "/a%00"]) {
      const res = await call(path);
      expect(res.status).toBe(404);
      expect(await res.text()).toContain("404 Not Found");
      expect(res.headers.get("Cache-Control")).toBeNull();
      expectSecurityHeaders(res);
    }
    const res = await call("/nope", { method: "HEAD" });
    expect(res.status).toBe(404);
  });

  it("never redirects to another host", async () => {
    await env.SITE.put("/evil.example/index.html", "x");
    for (const path of ["//evil.example", "/%2Fevil.example"]) {
      const res = await call(path);
      expect(res.status, path).toBe(404);
      expect(res.headers.get("Location")).toBeNull();
    }
  });

  it("redirects www to the apex", async () => {
    const res = await call("/tracker/?x=1", {}, "www.limbo.watch");
    expect(res.status).toBe(301);
    expect(res.headers.get("Location")).toBe("https://limbo.watch/tracker/?x=1");
  });

  it("allows only GET and HEAD", async () => {
    const res = await call("/", { method: "POST", body: "x" });
    expect(res.status).toBe(405);
    expect(res.headers.get("Allow")).toBe("GET, HEAD");
    expectSecurityHeaders(res);
  });
});

describe("headers", () => {
  it("sends nginx's content types", () => {
    expect(contentType("index.html")).toBe("text/html");
    expect(contentType("press/limbo.csv")).toBe("text/csv; charset=utf-8");
    expect(contentType("feed/limbo.atom")).toBe("application/atom+xml");
    expect(contentType("sitemap.xml")).toBe("text/xml");
    expect(contentType("assets/tracker.js")).toBe("application/javascript");
    expect(contentType("feed/all.zip")).toBe("application/zip");
    expect(contentType("osv/crc32c.map")).toBe("application/octet-stream");
    expect(contentType("a.dir/noext")).toBe("application/octet-stream");
  });

  it("allows any origin for the feed, OSV files and metrics only", async () => {
    expect(corsAllowed("/feed/all.zip") && corsAllowed("/osv/PyPI/all.zip") && corsAllowed("/metrics.json")).toBe(true);
    expect(corsAllowed("/") || corsAllowed("/feed") || corsAllowed("/metrics.json.bak")).toBe(false);
    expect((await call("/feed/index.json")).headers.get("Access-Control-Allow-Origin")).toBe("*");
    expect((await call("/metrics.json")).headers.get("Access-Control-Allow-Origin")).toBe("*");
    expect((await call("/")).headers.get("Access-Control-Allow-Origin")).toBeNull();
  });

  it("sends X-Goog-Hash on the ecosystem zips, for OSV-Scanner's HEAD (F-073)", async () => {
    const res = await call("/osv/PyPI/all.zip", { method: "HEAD" });
    expect(res.status).toBe(200);
    expect(res.headers.get("X-Goog-Hash")).toBe("crc32c=XpwhcQ==");
    expect(res.headers.get("Content-Length")).toBe(String(ZIP.length));
    expect(res.headers.get("Content-Type")).toBe("application/zip");
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
    expect((await res.arrayBuffer()).byteLength).toBe(0);
    expect((await call("/osv/limbo-db.zip", { method: "HEAD" })).headers.get("X-Goog-Hash")).toBeNull();
    expect((await call("/feed/all.zip", { method: "HEAD" })).headers.get("X-Goog-Hash")).toBeNull();
  });

  it("reads the CRC map line by line and ignores anything else", () => {
    const m = parseCrcMap('"/osv/PyPI/all.zip" "crc32c=XpwhcQ==";\n# comment\n"/etc/passwd" "crc32c=x";\n"/osv/x" "md5=abc";\n');
    expect([...m]).toEqual([["/osv/PyPI/all.zip", "crc32c=XpwhcQ=="]]);
  });

  it("has no X-Goog-Hash when the map is missing", async () => {
    await env.SITE.delete("osv/crc32c.map");
    expect((await call("/osv/PyPI/all.zip", { method: "HEAD" })).headers.get("X-Goog-Hash")).toBeNull();
  });
});

describe("downloads, as watchers make them", () => {
  it("serves the feed zip whole, with an ETag and Last-Modified", async () => {
    const res = await call("/feed/all.zip");
    expect(res.status).toBe(200);
    expect(new Uint8Array(await res.arrayBuffer())).toEqual(ZIP);
    expect(res.headers.get("ETag")).toMatch(/^"[0-9a-f]+"$/);
    expect(res.headers.get("Last-Modified")).toMatch(/GMT$/);
    expect(res.headers.get("Accept-Ranges")).toBe("bytes");
  });

  it("answers If-None-Match with 304, and a changed file with 200", async () => {
    const etag = (await call("/feed/all.zip")).headers.get("ETag");
    const res = await call("/feed/all.zip", { headers: { "If-None-Match": etag } });
    expect(res.status).toBe(304);
    expect(res.headers.get("ETag")).toBe(etag);
    expectSecurityHeaders(res);
    await env.SITE.put("feed/all.zip", "new");
    const again = await call("/feed/all.zip", { headers: { "If-None-Match": etag } });
    expect(again.status).toBe(200);
    expect(new TextDecoder().decode(await again.arrayBuffer())).toBe("new");
  });

  it("answers a failed If-Match with 412", async () => {
    const res = await call("/feed/all.zip", { headers: { "If-Match": '"nope"' } });
    expect(res.status).toBe(412);
  });

  it("parses one byte range as nginx does", () => {
    expect(parseRange("bytes=0-99", 1000)).toEqual({ offset: 0, length: 100 });
    expect(parseRange("bytes=990-", 1000)).toEqual({ offset: 990, length: 10 });
    expect(parseRange("bytes=990-5000", 1000)).toEqual({ offset: 990, length: 10 });
    expect(parseRange("bytes=-10", 1000)).toEqual({ offset: 990, length: 10 });
    expect(parseRange("bytes=-5000", 1000)).toEqual({ offset: 0, length: 1000 });
    expect(parseRange("bytes=1000-", 1000)).toBe(UNSATISFIABLE);
    expect(parseRange("bytes=-0", 1000)).toBe(UNSATISFIABLE);
    for (const bad of [null, "", "bytes=abc", "bytes=-", "bytes=5-1", "bytes=0-1,5-6", "items=0-1"]) {
      expect(parseRange(bad, 1000), String(bad)).toBeNull();
    }
  });

  it("serves byte ranges, suffix ranges, and 416 past the end", async () => {
    let res = await call("/feed/all.zip", { headers: { Range: "bytes=0-99" } });
    expect(res.status).toBe(206);
    expect(res.headers.get("Content-Range")).toBe(`bytes 0-99/${ZIP.length}`);
    expect(new Uint8Array(await res.arrayBuffer())).toEqual(ZIP.slice(0, 100));
    res = await call("/feed/all.zip", { headers: { Range: "bytes=-10" } });
    expect(res.status).toBe(206);
    expect(res.headers.get("Content-Range")).toBe(`bytes ${ZIP.length - 10}-${ZIP.length - 1}/${ZIP.length}`);
    expect(new Uint8Array(await res.arrayBuffer())).toEqual(ZIP.slice(-10));
    res = await call("/feed/all.zip", { headers: { Range: "bytes=5000-6000" } });
    expect(res.status).toBe(416);
    expect(res.headers.get("Content-Range")).toBe(`bytes */${ZIP.length}`);
    expectSecurityHeaders(res);
    res = await call("/feed/all.zip", { headers: { Range: "bytes=abc" } });
    expect(res.status).toBe(200);
    expect(new Uint8Array(await res.arrayBuffer())).toEqual(ZIP);
    res = await call("/nope.zip", { headers: { Range: "bytes=0-1" } });
    expect(res.status).toBe(404);
  });

  it("answers a range request whose If-None-Match matches with 304", async () => {
    const etag = (await call("/feed/all.zip")).headers.get("ETag");
    const res = await call("/feed/all.zip", { headers: { Range: "bytes=0-9", "If-None-Match": etag } });
    expect(res.status).toBe(304);
  });
});
