// Helpers for src/index.js, which serves limbo.watch's /osv/* from R2 as the nginx setup did until 2026-11-14 (F-179).
// They live here because the Workers runtime treats every named export of the main module as an entry point and
// refuses anything else. Every response carries the security headers, including 404s and redirects.

const CSP =
  "default-src 'self'; script-src 'self' 'unsafe-inline' https://www.googletagmanager.com; " +
  "style-src 'self' 'unsafe-inline'; img-src 'self' data: https://www.googletagmanager.com " +
  "https://*.google-analytics.com; connect-src 'self' https://api.deps.dev https://www.googletagmanager.com " +
  "https://*.google-analytics.com https://*.google.com; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

export const SECURITY_HEADERS = {
  "Strict-Transport-Security": "max-age=31536000",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "Content-Security-Policy": CSP,
};

// The data changes once a day (nginx: `expires 5m`).
export const MAX_AGE = 300;

// The types nginx sends for the site's files; anything else is application/octet-stream, as in nginx.
const TYPES = {
  html: "text/html",
  css: "text/css",
  js: "application/javascript",
  json: "application/json",
  xml: "text/xml",
  atom: "application/atom+xml",
  txt: "text/plain",
  csv: "text/csv; charset=utf-8", // nginx's list has no CSV (press/limbo.csv)
  svg: "image/svg+xml",
  png: "image/png",
  jpg: "image/jpeg",
  webp: "image/webp",
  ico: "image/x-icon",
  zip: "application/zip",
};

export function contentType(key) {
  const dot = key.lastIndexOf(".");
  const ext = dot > key.lastIndexOf("/") ? key.slice(dot + 1).toLowerCase() : "";
  return TYPES[ext] ?? "application/octet-stream";
}

// The feed and metrics are meant for tools, so any origin may fetch them.
export function corsAllowed(path) {
  return path.startsWith("/feed/") || path.startsWith("/osv/") || path === "/metrics.json";
}

// OSV-Scanner reuses a cached /osv/<Ecosystem>/all.zip only if a HEAD request returns its CRC-32C as
// X-Goog-Hash, the way Google Cloud Storage sends it (FINDINGS F-073). `limbowatch publish` writes the values to
// osv/crc32c.map, one `"/osv/<Ecosystem>/all.zip" "crc32c=<base64>";` line per zip.
export function parseCrcMap(text) {
  const out = new Map();
  for (const line of text.split("\n")) {
    const m = /^"(\/osv\/[^"]+)"\s+"(crc32c=[A-Za-z0-9+/=]+)";$/.exec(line.trim());
    if (m) out.set(m[1], m[2]);
  }
  return out;
}

// The map is read once per isolate and again when it's older than the cache time, so a new deploy's values
// apply within minutes. A stale value only makes OSV-Scanner download the zip again.
let crc = { map: new Map(), at: 0 };

export function resetCrcCache() {
  crc = { map: new Map(), at: 0 };
}

export async function gooHash(env, path, now) {
  if (!path.startsWith("/osv/") || !path.endsWith("/all.zip")) return null;
  if (now - crc.at > MAX_AGE * 1000) {
    const obj = await env.SITE.get("osv/crc32c.map");
    crc = { map: obj ? parseCrcMap(await obj.text()) : new Map(), at: now };
  }
  return crc.map.get(path) ?? null;
}

export function baseHeaders() {
  return new Headers(SECURITY_HEADERS);
}

export function notFound(head) {
  const h = baseHeaders();
  h.set("Content-Type", "text/html");
  const body = "<html>\n<head><title>404 Not Found</title></head>\n<body>\n<center><h1>404 Not Found</h1></center>\n</body>\n</html>\n";
  return new Response(head ? null : body, { status: 404, headers: h });
}

export function redirect(location) {
  const h = baseHeaders();
  h.set("Location", location);
  h.set("Content-Type", "text/html");
  h.set("Cache-Control", `max-age=${MAX_AGE}`);
  return new Response(null, { status: 301, headers: h });
}

export const UNSATISFIABLE = "unsatisfiable";

// One byte range (`bytes=a-b`, `bytes=a-`, `bytes=-n`) as {offset, length}; UNSATISFIABLE when it starts past the
// end; null when there's no range to apply (absent, malformed or several ranges), so the whole file is sent.
export function parseRange(header, size) {
  const m = /^bytes=(\d*)-(\d*)$/.exec((header ?? "").trim());
  if (!m || (m[1] === "" && m[2] === "")) return null;
  if (m[1] === "") {
    const n = Math.min(Number(m[2]), size);
    return n === 0 ? UNSATISFIABLE : { offset: size - n, length: n };
  }
  const start = Number(m[1]);
  if (start >= size) return UNSATISFIABLE;
  const end = m[2] === "" ? size - 1 : Math.min(Number(m[2]), size - 1);
  return end < start ? null : { offset: start, length: end - start + 1 };
}

// The R2 key for a URL path: `/` → index.html, `/x/` → x/index.html. Null for paths no file can have.
export function keyFor(path) {
  let p;
  try {
    p = decodeURIComponent(path);
  } catch {
    return null;
  }
  // `//host` would make the directory redirect a protocol-relative URL to another site
  if (!p.startsWith("/") || p.startsWith("//") || p.includes("\0")) return null;
  if (p.split("/").some((s) => s === "." || s === "..")) return null;
  const key = p.slice(1);
  return key === "" || key.endsWith("/") ? `${key}index.html` : key;
}
