// limbo.watch: serves the static output of `limbowatch publish` from the R2 bucket bound as SITE, doing what
// deploy/site/nginx.conf does (docs/HOSTING_PLAN.md). Only the default export may live here: the runtime treats every
// named export of this module as an entry point.
import { MAX_AGE, UNSATISFIABLE, baseHeaders, contentType, corsAllowed, gooHash, keyFor, notFound, parseRange, redirect } from "./serve.js";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.hostname.startsWith("www.")) {
      return redirect(`https://${url.hostname.slice(4)}${url.pathname}${url.search}`);
    }
    const head = request.method === "HEAD";
    if (request.method !== "GET" && !head) {
      const h = baseHeaders();
      h.set("Allow", "GET, HEAD");
      return new Response(null, { status: 405, headers: h });
    }

    const key = keyFor(url.pathname);
    if (key === null) return notFound(head);

    // Range is parsed here rather than by R2, so that, as in nginx, a range past the end is a 416 and a malformed one
    // is ignored. Conditional headers (If-None-Match, If-Modified-Since, ...) are answered by R2.
    let range = null;
    if (!head && request.headers.has("Range")) {
      const meta = await env.SITE.head(key);
      if (meta !== null) {
        range = parseRange(request.headers.get("Range"), meta.size);
        if (range === UNSATISFIABLE) {
          const h = baseHeaders();
          h.set("Content-Range", `bytes */${meta.size}`);
          return new Response(null, { status: 416, headers: h });
        }
      }
    }
    const obj = head
      ? await env.SITE.head(key)
      : await env.SITE.get(key, range ? { onlyIf: request.headers, range } : { onlyIf: request.headers });

    if (obj === null) {
      // nginx's try_files $uri $uri/: a directory without its slash gets a redirect to it
      if (!key.endsWith("index.html") && (await env.SITE.head(`${key}/index.html`)) !== null) {
        return redirect(`${url.pathname}/${url.search}`);
      }
      return notFound(head);
    }

    const h = baseHeaders();
    h.set("Content-Type", contentType(key));
    h.set("Cache-Control", `max-age=${MAX_AGE}`);
    h.set("ETag", obj.httpEtag);
    h.set("Last-Modified", obj.uploaded.toUTCString());
    h.set("Accept-Ranges", "bytes");
    if (corsAllowed(url.pathname)) h.set("Access-Control-Allow-Origin", "*");
    const goog = await gooHash(env, url.pathname, Date.now());
    if (goog) h.set("X-Goog-Hash", goog);

    if (head) {
      h.set("Content-Length", String(obj.size));
      return new Response(null, { status: 200, headers: h });
    }
    // R2 returns the object without a body when a precondition fails: 412 for If-Match and If-Unmodified-Since,
    // otherwise If-None-Match or If-Modified-Since said the client's copy is current, so 304
    if (!("body" in obj)) {
      const failed = request.headers.has("If-Match") || request.headers.has("If-Unmodified-Since");
      return new Response(null, { status: failed ? 412 : 304, headers: h });
    }
    if (range) {
      h.set("Content-Range", `bytes ${range.offset}-${range.offset + range.length - 1}/${obj.size}`);
      h.set("Content-Length", String(range.length));
      return new Response(obj.body, { status: 206, headers: h });
    }
    h.set("Content-Length", String(obj.size));
    return new Response(obj.body, { status: 200, headers: h });
  },
};
