/* limbo.watch package checker (https://limbo.watch/check/).
 *
 * Runs in the visitor's browser. The dependency tree comes from deps.dev; the advisories come from /check/index.json,
 * which limbowatch.publish.check builds with the same range parser `limbowatch scan` uses. This script only compares
 * versions, with ports of the orderings the CLI uses through univers: semantic_version (npm, crates.io), packaging
 * (PyPI) and Maven's ComparableVersion. tests/test_check.py runs it under Node against the Python code, so a verdict
 * here is the CLI's verdict. Never compares versions as strings.
 */
(function () {
  'use strict';

  class Invalid extends Error {}
  const strip = s => String(s).split(/\s+/).join('').replace(/^[vV]+/, ''); // univers Version.normalize
  const isDigits = s => /^[0-9]+$/.test(s);
  const sign = x => (x > 0n ? 1 : x < 0n ? -1 : 0);
  const big = s => BigInt(s);
  function tupleCmp(a, b, cmp) { // Python tuple ordering: element by element, then the shorter first
    for (let i = 0; i < Math.min(a.length, b.length); i++) {
      const c = cmp(a[i], b[i]);
      if (c) return c;
    }
    return a.length - b.length ? (a.length < b.length ? -1 : 1) : 0;
  }

  // --- semver: univers SemverVersion = semantic_version.Version.coerce(), compared without build metadata,
  // equal only when the build metadata is equal too -------------------------------------------------------
  const SV_STRICT = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9a-zA-Z.-]+))?(?:\+([0-9a-zA-Z.-]+))?$/;
  function semver(raw) {
    const s = strip(raw);
    const m = /^\d+(?:\.\d+(?:\.\d+)?)?/.exec(s);
    if (!s || !m) throw new Invalid(raw);
    let v = m[0];
    while ((v.match(/\./g) || []).length < 2) v += '.0';
    v = v.split('.').map(p => p.replace(/^0+/, '') || '0').join('.');
    if (m[0].length < s.length) {
      let rest = s.slice(m[0].length).replace(/[^a-zA-Z0-9+.-]/g, '-');
      let pre, build;
      const split = r => { const i = r.indexOf('+'); return i >= 0 ? [r.slice(0, i), r.slice(i + 1)] : [r, '']; };
      if (rest[0] === '+' || rest[0] === '.') [pre, build] = ['', rest.slice(1)];
      else if (rest[0] === '-') [pre, build] = split(rest.slice(1));
      else [pre, build] = split(rest);
      build = build.split('+').join('.');
      if (pre) v += '-' + pre;
      if (build) v += '+' + build;
    }
    const p = SV_STRICT.exec(v);
    if (!p) throw new Invalid(raw);
    const ids = (x, leadingZeros) => {
      if (x === undefined || x === '') return [];
      const parts = x.split('.');
      for (const it of parts) {
        if (!it || (!leadingZeros && it[0] === '0' && isDigits(it) && it !== '0')) throw new Invalid(raw);
      }
      return parts;
    };
    return { k: [big(p[1]), big(p[2]), big(p[3])], pre: ids(p[4], false), build: ids(p[5], true) };
  }
  function idCmp(a, b) { // NumericIdentifier < AlphaIdentifier; alpha compares as ASCII bytes
    const na = isDigits(a), nb = isDigits(b);
    if (na && nb) return sign(big(a) - big(b));
    if (na !== nb) return na ? -1 : 1;
    return a < b ? -1 : a > b ? 1 : 0;
  }
  function semverCmp(a, b) {
    for (let i = 0; i < 3; i++) if (a.k[i] !== b.k[i]) return a.k[i] < b.k[i] ? -1 : 1;
    if (!a.pre.length || !b.pre.length) return a.pre.length === b.pre.length ? 0 : a.pre.length ? -1 : 1; // no prerelease: MaxIdentifier
    return tupleCmp(a.pre, b.pre, idCmp);
  }
  const sameList = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
  const semverEq = (a, b) => semverCmp(a, b) === 0 && sameList(a.pre, b.pre) && sameList(a.build, b.build);

  // --- PEP 440: packaging.version.Version --------------------------------------------------------------
  const PEP440 = new RegExp('^\\s*v?(?:(?:([0-9]+)!)?([0-9]+(?:\\.[0-9]+)*)' +
    '([-_.]?(alpha|a|beta|b|preview|pre|c|rc)[-_.]?([0-9]+)?)?' +
    '((?:-([0-9]+))|(?:[-_.]?(post|rev|r)[-_.]?([0-9]+)?))?' +
    '([-_.]?(dev)[-_.]?([0-9]+)?)?)(?:\\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?\\s*$', 'i');
  const LETTERS = { alpha: 'a', beta: 'b', c: 'rc', pre: 'rc', preview: 'rc', rev: 'post', r: 'post' };
  const PRE_RANK = { a: 0n, b: 1n, rc: 2n };
  function letter(l, n) {
    if (l) { l = l.toLowerCase(); return [LETTERS[l] || l, big(n || '0')]; }
    return n ? ['post', big(n)] : null;
  }
  function pep440(raw) {
    const s = strip(raw);
    let epoch = 0n, release, pre = null, post = null, dev = null, local = null;
    if ([...s].every(c => '.0123456789'.includes(c))) {
      const parts = s.split('.');
      if (parts.includes('')) throw new Invalid(raw);
      release = parts.map(big);
    } else {
      const m = PEP440.exec(s);
      if (!m) throw new Invalid(raw);
      epoch = m[1] ? big(m[1]) : 0n;
      release = m[2].split('.').map(big);
      pre = letter(m[4], m[5]);
      post = letter(m[8], m[7] || m[9]);
      dev = letter(m[11], m[12]);
      local = m[13] === undefined ? null : m[13].split(/[._-]/).map(p => (isDigits(p) ? big(p) : p.toLowerCase()));
    }
    let i = release.length;
    while (i && release[i - 1] === 0n) i--;
    const trimmed = release.slice(0, i);
    let preRank, preN;
    if (pre === null && post === null && dev !== null) [preRank, preN] = [-1n, 0n];
    else if (pre === null) [preRank, preN] = [3n, 0n];
    else [preRank, preN] = [PRE_RANK[pre[0]], pre[1]];
    const suffix = [preRank, preN, post === null ? 0n : 1n, post === null ? 0n : post[1], dev === null ? 1n : 0n,
      dev === null ? 0n : dev[1]];
    return { epoch, trimmed, suffix, local, pre, dev };
  }
  const bigCmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
  function localCmp(a, b) { // ints → (n, ""), strings → (-1, s): strings sort before ints
    const sa = typeof a === 'string', sb = typeof b === 'string';
    if (sa && sb) return a < b ? -1 : a > b ? 1 : 0;
    if (sa !== sb) return sa ? -1 : 1;
    return bigCmp(a, b);
  }
  function pep440Cmp(a, b) {
    return bigCmp(a.epoch, b.epoch) || tupleCmp(a.trimmed, b.trimmed, bigCmp) || tupleCmp(a.suffix, b.suffix, bigCmp) ||
      (a.local === null && b.local === null ? 0 : a.local === null ? -1 : b.local === null ? 1 :
        tupleCmp(a.local, b.local, localCmp));
  }

  // --- Maven: univers.maven.Version (a port of Maven's ComparableVersion) -------------------------------
  const QUALIFIERS = ['alpha', 'beta', 'milestone', 'rc', 'snapshot', '', 'sp'];
  const ALIASES = { ga: '', final: '', cr: 'rc' };
  const falsy = x => x === 0n || x === '' || (Array.isArray(x) && x.length === 0);
  function mvNormalize(l) { // pops from the end while it walks a reversed copy, exactly as univers does
    for (const item of [...l].reverse()) {
      if (falsy(item)) l.pop();
      else if (!Array.isArray(item)) break;
    }
    return l;
  }
  function mvBuffer(buf, followedByDigit) {
    let v = buf;
    if (isDigits(buf)) v = big(buf);
    else if (followedByDigit && buf.length === 1) v = { a: 'alpha', b: 'beta', m: 'milestone' }[buf] || buf;
    return typeof v === 'string' && v in ALIASES ? ALIASES[v] : v;
  }
  function mvNewList(l) { l = mvNormalize(l); const sub = []; l.push(sub); return sub; }
  function maven(raw) {
    const buf = strip(raw).trim().toLowerCase();
    const parsed = [];
    let cur = parsed, start = 0, digit = false;
    for (let idx = 0; idx < buf.length; idx++) {
      const ch = buf[idx];
      if (ch === '.' || ch === '-') {
        cur.push(idx === start ? 0n : mvBuffer(buf.slice(start, idx)));
        start = idx + 1;
        if (ch === '-') cur = mvNewList(cur);
      } else if (isDigits(ch)) {
        if (!digit && idx > start) { cur.push(mvBuffer(buf.slice(start, idx), true)); cur = mvNewList(cur); start = idx; }
        digit = true;
      } else {
        if (digit && idx > start) { cur.push(mvBuffer(buf.slice(start, idx))); cur = mvNewList(cur); start = idx; }
        digit = false;
      }
    }
    if (buf.length > start) cur.push(mvBuffer(buf.slice(start)));
    mvNormalize(cur);
    return mvNormalize(parsed);
  }
  const mvStringValue = s => (QUALIFIERS.includes(s) ? String(QUALIFIERS.indexOf(s) + 1) : `${QUALIFIERS.length}-${s}`);
  function mvCmp(a, b) {
    if (typeof a === 'bigint') {
      if (typeof b === 'bigint') return sign(a - b);
      if (b === null) return sign(a);
      return 1;
    }
    if (typeof a === 'string') {
      if (b === null) return mvCmp(a, '');
      if (typeof b !== 'string') return -1;
      const x = mvStringValue(a), y = mvStringValue(b);
      return x < y ? -1 : x === y ? 0 : 1;
    }
    if (b === null) return a.length === 0 ? 0 : mvCmp(a[0], null);
    if (typeof b === 'bigint') return -1;
    if (typeof b === 'string') return 1;
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
      const l = i < a.length ? a[i] : null, r = i < b.length ? b[i] : null;
      const c = l === null ? (r === null ? 0 : -mvCmp(r, null)) : mvCmp(l, r);
      if (c) return c;
    }
    return 0;
  }

  // --- one interface per ecosystem key (GHSA's: npm, pip, rust, maven) ---------------------------------
  const ORDER = {
    npm: { parse: semver, cmp: semverCmp, eq: semverEq },
    rust: { parse: semver, cmp: semverCmp, eq: semverEq },
    pip: { parse: pep440, cmp: pep440Cmp, eq: (a, b) => pep440Cmp(a, b) === 0 },
    maven: { parse: maven, cmp: (a, b) => mvCmp(a, b), eq: (a, b) => mvCmp(a, b) === 0 },
  };
  function isPrerelease(eco, version) {
    try {
      const v = ORDER[eco].parse(version);
      if (eco === 'pip') return v.pre !== null || v.dev !== null;
      if (eco === 'maven') {
        const walk = l => l.some(x => (Array.isArray(x) ? walk(x) : typeof x === 'string' && QUALIFIERS.indexOf(x) > -1 && QUALIFIERS.indexOf(x) < 5));
        return walk(v);
      }
      return v.pre.length > 0;
    } catch (e) {
      return false;
    }
  }

  // --- matching: mirrors limbowatch.versions.affected / already_fixed and watch.match._version ----------
  function test(o, op, v, b) {
    if (op === '!=') return !o.eq(v, b);
    if (op === '=') return o.eq(v, b);
    const c = o.cmp(v, b);
    return { '<': c < 0, '<=': c <= 0, '>': c > 0, '>=': c >= 0 }[op];
  }
  function affected(eco, version, alts) {
    const o = ORDER[eco];
    if (!o || !alts || !version) return null;
    try {
      const v = o.parse(version);
      for (const cons of alts) {
        let ok = true;
        for (const [op, bound] of cons) {
          ok = test(o, op, v, o.parse(bound.replace(/^v+/, '')));
          if (!ok) break;
        }
        if (ok) return true;
      }
      return false;
    } catch (e) {
      return null;
    }
  }
  function alreadyFixed(eco, version, fixes) {
    const o = ORDER[eco];
    if (!o || !fixes || !fixes.length) return null;
    const line = s => s.replace(/^v+/, '').split('.').slice(0, 2).join('.');
    try {
      const v = o.parse(version);
      const same = fixes.filter(f => line(f) === line(version));
      if (same.length) return o.cmp(v, o.parse(same[0].replace(/^v+/, ''))) >= 0;
      if (fixes.length === 1) return o.cmp(v, o.parse(fixes[0].replace(/^v+/, ''))) >= 0;
      return null;
    } catch (e) {
      return null;
    }
  }
  function verdict(eco, version, e) { // [true | false | null (possibly), evidence]
    let hit = affected(eco, version, e.a);
    if (hit === null && e.r && e.d) {
      const vs = e.d.map(a => affected(eco, version, a));
      if (vs.every(x => x !== null && x === vs[0])) hit = vs[0];
    }
    if (hit === false) return [false, ''];
    if (hit === null) return [null, `the advisory’s range “${e.r || ''}” can’t be evaluated exactly`];
    if (alreadyFixed(eco, version, e.x)) {
      return [null, `${version} is in the range “${e.r}”, but at or after the fixed version “${e.f}”`];
    }
    return [true, `${version} is in the range “${e.r}”`];
  }
  function normName(eco, name) { // limbowatch.versions.norm_name
    if (eco === 'pip') return name.replace(/[-_.]+/g, '-').toLowerCase();
    if (eco === 'npm' || eco === 'rust') return name.toLowerCase();
    return name;
  }
  function findings(index, eco, name, version) { // watch.match.match, by package name
    const out = new Map();
    for (const e of (index.ecosystems[eco] || {})[normName(eco, name)] || []) {
      const [hit, why] = verdict(eco, version, e);
      if (hit === false) continue;
      if (!out.has(e.g) || out.get(e.g).hit !== true) out.set(e.g, { hit, why, e });
    }
    return [...out.values()].sort((a, b) => (a.e.g < b.e.g ? -1 : 1));
  }

  const api = { semver, semverCmp, semverEq, pep440, pep440Cmp, maven, mvCmp, ORDER, affected, alreadyFixed, verdict,
    normName, findings, isPrerelease, Invalid };
  if (typeof module === 'object' && module.exports) { module.exports = api; return; }

  // --- the page --------------------------------------------------------------------------------------
  const SYSTEMS = { npm: 'npm', pip: 'pypi', rust: 'cargo', maven: 'maven' };
  const FROM_SYSTEM = { NPM: 'npm', PYPI: 'pip', CARGO: 'rust', MAVEN: 'maven' };
  const LABEL = { npm: 'npm', pip: 'PyPI', rust: 'crates.io', maven: 'Maven' };
  const SEV = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
  const DEPS = 'https://api.deps.dev/v3/systems/';
  const $ = s => document.querySelector(s);
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const enc = encodeURIComponent;
  const out = $('#check-out');
  if (!out) return;
  let indexPromise = null;
  const loadIndex = () => (indexPromise ||= fetch('/check/index.json').then(r => {
    if (!r.ok) throw new Error('the advisory index didn’t load');
    return r.json();
  }));
  async function getJSON(url) {
    const r = await fetch(url);
    if (r.status === 404) return null;
    if (!r.ok) throw new Error(`deps.dev answered ${r.status}`);
    return r.json();
  }
  function names(eco, raw) { // spellings worth asking deps.dev for
    const n = raw.trim();
    const alts = eco === 'pip' ? [n, n.replace(/[-_.]+/g, '-').toLowerCase()] : eco === 'maven' ? [n] : [n, n.toLowerCase()];
    return [...new Set(alts)];
  }
  async function findPackage(eco, raw) {
    if (eco === 'maven' && !raw.includes(':')) return null;
    for (const n of names(eco, raw)) {
      const p = await getJSON(`${DEPS}${SYSTEMS[eco]}/packages/${enc(n)}`);
      if (p && p.versions && p.versions.length) return { eco, name: p.packageKey?.name || n, versions: p.versions };
    }
    return null;
  }
  function pickVersion(pkg, wanted) {
    const vs = pkg.versions.map(v => v.versionKey.version);
    if (wanted) return vs.includes(wanted) ? { version: wanted, why: 'the version you asked for' } : null;
    const o = ORDER[pkg.eco];
    const dflt = pkg.versions.find(v => v.isDefault)?.versionKey.version;
    if (dflt && !isPrerelease(pkg.eco, dflt)) return { version: dflt, why: 'its current version on deps.dev' };
    let best = null;
    for (const v of vs) {
      if (isPrerelease(pkg.eco, v)) continue;
      try { if (best === null || o.cmp(o.parse(v), o.parse(best)) > 0) best = v; } catch (e) { /* unparseable: skip */ }
    }
    if (best) return { version: best, why: dflt ? `its newest release; deps.dev’s default, ${dflt}, is a pre-release` : 'its newest release' };
    return dflt ? { version: dflt, why: 'its current version on deps.dev, a pre-release' } : null;
  }
  function via(graph, i) { // the shortest path from the package checked to node i
    const parent = new Map([[0, null]]), q = [0];
    while (q.length) {
      const n = q.shift();
      for (const e of graph.edges || []) {
        if (e.fromNode === n && !parent.has(e.toNode)) { parent.set(e.toNode, n); q.push(e.toNode); }
      }
    }
    const path = [];
    for (let n = parent.get(i); n !== null && n !== undefined && n !== 0; n = parent.get(n)) path.unshift(graph.nodes[n].versionKey.name);
    return path;
  }
  const days = iso => (iso ? Math.max(0, (Date.now() - Date.parse(iso)) / 864e5) : null);
  const fmtDays = d => (d === null ? '–' : d < 1 ? 'under a day' : `${Math.round(d)} day${Math.round(d) === 1 ? '' : 's'}`);
  function busy(text) { out.innerHTML = `<p class="muted" role="status">${esc(text)}</p>`; }
  function fail(text) { out.innerHTML = `<div class="note"><h3>Couldn’t check it</h3><p class="small ink2">${text}</p></div>`; }

  async function run(eco, raw, wanted) {
    raw = raw.trim();
    if (!raw) return;
    const url = new URL(location.href);
    url.search = new URLSearchParams({ eco, name: raw, ...(wanted ? { version: wanted } : {}) }).toString();
    history.replaceState(null, '', url);
    busy('Looking it up on deps.dev…');
    try {
      const ecos = eco === 'any' ? Object.keys(SYSTEMS) : [eco];
      const found = (await Promise.all(ecos.map(e => findPackage(e, raw)))).filter(Boolean);
      if (!found.length) {
        const where = ecos.map(e => LABEL[e]).join(', ').replace(/, ([^,]*)$/, ' or $1');
        const hint = ecos.includes('maven') && !raw.includes(':') ? ' Maven packages are named <span class="mono">group:artifact</span>.' : '';
        return fail(`deps.dev knows no package named <strong>${esc(raw)}</strong> on ${esc(where)}.${hint}`);
      }
      if (found.length > 1) {
        out.innerHTML = `<div class="card chk-pick"><p><strong>${esc(raw)}</strong> exists in ${found.length} ecosystems. Which one?</p>
<div>${found.map(f => `<button type="button" class="btn line" data-eco="${f.eco}">${esc(LABEL[f.eco])}: ${esc(f.name)}</button>`).join('')}</div></div>`;
        out.querySelectorAll('button[data-eco]').forEach(b => b.addEventListener('click', () => {
          $('#chk-eco').value = b.dataset.eco;
          run(b.dataset.eco, raw, wanted);
        }));
        return;
      }
      const pkg = found[0];
      const pick = pickVersion(pkg, wanted);
      if (!pick) return fail(`deps.dev lists no version <strong>${esc(wanted || '')}</strong> of ${esc(pkg.name)}.`);
      busy(`Resolving the dependency tree of ${pkg.name} ${pick.version}…`);
      const [index, graph] = await Promise.all([
        loadIndex(),
        getJSON(`${DEPS}${SYSTEMS[pkg.eco]}/packages/${enc(pkg.name)}/versions/${enc(pick.version)}:dependencies`),
      ]);
      render(index, pkg, pick, graph);
    } catch (e) {
      fail(`${esc(e.message || e)}. deps.dev or limbo.watch may be unreachable; try again in a minute.`);
    }
  }

  function render(index, pkg, pick, graph) {
    const self = { versionKey: { system: SYSTEMS[pkg.eco].toUpperCase(), name: pkg.name, version: pick.version } };
    const nodes = graph && graph.nodes && graph.nodes.length ? graph.nodes : [self];
    const rows = [], unresolved = [];
    nodes.forEach((n, i) => {
      const eco = FROM_SYSTEM[n.versionKey.system];
      if (!eco || !n.versionKey.version) {
        unresolved.push(`${n.versionKey.name}: ${!eco ? 'not an ecosystem the checker reads' : 'no resolved version'}`);
        return;
      }
      for (const err of n.errors || []) unresolved.push(`${n.versionKey.name} ${n.versionKey.version}: ${err.message || err}`);
      for (const f of findings(index, eco, n.versionKey.name, n.versionKey.version)) {
        rows.push({ ...f, name: n.versionKey.name, version: n.versionKey.version, path: i ? via(graph, i) : [] });
      }
    });
    rows.sort((a, b) => (a.hit === b.hit ? 0 : a.hit ? -1 : 1) || (SEV[a.e.s] ?? 4) - (SEV[b.e.s] ?? 4) || (a.name < b.name ? -1 : 1));
    const sure = rows.filter(r => r.hit), maybe = rows.filter(r => !r.hit);
    const pkgsHit = new Set(sure.map(r => r.name)).size;
    const deps = nodes.length - 1;
    const resolved = !!(graph && graph.nodes && graph.nodes.length);
    const tree = graph && !resolved ? `deps.dev couldn’t resolve the dependency tree of ${esc(pkg.name)} ${esc(pick.version)}, so only the package itself was checked.`
      : !graph ? `deps.dev hasn’t resolved the dependency tree of ${esc(pkg.name)} ${esc(pick.version)} yet (new versions take a while), so only the package itself was checked.`
      : deps === 0 ? `${esc(pkg.name)} ${esc(pick.version)} has no dependencies, so the package itself is all there is to check.`
      : `${deps.toLocaleString()} package${deps === 1 ? '' : 's'} in its dependency tree (${nodes.filter(n => n.relation === 'DIRECT').length} direct), plus ${esc(pkg.name)} itself.`;
    const what = resolved ? 'this tree' : `${esc(pkg.name)} ${esc(pick.version)} itself`;
    const head = sure.length
      ? `<strong>${sure.length} advisor${sure.length === 1 ? 'y' : 'ies'} in limbo affect${sure.length === 1 ? 's' : ''} ${resolved ? `${pkgsHit} package${pkgsHit === 1 ? '' : 's'} in this tree` : what}.</strong>`
      : maybe.length ? `<strong>No advisory in limbo certainly affects ${what}</strong>, but ${maybe.length} may.`
      : `<strong>No advisory in limbo affects ${what}.</strong>`;
    const prev = resolved ? null : previousRelease(pkg, pick.version);
    const retry = prev ? `<p class="small"><button type="button" class="btn line" id="chk-prev">Check the tree of ${esc(prev)}, the release before</button></p>` : '';
    const tableRows = rows.map(r => {
      const sev = r.e.s || 'unknown';
      const pathText = r.path.length ? `via ${r.path.slice(-3).join(' › ')}${r.path.length > 3 ? ' …' : ''}` : r.name === pkg.name ? 'the package itself' : 'direct dependency';
      return `<tr><td class="c-p"><strong>${esc(r.name)}</strong> <span class="mono">${esc(r.version)}</span><small>${esc(pathText)}</small></td>
<td class="c-id mono"><a href="/advisory/${esc(r.e.g)}/">${esc(r.e.g)}</a>${r.hit ? '' : '<small>possibly affected</small>'}</td>
<td class="c-sev sev-${esc(sev)}">${esc(sev[0].toUpperCase() + sev.slice(1))}</td>
<td class="c-cve"><small>${esc(r.why)}</small></td>
<td class="c-wait n" data-l="Waiting">${esc(fmtDays(days(r.e.p)))}</td>
<td class="c-fix mono${r.e.f ? '' : ' none'}"><span>${esc((r.e.f || '').slice(0, 40))}</span></td></tr>`;
    }).join('');
    const asOf = new Date(index.generated_at).toUTCString().replace(/:\d\d GMT$/, ' UTC');
    out.innerHTML = `<div class="card chk-res ${sure.length ? 'hit' : 'clear'}">
<p class="eyebrow">${esc(LABEL[pkg.eco])} · ${esc(pkg.name)} ${esc(pick.version)}, ${esc(pick.why)}</p>
<p class="chk-v">${head}</p><p class="small ink2">${tree} Checked against the ${index.advisories.toLocaleString()} advisories in limbo for npm, PyPI, crates.io and Maven, as of ${esc(asOf)}.</p>${retry}
${sure.length || maybe.length ? '' : '<p class="small ink2">Advisories GitHub has already reviewed aren’t checked here: your usual scanner reports those.</p>'}</div>
${rows.length ? `<div class="tbl"><table><thead><tr><th scope="col">Package</th><th scope="col">Advisory</th><th scope="col">Severity</th><th scope="col">Why</th>
<th scope="col" class="n">Waiting</th><th scope="col">Fixed in</th></tr></thead><tbody>${tableRows}</tbody></table></div>` : ''}
${unresolved.length ? `<div class="note"><h3>Not fully checked</h3><ul>${unresolved.slice(0, 20).map(u => `<li>${esc(u)}</li>`).join('')}${unresolved.length > 20 ? `<li>and ${unresolved.length - 20} more</li>` : ''}</ul></div>` : ''}
${graph && graph.error ? `<div class="note"><h3>deps.dev couldn’t resolve the whole tree</h3><p class="small ink2">${esc(graph.error)}.${resolved ? ' The packages it did resolve were checked.' : ''}</p></div>` : ''}`;
    const b = $('#chk-prev');
    if (b) b.addEventListener('click', () => { $('#chk-version').value = prev; run(pkg.eco, pkg.name, prev); });
  }

  function previousRelease(pkg, version) { // the newest release older than `version`
    const o = ORDER[pkg.eco];
    let cur, best = null;
    try { cur = o.parse(version); } catch (e) { return null; }
    for (const v of pkg.versions.map(x => x.versionKey.version)) {
      if (isPrerelease(pkg.eco, v)) continue;
      try {
        const pv = o.parse(v);
        if (o.cmp(pv, cur) < 0 && (best === null || o.cmp(pv, o.parse(best)) > 0)) best = v;
      } catch (e) { /* unparseable: skip */ }
    }
    return best;
  }

  const form = $('#check-form');
  form.addEventListener('submit', e => {
    e.preventDefault();
    run($('#chk-eco').value, $('#chk-name').value, $('#chk-version').value.trim());
  });
  const q = new URLSearchParams(location.search);
  if (q.get('name')) {
    $('#chk-name').value = q.get('name');
    if (q.get('eco') && (q.get('eco') in SYSTEMS || q.get('eco') === 'any')) $('#chk-eco').value = q.get('eco');
    $('#chk-version').value = q.get('version') || '';
    run($('#chk-eco').value, q.get('name'), $('#chk-version').value.trim());
  }
})();
