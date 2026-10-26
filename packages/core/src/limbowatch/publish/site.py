"""Static site for limbo.watch: one page, data embedded, no external scripts.

Charts follow the dataviz method: single-series bars in the "in limbo" amber (validated per
mode: #B87400 on light, #C98500 on dark), direct value labels, hover tooltips, and a table
view for everything.
"""

from __future__ import annotations

import html
import json
from typing import Any

from limbowatch.models import Status
from limbowatch.publish import ATTRIBUTION, Item, days_since

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Limbo Tracker · limbo.watch</title>
<meta name="description" content="Live count of published security advisories that scanners can't see yet.">
<link rel="icon" href="favicon.svg" type="image/svg+xml">
<style>
:root{color-scheme:light;--bg:#F7F6F2;--surface:#FCFCFB;--ink:#0F1218;--ink2:#52514E;--muted:#7C818C;
--grid:#E1E0D9;--line:rgba(11,11,11,.10);--mark:#B87400;--accent:#B87400}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;--bg:#0F1218;--surface:#161A22;
--ink:#F3F1EA;--ink2:#C3C2B7;--muted:#898781;--grid:#2A303B;--line:rgba(255,255,255,.10);--mark:#C98500;--accent:#F4A62A}}
:root[data-theme="dark"]{color-scheme:dark;--bg:#0F1218;--surface:#161A22;--ink:#F3F1EA;--ink2:#C3C2B7;--muted:#898781;
--grid:#2A303B;--line:rgba(255,255,255,.10);--mark:#C98500;--accent:#F4A62A}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1040px;margin:0 auto;padding:32px 16px 64px}
header{display:flex;align-items:center;gap:14px;margin-bottom:28px}header img{width:44px;height:44px;border-radius:10px}
h1{font-size:22px;margin:0}h1 b{color:var(--accent)}h2{font-size:17px;margin:40px 0 4px}
.sub{color:var(--ink2);margin:0}.small{color:var(--muted);font-size:13px}
.hero{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:24px}
.hero .n{font-size:64px;font-weight:650;line-height:1;margin:6px 0}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-top:12px}
.tile{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.tile .v{font-size:26px;font-weight:600}.tile .l{color:var(--ink2);font-size:14px}
.chart{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:16px;margin-top:10px}
.row{display:grid;grid-template-columns:minmax(120px,240px) 1fr;align-items:center;gap:10px;height:30px}
.row .lab{color:var(--ink2);font-size:14px;text-align:right;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.track{position:relative;height:18px;border-left:1px solid var(--grid)}
.bar{height:18px;background:var(--mark);border-radius:0 4px 4px 0;min-width:2px}
.val{position:absolute;top:-1px;font-size:13px;color:var(--ink);padding-left:6px;font-variant-numeric:tabular-nums;white-space:nowrap;overflow-wrap:normal}
.row:hover .lab{color:var(--ink)}.tip{position:fixed;pointer-events:none;background:var(--ink);color:var(--surface);
font-size:13px;padding:6px 8px;border-radius:6px;display:none;z-index:9}
table{width:100%;border-collapse:collapse;font-size:14px;margin-top:10px;background:var(--surface);border:1px solid var(--line);border-radius:12px;overflow:hidden}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--grid);vertical-align:top}th{color:var(--muted);font-weight:500;font-size:13px;cursor:pointer;white-space:nowrap}
td.num{font-variant-numeric:tabular-nums;text-align:right}
table{table-layout:fixed}td{overflow-wrap:anywhere}th:nth-child(1){width:22%}th:nth-child(2){width:26%}th:nth-child(3){width:10%}th:nth-child(4){width:20%}th:nth-child(5){width:8%}th:nth-child(6){width:14%}
@media (max-width:640px){th:nth-child(6),td:nth-child(6),th:nth-child(3),td:nth-child(3){display:none}}a{color:inherit}
.wrap{overflow-x:auto}input[type=search]{width:100%;max-width:360px;padding:8px 10px;border-radius:8px;border:1px solid var(--grid);
background:var(--surface);color:var(--ink);font:inherit;margin-top:10px}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;border:1px solid var(--grid);font-size:12px;color:var(--ink2);white-space:nowrap}
footer{margin-top:48px;color:var(--muted);font-size:13px}code{font-size:13px}
body{overflow-wrap:anywhere}.hero,.chart,.tile{min-width:0}
@media (max-width:640px){main{padding:20px 16px 48px}.hero{padding:16px}.hero .n{font-size:48px}
.tiles{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.tile{padding:10px 12px}.tile .v{font-size:22px}
.row{grid-template-columns:minmax(0,38%) minmax(0,1fr);gap:8px}.row .lab{font-size:13px}.chart{padding:12px}
h1{font-size:18px}header img{width:36px;height:36px}.pill{white-space:normal}th:nth-child(5),td:nth-child(5){display:none}}
</style>
</head>
<body>
<main>
<header><img src="avatar-500.png" alt=""><div><h1>limbo<b>.</b>watch · Limbo Tracker</h1>
<p class="sub">Published security advisories that dependency scanners can't see yet.</p></div></header>
<section class="hero"><div class="small">In limbo right now, waiting for GitHub review</div><div class="n" id="hero"></div>
<p class="sub">Published by maintainers on GitHub, but not yet in GitHub's reviewed Advisory Database or OSV, so
Dependabot, npm audit, OSV-Scanner and most scanners stay silent. <span id="asof"></span></p>
<div class="tiles" id="tiles"></div></section>
<h2>How long they've waited</h2><p class="sub small">Days since the maintainer published the advisory.</p>
<div class="chart" id="ages"></div>
<h2>CVE status</h2><p class="sub small">No CVE anywhere: the advisory has no CVE ID and no CVE record mentions it. Reserved: the ID exists,
its record hasn't been published. Not cited: another CNA (usually VulnCheck) published a CVE the advisory doesn't mention.</p>
<div class="chart" id="cves"></div>
<h2>Severity</h2><div class="chart" id="sev"></div>
<h2>Ecosystem</h2><div class="chart" id="eco"></div>
<h2>All advisories in limbo</h2>
<input type="search" id="q" placeholder="Filter by package, repo, GHSA or CVE…" aria-label="Filter advisories">
<div class="wrap"><table><thead><tr><th data-k="ghsa">Advisory</th><th data-k="pkg">Package</th><th data-k="sev">Severity</th>
<th data-k="cve">CVE</th><th data-k="age" class="num">Days</th><th data-k="fix">Fixed in</th></tr></thead><tbody id="rows"></tbody></table></div>
<p class="small" id="count"></p>
<h2>Recently changed</h2><div class="wrap"><table><thead><tr><th>Advisory</th><th>When</th><th>What changed</th></tr></thead>
<tbody id="events"></tbody></table></div>
<h2>Data</h2>
<p class="sub">Machine-readable, CC BY 4.0: <a href="feed/all.zip">feed/all.zip</a> (OSV schema, one record per advisory in limbo,
same layout as OSV's bulk exports) · <a href="feed/index.json">feed/index.json</a> · <a href="metrics.json">metrics.json</a>.
Records keep their GHSA ID, so you can drop each one the moment OSV has it.</p>
<p class="sub small" id="coverage"></p>
<footer><p>Every number is a floor: the tracker sees only repositories on its watchlist (repos where reviewed advisories
originated, upstreams of popular projects, repos named in new GitHub-assigned CVEs). Version ranges are as entered by
maintainers and unreviewed. Only factual metadata is shown; read the advisory itself for details.</p>
<p>ATTRIBUTION</p><p><a href="https://github.com/limbowatch/limbowatch">Source and methods</a> · Apache-2.0 code ·
<a href="https://github.com/limbowatch/limbowatch/tree/main/research/2026-10-state-of-the-gap">State of the Gap report</a></p></footer>
</main>
<div class="tip" id="tip"></div>
<script id="data" type="application/json">DATA</script>
<script>
const D=JSON.parse(document.getElementById('data').textContent),M=D.metrics,fmt=n=>n==null?'–':n.toLocaleString('en');
const $=id=>document.getElementById(id),tip=$('tip');
$('hero').textContent=fmt(M.in_limbo.count);
$('asof').textContent='Updated '+M.generated_at.replace('T',' ').replace('Z',' UTC')+'.';
const tiles=[[M.in_limbo.by_cve['no CVE anywhere']||0,'with no CVE anywhere'],
 [M.likely_permanent.count,'more in ecosystems GitHub never reviews (likely permanent)'],
 [M.in_limbo.age_days_median,'median days waiting so far'],
 [M.in_limbo.rbp.count,'cite a CVE that is still only reserved'],
 [M.left_limbo.review_lag_days_median??'…', M.left_limbo.review_lag_days_median==null?'median days to review: measured as tracked advisories get reviewed':'median days to review, once reviewed']];
$('tiles').innerHTML=tiles.map(([v,l])=>`<div class="tile"><div class="v">${typeof v==='string'?v:fmt(v)}</div><div class="l">${l}</div></div>`).join('');
function bars(el,pairs,unit){const max=Math.max(1,...pairs.map(p=>p[1]));
 $(el).innerHTML=pairs.map(([k,v])=>`<div class="row" data-tip="${k}: ${fmt(v)} ${unit}"><div class="lab">${k}</div>
 <div class="track"><div class="bar" style="width:${v/max*76}%"></div><span class="val" style="left:${v/max*76}%">${fmt(v)}</span></div></div>`).join('');}
bars('ages',Object.entries(M.in_limbo.age_buckets),'advisories');
bars('cves',['no CVE anywhere','CVE reserved (RBP)','CVE published, cited','CVE published by another CNA, not cited']
 .map(k=>[k,M.in_limbo.by_cve[k]||0]),'advisories');
bars('sev',Object.entries(M.in_limbo.by_severity).filter(([k,v])=>v||k!=='unknown'),'advisories');
bars('eco',Object.entries(M.in_limbo.by_ecosystem).slice(0,10),'advisories');
document.addEventListener('mousemove',e=>{const r=e.target.closest('[data-tip]');if(!r){tip.style.display='none';return}
 tip.textContent=r.dataset.tip;tip.style.display='block';tip.style.left=(e.clientX+12)+'px';tip.style.top=(e.clientY+12)+'px'});
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
let rows=D.rows,sortK='age',dir=1;  // newest first
function render(){const q=$('q').value.trim().toLowerCase();
 const list=rows.filter(r=>!q||[r.ghsa,r.pkg,r.repo,r.cve].join(' ').toLowerCase().includes(q))
  .sort((a,b)=>((a[sortK]??-1)>(b[sortK]??-1)?1:-1)*dir);
 $('rows').innerHTML=list.slice(0,500).map(r=>`<tr><td><a href="${esc(r.url)}">${esc(r.ghsa)}</a><div class="small">${esc(r.repo)}</div></td>
  <td>${esc(r.pkg)}</td><td>${esc(r.sev)}</td><td><span class="pill">${esc(r.cvelabel)}</span><div class="small">${esc(r.cve)}</div></td>
  <td class="num">${r.age==null?'–':Math.floor(r.age)}</td><td class="small">${esc(r.fix)}</td></tr>`).join('');
 $('count').textContent=`Showing ${Math.min(500,list.length).toLocaleString('en')} of ${list.length.toLocaleString('en')}.`;}
$('q').addEventListener('input',render);
document.querySelectorAll('th[data-k]').forEach(th=>th.addEventListener('click',()=>{const k=th.dataset.k;dir=sortK===k?-dir:1;sortK=k;render()}));
render();
$('events').innerHTML=M.recent_events.slice(0,30).map(e=>`<tr><td>${esc(e.ghsa_id)}</td><td class="small">${esc(e.at.slice(0,10))}</td><td>${esc(e.event)}</td></tr>`).join('')||'<tr><td colspan="3" class="small">No changes recorded yet.</td></tr>';
const c=M.coverage;$('coverage').textContent=`Watchlist: ${fmt(c.watchlist_repos)} repositories, ${fmt(c.polled_last_24h)} polled in the last 24 hours; ${fmt(c.reviewed_advisories_known)} reviewed advisories known.`;
</script>
</body>
</html>
"""


def rows(items: list[Item], now: Any) -> list[dict[str, Any]]:
    out = []
    for i in items:
        if i.assessment.status is not Status.LIMBO or i.assessment.likely_permanent:
            continue
        a, f = i.adv, i.facts
        pkgs = sorted({f"{p.ecosystem}:{p.name}" for p in a.packages if p.name}) or [a.repo]
        fixes = sorted({p.patched_versions for p in a.packages if p.patched_versions})
        cves = [c for c in [f.cited_cve, *f.uncited_cves] if c]
        out.append(
            {
                "ghsa": a.ghsa_id,
                "repo": a.repo,
                "url": a.html_url,
                "pkg": ", ".join(pkgs)[:160],
                "sev": a.severity or "unknown",
                "cve": ", ".join(cves),
                "cvelabel": i.assessment.cve_label.value,
                "age": days_since(a.published_at, now),
                "fix": "; ".join(fixes)[:80],
            }
        )
    return out


def build(items: list[Item], metrics: dict[str, Any], now: Any) -> str:
    data = json.dumps({"metrics": metrics, "rows": rows(items, now)}, separators=(",", ":"))
    data = data.replace("</", "<\\/")  # keep the JSON from closing the <script> element
    return PAGE.replace("ATTRIBUTION", html.escape(ATTRIBUTION)).replace("DATA", data)
