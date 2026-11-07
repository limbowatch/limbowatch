"""Static site for limbo.watch, built from tracker state.

Pages: `/` (live count, the queue chart and what limbo is), `/tracker/` (every advisory, filterable), one page
per advisory in limbo at `/advisory/<GHSA>/`, `/feed/` (how to use the OSV feed), `/scan/`, `/methodology/`,
`/press/` (citable numbers, the chart as SVG, every advisory as CSV, contact), `/why/` and `/quality/`. Plus Atom
feeds of new advisories, `sitemap.xml` and `robots.txt`. Self-contained:
no third-party scripts, fonts or images, so the CSP can stay at 'self'. Factual metadata only
(FINDINGS F-059): no advisory titles, descriptions or credits.

Amber marks "in limbo" and nothing else (brand/README.md).
"""

from __future__ import annotations

import csv
import html
import io
import json
import re
import statistics
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from limbowatch.ecosystems import PackageName, package_name, reviewable
from limbowatch.models import AdvisoryPackage, CveLabel, Status
from limbowatch.publish import ATTRIBUTION, Item, days_since, eco_label, fixes_text
from limbowatch.publish.quality import NAME, Problem, problems
from limbowatch.versions import fixed_versions, no_fix, osv_ranges

REPO_URL = "https://github.com/limbowatch/limbowatch"
REPORT_URL = f"{REPO_URL}/tree/main/research/2026-10-state-of-the-gap"
ISSUE_URL = f"{REPO_URL}/issues/1"
FINDINGS_URL = f"{REPO_URL}/blob/main/docs/FINDINGS.md"
SITE = "https://limbo.watch"
CONTACT = "blueandhack@gmail.com"
QUEUE_UNIT = 40  # advisories per square in the queue chart
QUEUE_WEEKS = 52  # weekly columns; the last one holds everything older
LEFT_WINDOW = timedelta(days=30)
LIST_ROWS = 5
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
CVE_KEY = {
    CveLabel.NONE: "none",
    CveLabel.RESERVED: "rbp",
    CveLabel.PUBLISHED_CITED: "pub",
    CveLabel.PUBLISHED_UNCITED: "cna",
    CveLabel.OTHER: "other",
}
CVE_TEXT = {
    "none": "No CVE anywhere",
    "rbp": "CVE reserved (RBP)",
    "pub": "CVE published, cited",
    "cna": "CVE from another CNA",
    "other": "CVE in another state",
}
LEFT_TEXT = {
    "reviewed": "Reviewed by GitHub",
    "duplicate of a reviewed advisory": "Duplicate of a reviewed advisory",
    "withdrawn": "Withdrawn",
    "no longer published": "No longer published",
}

E = html.escape

CSS = """:root{color-scheme:light;--bg:#F7F6F2;--surface:#FCFCFB;--sunk:#EFEDE6;--ink:#0F1218;--ink2:#4A4D55;--muted:#6B6F78;
--line:#E1E0D9;--line2:#ECEBE5;--border:#C9C7BD;--mark:#B87400;--amber-text:#8F5A00;--pill-bg:#F6E7C8;--pill-ink:#5E3B00;
--code-bg:#0F1218;--code-ink:#F3F1EA;--btn-bg:#0F1218;--btn-ink:#F7F6F2;
--sans:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
--mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;--bg:#0F1218;--surface:#161A22;
--sunk:#1B2029;--ink:#F3F1EA;--ink2:#C3C2B7;--muted:#9A998F;--line:#2A303B;--line2:#232833;--border:#3A404C;--mark:#F4A62A;
--amber-text:#F4A62A;--pill-bg:#3A2A0A;--pill-ink:#F7C66B;--code-bg:#0A0C10;--btn-bg:#F3F1EA;--btn-ink:#0F1218}}
:root[data-theme="dark"]{color-scheme:dark;--bg:#0F1218;--surface:#161A22;--sunk:#1B2029;--ink:#F3F1EA;--ink2:#C3C2B7;
--muted:#9A998F;--line:#2A303B;--line2:#232833;--border:#3A404C;--mark:#F4A62A;--amber-text:#F4A62A;--pill-bg:#3A2A0A;
--pill-ink:#F7C66B;--code-bg:#0A0C10;--btn-bg:#F3F1EA;--btn-ink:#0F1218}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 var(--sans);font-variant-numeric:tabular-nums}
a{color:inherit}a:hover{color:var(--amber-text)}
.wrap{max-width:1200px;margin:0 auto;padding:0 24px}
.mono{font-family:var(--mono)}.muted{color:var(--muted)}.ink2{color:var(--ink2)}
.eyebrow{margin:0;font-size:14px;color:var(--muted)}.small{font-size:14px}
.vh{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
:focus-visible{outline:2px solid var(--mark);outline-offset:2px}
/* header */
.top{border-bottom:1px solid var(--line)}
.bar{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:8px 16px;padding-top:14px;padding-bottom:14px}
.brand{display:flex;align-items:center;gap:10px;text-decoration:none;font-size:18px;font-weight:600;letter-spacing:-.01em}
.brand b{color:var(--mark);font-weight:600}.brand svg{flex:none}
nav.main{display:flex;flex-wrap:wrap;gap:0 24px;font-size:15px}
nav.main a{text-decoration:none;padding:10px 0;border-bottom:2px solid transparent}
nav.main a[aria-current]{font-weight:600;border-bottom-color:currentColor}
.menu,.tl-v,.ftoggle,.tabs .sm{display:none}
/* hero (always dark) */
.hero{background:#0F1218;color:#F3F1EA;border-bottom:1px solid #2A303B}
.hero a:hover{color:#F4A62A}.hero .brand b{color:#F4A62A}.hero .eyebrow{color:#A9A8A0}
.hero-body{padding-top:64px;padding-bottom:80px}
.hero h1{margin:0;max-width:900px;font-size:clamp(38px,6vw,76px);line-height:1.03;letter-spacing:-.035em;font-weight:650}
.lede{margin:24px 0 0;max-width:680px;font-size:19px;color:#A9A8A0}
.count-row{margin-top:56px;display:flex;flex-wrap:wrap;gap:40px 64px;align-items:flex-end}
.big{font-size:clamp(88px,13vw,168px);line-height:.85;font-weight:650;letter-spacing:-.05em;color:#F4A62A}
.big-label{margin-top:14px;font-size:18px;font-weight:500}
.stats{margin:0;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:20px 48px;flex:1 1 360px;max-width:520px}
.stats dt{font-size:14px;color:#A9A8A0}.stats dd{margin:4px 0 0;font-size:28px;font-weight:600}
.tl{margin:72px 0 0}.tl figcaption{font-size:14px;color:#A9A8A0;margin-bottom:18px}
.tl-row{display:flex;align-items:center}.tl-cols{display:flex}
.tl .f3{flex:3}.tl .f1{flex:1}.tl .pr{padding-right:16px}
.tl-tag{margin:0;font-size:15px;color:#F4A62A;font-weight:600}
.tl-note{margin:4px 0 12px;font-size:15px;color:#A9A8A0}
.dot{width:16px;height:16px;border-radius:50%;flex:none}.dot.amber{background:#F4A62A}
.dot.ring{border:3px solid #F3F1EA}.dot.fill{background:#F3F1EA}
.seg{height:6px;background:#F4A62A}.seg.thin{height:2px;background:#3A404C}
.tl-labels{margin-top:14px;font-size:15px;line-height:1.4}.tl-labels span{color:#A9A8A0}
.tl-labels .f1{display:flex;justify-content:space-between;gap:12px}.tl-labels .r{text-align:right}
.tl-foot{margin:20px 0 0;font-size:14px;color:#A9A8A0}
.ctas{margin-top:56px;display:flex;flex-wrap:wrap;gap:12px}
.btn{display:inline-flex;align-items:center;min-height:48px;padding:0 22px;border-radius:10px;text-decoration:none;font-weight:600;font-size:16px;border:1px solid transparent}
.btn.light{background:#F3F1EA;color:#0F1218}.btn.light:hover{color:#0F1218;background:#fff}
.btn.ghost{border-color:#3A404C;color:#F3F1EA;font-weight:500}
.btn.solid{background:var(--btn-bg);color:var(--btn-ink);min-height:44px;font-size:15px;padding:0 18px}.btn.solid:hover{color:var(--btn-ink)}
.btn.line{border-color:var(--border);min-height:44px;font-size:15px;padding:0 18px}
/* coverage strip */
.strip{background:var(--sunk);border-bottom:1px solid var(--line)}
.strip .wrap{padding-top:16px;padding-bottom:16px;display:flex;flex-wrap:wrap;gap:8px 24px;align-items:center;font-size:14px;color:var(--ink2)}
.strip strong{color:var(--ink);font-weight:600}
.meter{flex:1 1 160px;max-width:240px;height:6px;border-radius:3px;background:var(--line);overflow:hidden}
.meter span{display:block;height:100%;background:var(--ink)}
/* sections */
section.s{padding-top:88px}
h2{margin:0;font-size:32px;line-height:1.15;letter-spacing:-.02em;font-weight:650}
h2.sm{font-size:24px;letter-spacing:-.01em}h2.xs{font-size:20px;margin-bottom:16px}
.sub{margin:8px 0 0;font-size:17px;color:var(--ink2)}
.cols{margin-top:32px;display:flex;flex-wrap:wrap;gap:24px}.cols>*{flex:1 1 460px;min-width:0}
.card{background:var(--surface);border:1px solid var(--line);border-radius:14px}
.list{padding:8px 0}.list h3{margin:0;padding:16px 24px 8px;font-size:15px;font-weight:600;color:var(--ink2)}
.li{display:flex;gap:16px;align-items:baseline;padding:14px 24px;border-top:1px solid var(--line2);text-decoration:none}
.li .m{flex:1;min-width:0;overflow-wrap:anywhere}.li .m small{font:13px var(--mono);color:var(--ink2)}
.li .r{font-size:14px;color:var(--ink2);text-align:right;white-space:nowrap}
.adot{width:8px;height:8px;border-radius:50%;background:var(--mark);flex:none;transform:translateY(-2px)}
.facts3{margin-top:48px;display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));border-top:2px solid var(--ink)}
.facts3>div{padding:28px 32px 28px 0}.facts3 .n{font-size:56px;font-weight:650;letter-spacing:-.04em;line-height:1}
.facts3 p{margin:14px 0 0;color:var(--ink2)}.facts3 strong{color:var(--ink)}
.more{display:inline-flex;align-items:center;min-height:44px;margin-top:12px;font-weight:600}
.cards3{margin-top:32px;display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:24px}
h2.lg{margin-top:10px;max-width:820px;font-size:40px}
.cards3 .card{padding:28px}.cards3 h3{margin:0;font-size:19px;font-weight:600}.cards3 p{margin:8px 0 16px;font-size:15px;color:var(--ink2)}
pre{margin:0;padding:14px 16px;background:var(--code-bg);color:var(--code-ink);border-radius:10px;font:13px/1.6 var(--mono);overflow-x:auto}
pre.light{background:var(--surface);color:var(--ink);border:1px solid var(--line);font-size:12.5px;line-height:1.65;padding:18px 20px}
.about{display:flex;flex-wrap:wrap;gap:24px 64px;border-top:1px solid var(--line);padding-top:48px}
.about h2{flex:1 1 240px}.about div{flex:3 1 520px;min-width:0;color:var(--ink2);line-height:1.65}.about p{margin:0 0 16px}
footer.wrap{padding-top:72px;padding-bottom:48px;font-size:13px;line-height:1.6;color:var(--muted)}
footer .f{border-top:1px solid var(--line);padding-top:24px;display:flex;flex-wrap:wrap;gap:16px 48px;justify-content:space-between}
footer p{margin:0;max-width:760px}
/* tracker */
.head{padding-top:48px;display:flex;flex-wrap:wrap;gap:24px 48px;align-items:flex-end;justify-content:space-between}
h1.page{margin:8px 0 0;font-size:44px;line-height:1.05;letter-spacing:-.03em;font-weight:650}
h1.page b{color:var(--mark);font-weight:650}
.sevs{margin:0;display:flex;flex-wrap:wrap;gap:8px 32px;font-size:14px}.sevs dt{color:var(--muted)}.sevs dd{margin:2px 0 0;font-size:22px;font-weight:600}
.tabs{margin-top:40px;display:flex;flex-wrap:wrap;gap:0 24px;border-bottom:1px solid var(--line)}
.tabs button{min-height:44px;padding:0 2px;background:none;border:0;border-bottom:2px solid transparent;font:inherit;font-size:15px;color:var(--ink2);cursor:pointer}
.tabs button[aria-selected="true"]{border-bottom-color:var(--ink);color:var(--ink);font-weight:600}.tabs .n{color:var(--muted);font-weight:500}
.filters{margin-top:20px;display:flex;flex-wrap:wrap;gap:12px;align-items:flex-end}
.filters label{flex:1 1 130px;min-width:0;display:flex;flex-direction:column;gap:6px;font-size:13px;color:var(--ink2)}.filters label.q{flex:2 1 240px}
.filters input,.filters select{width:100%}
.filters input,.filters select{min-height:44px;padding:0 12px;border:1px solid var(--border);border-radius:10px;background:var(--surface);font:inherit;font-size:15px;color:var(--ink)}
.tbl{margin-top:24px;overflow-x:auto;border:1px solid var(--line);border-radius:14px;background:var(--surface)}
table{width:100%;min-width:880px;border-collapse:collapse;font-size:15px}
th{text-align:left;color:var(--muted);font-size:13px;font-weight:500;padding:14px 12px;border-bottom:1px solid var(--line)}
td{padding:14px 12px;border-bottom:1px solid var(--line2);vertical-align:top}
th:first-child,td:first-child{padding-left:20px}th:last-child,td:last-child{padding-right:20px}
td.p{max-width:300px;overflow-wrap:anywhere}td small{display:block;font-size:13px;color:var(--muted);overflow-wrap:anywhere}td a{text-decoration:none}td a:hover{text-decoration:underline}
.sev-critical,.sev-high{font-weight:600}.sev-low,.sev-unknown{color:var(--ink2)}
.cve{display:inline-flex;align-items:center;gap:8px;white-space:nowrap}
.cd{width:10px;height:10px;border-radius:50%;border:2px solid var(--ink);flex:none}
.cd.rbp{background:linear-gradient(90deg,var(--ink) 50%,transparent 50%)}.cd.pub{background:var(--ink)}.cd.cna{background:var(--ink);border-radius:2px}
.cd.other{border-style:dotted}
.wait{display:block;margin-top:6px;height:4px;border-radius:2px;background:var(--line2);width:140px}.wait i{display:block;height:4px;border-radius:2px;background:var(--mark)}
.pager{margin-top:16px;display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:space-between;font-size:14px;color:var(--ink2)}
.pager span.b{display:flex;gap:8px}
.pager button{min-height:44px;padding:0 16px;border:1px solid var(--border);border-radius:10px;background:var(--surface);font:inherit;color:var(--ink);cursor:pointer}
.pager button:disabled{color:var(--muted);cursor:default}
.legend{margin-top:20px;display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px}
.legend .card{padding:20px}.legend p{margin:0}.legend p.t{display:flex;align-items:center;gap:8px;font-weight:600}
.legend p.d{margin-top:8px;font-size:14px;color:var(--ink2)}
/* advisory */
.crumb{padding-top:32px;font-size:14px;color:var(--muted)}.crumb a{color:var(--ink2)}
.adv-head{margin-top:24px;display:flex;flex-wrap:wrap;gap:24px;align-items:flex-start;justify-content:space-between}
.pill{margin:0;display:inline-flex;align-items:center;gap:8px;padding:6px 12px;border-radius:999px;background:var(--pill-bg);color:var(--pill-ink);font-size:14px;font-weight:600}
.pill i{width:8px;height:8px;border-radius:50%;background:var(--mark)}
h1.ghsa{margin:16px 0 0;font:500 clamp(26px,4vw,40px)/1.2 var(--mono);letter-spacing:-.02em;overflow-wrap:anywhere}
.adv-body{margin-top:40px;display:flex;flex-wrap:wrap;gap:32px}.adv-body>section{min-width:0}
.facts{margin:0}.facts>div{display:flex;flex-wrap:wrap;gap:4px 24px;padding:16px 20px;border-bottom:1px solid var(--line2)}
.facts>div:last-child{border-bottom:0}.facts dt{flex:0 0 200px;color:var(--muted);font-size:14px}.facts dd{margin:0;flex:1 1 240px;min-width:0;overflow-wrap:anywhere}
.facts small{display:block;font-size:13px;color:var(--muted)}
.advice{margin-top:24px;padding:20px 24px;border-radius:14px;background:#0F1218;color:#F3F1EA;border:1px solid #2A303B}
.advice h2{font-size:17px;font-weight:600;letter-spacing:0}.advice p{margin:8px 0 0;font-size:15px;color:#C3C2B7}
ol.steps{margin:0;padding:0;list-style:none}ol.steps li{display:flex;gap:16px}
.rail{display:flex;flex-direction:column;align-items:center;flex:none;width:14px}
.rail b{width:14px;height:14px;border-radius:50%;background:var(--mark);flex:none}.rail b.o{width:10px;height:10px;background:none;border:2px solid var(--mark);margin:2px}
.rail b.p{width:10px;height:10px;background:none;border:2px dashed var(--muted);margin:2px}
.rail i{width:3px;flex:1;background:var(--mark);min-height:40px}.rail i.p{width:0;border-left:2px dashed var(--border);background:none}
.step{padding-bottom:24px}.step p{margin:0}.step .w{font:13px var(--mono);color:var(--muted)}.step .h{margin-top:4px;font-weight:600}
.step .h.p{color:var(--ink2)}.step .d{margin-top:2px;font-size:14px;color:var(--ink2)}
/* feed */
.files>div{display:flex;flex-wrap:wrap;gap:8px 24px;align-items:center;padding:18px 20px;border-bottom:1px solid var(--line2)}
.files>div:last-child{border-bottom:0}.files .x{flex:1 1 300px;min-width:0}.files p{margin:4px 0 0;font-size:14px;color:var(--ink2)}
.num{flex:none;width:28px;height:28px;border-radius:50%;border:1px solid var(--border);display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:600}
.num.p{border-style:dashed;color:var(--ink2)}
.note{margin-top:24px;padding:20px 24px;border:1px solid var(--line);border-radius:14px;background:var(--sunk)}
/* why */
.story{max-width:680px;padding-top:48px}.story p{margin:0 0 20px;font-size:18px;line-height:1.7;color:var(--ink2)}
.story p strong{color:var(--ink)}.story .mono{overflow-wrap:anywhere}.story .sig{margin-top:40px;color:var(--ink);font-weight:600}
.story-tl{margin:8px 0 40px;padding:0;list-style:none;border-left:2px solid var(--line)}
.story-tl li{position:relative;padding:0 0 22px 24px}.story-tl li:before{content:"";position:absolute;left:-6px;top:7px;
width:10px;height:10px;border-radius:50%;background:var(--bg);border:2px solid var(--mark)}
.story-tl li.now:before{background:var(--mark)}.story-tl time{display:block;font:13px var(--mono);color:var(--muted)}
.story-tl span{display:block;margin-top:2px;line-height:1.55}
/* cookie consent (only when analytics is on) */
.consent{position:fixed;left:16px;right:16px;bottom:16px;z-index:30;max-width:600px;margin-left:auto;display:flex;flex-wrap:wrap;
gap:12px 16px;align-items:center;padding:16px 18px;background:var(--surface);color:var(--ink);border:1px solid var(--border);
border-radius:14px;box-shadow:0 16px 40px rgba(0,0,0,.25);font-size:14px;line-height:1.5}
.consent[hidden]{display:none}.consent p{margin:0;flex:1 1 280px;color:var(--ink2)}.consent div{display:flex;gap:8px}
.note h3{margin:0;font-size:16px;font-weight:600}.note ul{margin:10px 0 0;padding-left:18px;font-size:14px;color:var(--ink2)}
@media (max-width:640px){.wrap{padding-left:16px;padding-right:16px}
/* header: one row, menu in a panel */
.bar{position:relative;flex-wrap:nowrap;padding-top:8px;padding-bottom:8px}nav.main{display:none}
.menu{display:block}.menu summary{display:flex;align-items:center;gap:10px;min-height:44px;padding:0 12px;margin-right:-12px;
list-style:none;cursor:pointer;font-size:15px;font-weight:500;-webkit-tap-highlight-color:transparent}
.menu summary::-webkit-details-marker{display:none}
.burger,.burger:before,.burger:after{display:block;width:18px;height:2px;border-radius:1px;background:currentColor;transition:transform .15s}
.burger{position:relative}.burger:before,.burger:after{content:"";position:absolute;left:0}.burger:before{top:-6px}.burger:after{top:6px}
.menu[open] .burger{background:transparent}.menu[open] .burger:before{top:0;transform:rotate(45deg)}
.menu[open] .burger:after{top:0;transform:rotate(-45deg)}
.menu nav{position:absolute;left:0;right:0;top:100%;z-index:20;display:flex;flex-direction:column;padding:4px 16px 12px;
background:var(--bg);border-bottom:1px solid var(--line);box-shadow:0 16px 32px rgba(0,0,0,.18)}
.menu nav a{display:flex;align-items:center;min-height:52px;border-bottom:1px solid var(--line2);text-decoration:none;font-size:18px}
.menu nav a:last-child{border-bottom:0}.menu nav a[aria-current]{font-weight:600;color:var(--amber-text)}
.hero .menu nav{background:#0F1218;border-color:#2A303B}.hero .menu nav a{border-color:#232833}
/* home */
.hero-body{padding-top:32px;padding-bottom:48px}.hero .eyebrow .dt{display:none}.hero h1{margin-top:12px}.lede{font-size:17px;margin-top:18px}
.count-row{margin-top:40px;gap:28px}.stats{gap:18px 24px}.stats dd{font-size:24px}
.tl{margin-top:48px}.tl-row,.tl-cols{display:none}
.tl-v{display:block;margin:0;padding:0;list-style:none}.tl-v li{position:relative;padding:0 0 20px 34px;font-size:15px;line-height:1.45}
.tl-v li:before{content:"";position:absolute;left:5px;top:10px;bottom:-10px;width:6px;background:#F4A62A}
.tl-v li.rev:before{left:7px;width:2px;background:#3A404C}.tl-v li.seen:before{display:none}
.tl-v b{position:absolute;left:0;top:2px;width:16px;height:16px;border-radius:50%}.tl-v .pub b{background:#F4A62A}
.tl-v .rev b{background:#0F1218;border:3px solid #F3F1EA}.tl-v .seen b{background:#F3F1EA}
.tl-v span{display:block;color:#A9A8A0}.tl-v .limbo{padding-top:4px;padding-bottom:28px}.tl-v .limbo .tl-tag{margin-bottom:4px}
.tl-foot{margin-top:4px}
.ctas{margin-top:40px;flex-direction:column}.ctas .btn{justify-content:center}
.strip .wrap{flex-direction:column;align-items:stretch;gap:12px}.meter{flex:none;max-width:none}
.strip a{display:inline-flex;align-items:center;min-height:44px;margin:-10px 0}
section.s{padding-top:64px}h2{font-size:26px}h2.lg{font-size:30px}h2.sm{font-size:22px}
.cols{margin-top:24px;gap:16px}.li{padding:14px 16px;gap:12px}.list h3{padding:14px 16px 6px}
.li .m small{display:block;margin-top:2px;line-height:1.5}.li .m small .sep{display:none}.li .m small span{display:block}
.facts3{margin-top:32px}.facts3>div{padding:24px 0}.facts3 .n{font-size:44px}
.cards3{gap:16px}.cards3 .card{padding:20px}
.cards3 pre,ol.steps pre{white-space:pre-wrap;overflow-wrap:anywhere}
.about{padding-top:32px}footer.wrap{padding-top:56px}
/* tracker */
h1.page{font-size:34px}.head{padding-top:32px;gap:24px}.sevs{display:grid;grid-template-columns:repeat(4,auto);gap:4px 16px;width:100%}
.tabs{margin-top:32px;flex-wrap:nowrap;gap:0 20px;overflow-x:auto;scrollbar-width:none}.tabs::-webkit-scrollbar{display:none}
.tabs button{flex:none;white-space:nowrap}.tabs .lg{display:none}.tabs .sm{display:inline}
.filters{gap:10px}.filters label.q{flex:1 1 200px}.filters label:not(.q){display:none;flex:1 1 calc(50% - 5px)}
.filters.open label{display:flex}
.ftoggle{display:inline-flex;align-items:center;gap:8px;min-height:44px;padding:0 14px;border:1px solid var(--border);border-radius:10px;
background:var(--surface);font:inherit;font-size:15px;font-weight:500;color:var(--ink);cursor:pointer;white-space:nowrap}
.ftoggle[aria-expanded="true"]{background:var(--ink);color:var(--bg);border-color:var(--ink)}
.tbl{margin-top:16px;overflow:visible}table{min-width:0}thead{display:none}
.tbl tr{display:grid;grid-template-columns:minmax(0,1fr) auto;grid-template-areas:"p sev" "id id" "cve cve" "wait fix";
gap:6px 12px;padding:16px;border-bottom:1px solid var(--line2)}.tbl tr:last-child{border-bottom:0}
.tbl td{display:block;padding:0;border:0;max-width:none}.tbl td[colspan]{grid-column:1/-1}
.tbl .c-p{grid-area:p}.tbl .c-id{grid-area:id}.tbl .c-cve{grid-area:cve}.tbl .c-cve small{margin-top:2px}
.tbl .c-sev{grid-area:sev;align-self:start;justify-self:end;padding:1px 10px;border:1px solid var(--border);border-radius:999px;font-size:13px;line-height:1.6}
.tbl .c-sev.sev-critical,.tbl .c-sev.sev-high{background:var(--pill-bg);color:var(--pill-ink);border-color:transparent}
.tbl .c-wait{grid-area:wait;align-self:end;font-size:14px}.tbl .c-wait:before{content:attr(data-l) " ";color:var(--muted)}
.tbl .c-fix{grid-area:fix;align-self:end;text-align:right}.tbl .c-fix:before{content:"Fixed in ";font:13px var(--sans);color:var(--muted)}
.tbl .c-fix.none:before{content:"No fixed version"}.tbl .c-fix.none span{display:none}
.wait{width:110px}
.pager{flex-direction:column;align-items:stretch}.pager span.b{flex-wrap:wrap}.pager button{flex:1}
.pager .btn{flex:1 1 100%;justify-content:center}
/* advisory, feed, why */
.facts dt{flex-basis:100%}.facts>div{padding:14px 16px}.adv-head .btn{width:100%;justify-content:center}
ol.steps li{gap:12px}pre.light{max-height:440px;overflow:auto}
.story{padding-top:32px}.story p{font-size:17px}
.consent div{width:100%}.consent .btn{flex:1;justify-content:center}}
/* home: search, flow, queue */
.find{margin-top:32px;max-width:640px}.find label{display:block;font-size:15px;font-weight:600;margin-bottom:8px}
.find div{display:flex;gap:8px}.find input{flex:1;min-width:0;min-height:48px;padding:0 14px;border-radius:10px;border:1px solid var(--border);
background:var(--surface);color:var(--ink);font:inherit}
.find button{min-height:48px;padding:0 18px;border-radius:10px;border:0;background:var(--btn-bg);color:var(--btn-ink);font:inherit;font-weight:600;cursor:pointer}
.find.dark input{background:#161A22;border-color:#3A404C;color:#F3F1EA}.find.dark input::placeholder{color:#7C818C}
.find.dark button{background:#F3F1EA;color:#0F1218}
.side{flex:1 1 380px;max-width:560px}.flow{margin:0 0 24px;font-size:19px;line-height:1.45;color:#C3C2B7}.flow strong{color:#F3F1EA}
.stats.three{grid-template-columns:repeat(3,minmax(0,1fr))}
figure.queue{margin:64px 0 0}figure.queue svg{display:block;width:100%;height:auto}
.qaxis{position:relative;height:22px;margin-top:10px;font-size:13px;color:#A9A8A0}
.qaxis span{position:absolute;top:0;white-space:nowrap}.qaxis span.end{transform:translateX(-80%)}
figure.queue figcaption{margin-top:14px;font-size:14px;color:#A9A8A0;max-width:760px}
@media (prefers-reduced-motion:no-preference){figure.queue g g{animation:settle .7s cubic-bezier(.2,.7,.3,1) both;
animation-delay:calc(var(--c) * 14ms)}@keyframes settle{from{opacity:0;transform:translateY(-24px)}to{opacity:1;transform:none}}}
/* home: proof */
.proof{display:flex;flex-wrap:wrap;gap:32px 64px;align-items:center}.ptext{flex:3 1 480px;min-width:0}.ptext .sub{max-width:640px}
.links{display:flex;flex-wrap:wrap;gap:4px 24px;margin:16px 0 0}.links a{display:inline-flex;align-items:center;min-height:44px;font-weight:600}
.vs{flex:2 1 320px;display:flex;flex-direction:column;gap:12px}
.vs>div{position:relative;display:flex;justify-content:space-between;align-items:center;padding:18px 20px;border:1px solid var(--line);
border-radius:12px;background:var(--surface);overflow:hidden}
.vs span{position:relative;z-index:1;font-size:15px}.vs b{position:relative;z-index:1;font-size:32px;font-weight:650;letter-spacing:-.02em}
.vs b.zero{color:var(--muted)}.vs .lw{border-color:var(--mark)}.vs .lw b{color:var(--amber-text)}
.vs i{position:absolute;inset:0 auto 0 0;background:var(--pill-bg);opacity:.6}
/* home: ecosystems, CVE split, paths */
.two{display:flex;flex-wrap:wrap;gap:48px 64px}.two>div{flex:1 1 420px;min-width:0}
table.eco{margin-top:20px;min-width:0;font-size:15px}table.eco th,table.eco td{padding:9px 8px;border-bottom:1px solid var(--line2)}
table.eco th:first-child{padding-left:0;font-weight:500;color:var(--ink);font-size:15px}table.eco td:last-child,table.eco th:last-child{padding-right:0}
table.eco thead th{color:var(--muted);font-size:13px;font-weight:500}.n{text-align:right;white-space:nowrap}
td.ebar{width:45%}td.ebar span{display:block;height:10px;border-radius:2px;background:var(--mark)}
.split{display:flex;height:28px;margin-top:24px;border-radius:6px;overflow:hidden;gap:2px}
.s0{background:var(--ink)}.s1{background:var(--ink2)}.s2{background:var(--muted)}.s3{background:var(--border)}
ul.keys{margin:20px 0 0;padding:0;list-style:none}ul.keys li{position:relative;padding:10px 0 10px 28px;border-bottom:1px solid var(--line2)}
ul.keys i{position:absolute;left:0;top:15px;width:14px;height:14px;border-radius:3px}ul.keys span{display:block;font-size:14px;color:var(--ink2)}
.paths{margin-top:32px;display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:32px 48px}
.paths>div{border-top:2px solid var(--ink);padding-top:20px}.paths h3{margin:0;font-size:19px;font-weight:600}
.paths p{margin:10px 0 0;color:var(--ink2)}.paths .links{flex-direction:column;gap:0;margin-top:8px}
/* footer */
.fcols{display:grid;grid-template-columns:2fr repeat(3,1fr);gap:32px;padding:48px 0;border-top:1px solid var(--line)}
.fabout{color:var(--ink)}.fabout p{margin:12px 0 0;max-width:320px;color:var(--ink2);font-size:14px}
.fcols h2{font-size:13px;font-weight:600;color:var(--ink);letter-spacing:0}.fcols ul{margin:10px 0 0;padding:0;list-style:none}
.fcols li a{display:inline-flex;min-height:32px;align-items:center;color:var(--ink2);text-decoration:none;font-size:14px;overflow-wrap:anywhere}
.fcols li a:hover{color:var(--amber-text);text-decoration:underline}
/* press */
.lead{max-width:680px;font-size:18px}.contact{flex:0 1 360px;padding:24px}.contact p{margin:6px 0 16px;color:var(--ink2);font-size:15px}
.contact .btn{width:100%;justify-content:center;overflow-wrap:anywhere}
ol.quotes{margin:24px 0 16px;padding:0;list-style:none;counter-reset:q;max-width:860px}
ol.quotes li{padding:20px 0;border-top:1px solid var(--line)}ol.quotes p{margin:0;font-size:19px;line-height:1.5}
ol.quotes a{display:inline-flex;min-height:36px;align-items:center;font-size:14px;color:var(--ink2)}
.poster{margin-top:24px;padding:8px 32px 28px;background:#0F1218;border-radius:14px}.poster figure.queue{margin-top:24px}
pre.wrapcode{white-space:pre-wrap;overflow-wrap:anywhere;margin-top:16px}
ul.kit{margin:16px 0 0;padding:0;list-style:none}ul.kit a{display:inline-flex;min-height:40px;align-items:center}
.tbl td.n,.tbl th.n{text-align:right}
/* methodology */
.doc{display:grid;grid-template-columns:minmax(220px,1fr) minmax(0,2.4fr);gap:48px;padding-top:48px}
.doc>div:first-child{position:sticky;top:24px;align-self:start}
.toc ol{margin:24px 0 0;padding:0;list-style:none}.toc a{display:flex;min-height:36px;align-items:center;color:var(--ink2);text-decoration:none;font-size:15px}
.toc a:hover{color:var(--amber-text)}
.prose{max-width:720px}.prose section{padding:8px 0 32px;border-bottom:1px solid var(--line2);margin-bottom:24px;scroll-margin-top:16px}
.prose h2{margin-bottom:12px}.prose p,.prose li{color:var(--ink2);line-height:1.7}.prose strong{color:var(--ink)}.prose ul{padding-left:20px}
@media (max-width:900px){.fcols{grid-template-columns:1fr 1fr}.fabout{grid-column:1/-1}.doc{grid-template-columns:1fr;gap:24px}
.doc>div:first-child{position:static}}
@media (max-width:640px){.find div{flex-direction:column}.find button{width:100%}.flow{font-size:17px}
.stats.three{grid-template-columns:repeat(3,minmax(0,1fr))}figure.queue{margin-top:40px}.qaxis span:nth-child(3){display:none}
.vs b{font-size:26px}.poster{padding:4px 16px 20px}ol.quotes p{font-size:17px}.fcols{grid-template-columns:1fr;gap:24px}}
/* data quality */
.qrepo{margin-top:32px}.qrepo h3{display:flex;flex-wrap:wrap;gap:4px 12px;align-items:baseline;margin:0 0 10px;font-size:17px;overflow-wrap:anywhere}
.qrepo h3 small{color:var(--muted);font-weight:400;font-size:14px}.qrepo .card{padding:0}
.qrow{padding:16px;border-top:1px solid var(--line2)}.qrow:first-child{border-top:0}.qrow p{margin:6px 0 0}
.qrow .qh{font-size:14px;color:var(--muted)}.qrow .was{background:var(--sunk);padding:2px 6px;border-radius:6px;overflow-wrap:anywhere}
"""

TRACKER_JS = """(()=>{const $=s=>document.querySelector(s),esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const CVE=JSON.parse($('#cve-text').textContent),SEV={critical:0,high:1,medium:2,low:3,unknown:4},PER=50;
let D=null,tab='pending',page=0;
const days=n=>n==null?'–':(n<1?'< 1 day':Math.floor(n)===1?'1 day':Math.floor(n).toLocaleString('en')+' days');
function list(){const q=$('#q').value.trim().toLowerCase(),eco=$('#eco').value,sev=$('#sev').value,cve=$('#cve').value,sort=$('#sort').value,pub=+$('#pub').value||0;
 let r=D[tab].filter(x=>(!q||(x.id+' '+x.pkg+' '+x.repo+' '+x.cves).toLowerCase().includes(q))&&(!eco||x.eco===eco)
  &&(!sev||(sev==='high+'?SEV[x.sev]<=1:sev==='medium+'?SEV[x.sev]<=2:x.sev===sev))&&(!cve||x.cve===cve)&&(!pub||(x.age??1e9)<=pub));
 const by={sev:(a,b)=>SEV[a.sev]-SEV[b.sev]||(b.age??0)-(a.age??0),old:(a,b)=>(b.age??0)-(a.age??0),new:(a,b)=>(a.age??1e9)-(b.age??1e9)};
 return r.sort(by[sort]);}
function render(){if(!D)return;const r=list(),n=r.length,max=Math.max(1,...r.map(x=>x.age||0));page=Math.min(page,Math.max(0,Math.ceil(n/PER)-1));
 const rows=r.slice(page*PER,page*PER+PER);
 $('#rows').innerHTML=rows.map(x=>`<tr><td class="p c-p"><a href="/advisory/${esc(x.id)}/"><strong>${esc(x.pkg)}</strong></a><small>${esc(x.eco)} · ${esc(x.repo)}</small></td>
<td class="mono c-id" style="font-size:13px;white-space:nowrap"><a href="/advisory/${esc(x.id)}/">${esc(x.id)}</a></td><td class="c-sev sev-${esc(x.sev)}">${esc(x.sev[0].toUpperCase()+x.sev.slice(1))}</td>
<td class="c-cve">${tab==='left'?esc(x.to)+'<small>'+esc(x.at)+'</small>':`<span class="cve"><span class="cd ${esc(x.cve)}" aria-hidden="true"></span>${esc(CVE[x.cve])}</span><small class="mono">${esc(x.cves)}</small>`}</td>
<td class="c-wait" data-l="${tab==='left'?'Waited':'Waiting'}">${esc(days(x.age))}${tab==='left'?'':`<span class="wait" aria-hidden="true"><i style="width:${Math.max(2,Math.round((x.age||0)/max*100))}%"></i></span>`}</td>
<td class="mono c-fix${x.fix?'':' none'}" style="font-size:13px">${x.fix?esc(x.fix):'<span>–</span>'}</td></tr>`).join('')||'<tr><td colspan="6" class="muted">Nothing matches.</td></tr>';
 $('#shown').textContent=n?`Showing ${(page*PER+1).toLocaleString('en')}–${Math.min(n,page*PER+PER).toLocaleString('en')} of ${n.toLocaleString('en')}`:'';
 $('#prev').disabled=page===0;$('#next').disabled=(page+1)*PER>=n;
 const nf=['#eco','#sev','#cve','#pub'].filter(s=>$(s).value).length+($('#sort').value!=='new');
 $('#ftoggle').textContent=nf?`Filters · ${nf}`:'Filters';
 $('#h-cve').textContent=tab==='left'?'Left limbo':'CVE';$('#h-wait').textContent=tab==='left'?'Waited':'Waiting';}
document.querySelectorAll('.tabs button').forEach(b=>b.addEventListener('click',()=>{tab=b.dataset.tab;page=0;
 document.querySelectorAll('.tabs button').forEach(o=>o.setAttribute('aria-selected',String(o===b)));render();}));
$('#filters').addEventListener('submit',e=>e.preventDefault());
$('#ftoggle').addEventListener('click',()=>{const o=$('#filters').classList.toggle('open');$('#ftoggle').setAttribute('aria-expanded',String(o));});
['#q','#eco','#sev','#cve','#pub','#sort'].forEach(s=>$(s).addEventListener('input',()=>{page=0;render();}));
$('#prev').addEventListener('click',()=>{page--;render();});$('#next').addEventListener('click',()=>{page++;render();});
const q0=new URLSearchParams(location.search).get('q');if(q0)$('#q').value=q0;
fetch('/tracker/data.json').then(r=>r.json()).then(d=>{D=d;const ecos=[...new Set([...d.pending,...d.permanent].map(x=>x.eco))].sort();
 $('#eco').insertAdjacentHTML('beforeend',ecos.map(e=>`<option>${esc(e)}</option>`).join(''));render();})
 .catch(()=>{$('#rows').innerHTML='<tr><td colspan="6">Couldn\\'t load the data. <a href="/feed/">Use the feed instead.</a></td></tr>';});
})();
"""


def mark(stroke: str, dot: str, size: int = 30) -> str:
    """The "Suspended" mark (brand/make_brand.py, small version): an hourglass whose grain is stuck in the neck."""
    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 512 512" aria-hidden="true">'
        f'<path d="M 124 72 L 388 72 L 256 198 Z" fill="{stroke}" stroke="{stroke}" stroke-width="52" stroke-linejoin="round"/>'
        f'<path d="M 124 440 L 388 440 L 256 314 Z" fill="none" stroke="{stroke}" stroke-width="52" stroke-linejoin="round"/>'
        f'<circle cx="256" cy="256" r="28" fill="{dot}"/></svg>'
    )


def header(active: str, dark: bool = False) -> str:
    links = [("tracker", "/tracker/", "Tracker"), ("scan", "/scan/", "Scan your project"), ("feed", "/feed/", "Feed"),
             ("methodology", "/methodology/", "Methodology"), ("press", "/press/", "Press"), ("why", "/why/", "Why"),
             ("", REPO_URL, "GitHub ↗")]  # fmt: skip
    current = ' aria-current="page"'
    nav = "".join(
        f'<a href="{href}"{current if key and key == active else ""}>{label}</a>' for key, href, label in links
    )
    logo = mark("#F3F1EA", "#F4A62A") if dark else mark("currentColor", "var(--mark)")
    # Phones get the same links in a disclosure panel; only one of the two navs is ever displayed.
    menu = (
        '<details class="menu"><summary><span class="burger" aria-hidden="true"></span>Menu</summary>'
        f'<nav aria-label="Main">{nav}</nav></details>'
    )
    return (
        f'<div class="wrap bar"><a class="brand" href="/">{logo}<span>limbo<b>.</b>watch</span></a>'
        f'<nav class="main" aria-label="Main">{nav}</nav>{menu}</div>'
    )


def footer(extra: str = "") -> str:
    cols = [
        ("Use it", [("/tracker/", "Tracker"), ("/scan/", "Scan your project"), ("/feed/", "Limbo feed (OSV)"),
                    ("/feed/critical.atom", "Atom: new critical and high"), ("/quality/", "Data quality")]),
        ("Learn", [("/methodology/", "Methodology"), (REPORT_URL, "October 2026 report"), ("/why/", "Why I built it"),
                   (FINDINGS_URL, "Research log")]),
        ("Contact", [("/press/", "Press and research"), (f"mailto:{CONTACT}", CONTACT), (REPO_URL, "GitHub"),
                     (ISSUE_URL, "Daily report by email")]),
    ]  # fmt: skip
    nav = "".join(
        f"<div><h2>{h}</h2><ul>{''.join(f'<li><a href="{E(u)}">{E(t)}</a></li>' for u, t in links)}</ul></div>"
        for h, links in cols
    )
    return (
        f'<footer class="wrap"><div class="fcols"><div class="fabout">{mark("currentColor", "var(--mark)", 26)}'
        "<p>Limbowatch tracks security advisories that maintainers have published but scanners can’t see yet. "
        "Open source, open data.</p></div>"
        f'{nav}</div><div class="f"><p>{extra}{E(ATTRIBUTION)}</p>'
        f'<p>limbo.watch · <a href="{REPO_URL}">Source</a> · Apache-2.0</p></div></footer>'
    )


MENU_JS = (
    "<script>document.addEventListener('click',e=>{const m=document.querySelector('details.menu[open]');"
    "if(m&&(!m.contains(e.target)||e.target.closest('a')))m.open=false});</script>\n"
)


def page(title: str, description: str, body: str, path: str = "/", jsonld: dict[str, Any] | None = None) -> str:
    """A full HTML page, with the tags link previews and search engines read (Open Graph, canonical URL,
    the Atom feed and, where given, schema.org JSON-LD)."""
    url = SITE + path
    ld = json.dumps(jsonld, separators=(",", ":")).replace("</", "<\\/") if jsonld else ""
    return (
        '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f'<title>{E(title)}</title>\n<meta name="description" content="{E(description)}">\n'
        f'<link rel="canonical" href="{E(url)}">\n'
        '<meta property="og:type" content="website">\n<meta property="og:site_name" content="limbo.watch">\n'
        f'<meta property="og:title" content="{E(title)}">\n<meta property="og:description" content="{E(description)}">\n'
        f'<meta property="og:url" content="{E(url)}">\n<meta property="og:image" content="{SITE}/assets/social.png">\n'
        '<meta property="og:image:width" content="1280">\n<meta property="og:image:height" content="640">\n'
        '<meta name="twitter:card" content="summary_large_image">\n'
        '<link rel="alternate" type="application/atom+xml" title="New advisories in limbo" href="/feed/limbo.atom">\n'
        '<link rel="icon" href="/favicon.svg" type="image/svg+xml">\n<link rel="stylesheet" href="/assets/site.css">\n'
        + (f'<script type="application/ld+json">{ld}</script>\n' if ld else "")
        + f"</head>\n<body>\n{body}\n{MENU_JS}</body>\n</html>\n"
    )


def stamp(iso: str) -> str:
    """'2026-10-28T02:37:44Z' -> '2026-10-28 02:37 UTC'."""
    return f"{iso[:16].replace('T', ' ')} UTC" if iso else ""


def fmt_days(d: float | None) -> str:
    if d is None:
        return "–"
    n = int(d)
    return "< 1 day" if d < 1 else "1 day" if n == 1 else f"{n:,} days"


def pending(items: list[Item]) -> list[Item]:
    return [i for i in items if i.assessment.status is Status.LIMBO and not i.assessment.likely_permanent]


def permanent(items: list[Item]) -> list[Item]:
    return [i for i in items if i.assessment.status is Status.LIMBO and i.assessment.likely_permanent]


def _name(p: AdvisoryPackage) -> PackageName:
    return package_name(p.ecosystem, p.name) or PackageName("", "", False)


def pkg_names(i: Item) -> str:
    names = sorted({n.name for p in i.adv.packages if (n := package_name(p.ecosystem, p.name))})
    if not names:
        return i.adv.repo
    return names[0] if len(names) == 1 else f"{names[0]} +{len(names) - 1} more"


def eco_names(i: Item) -> str:
    return ", ".join(sorted({eco_label(p.ecosystem) for p in i.adv.packages})) or "–"


def fixes(i: Item) -> str:
    return fixes_text(i)


def cves(i: Item) -> str:
    return ", ".join(c for c in [i.facts.cited_cve, *i.facts.uncited_cves] if c)


def row(i: Item, now: datetime) -> dict[str, Any]:
    return {
        "id": i.adv.ghsa_id,
        "pkg": pkg_names(i),
        "eco": eco_names(i),
        "repo": i.adv.repo,
        "sev": i.adv.severity or "unknown",
        "cve": CVE_KEY[i.assessment.cve_label],
        "cves": cves(i),
        "age": None if (a := days_since(i.adv.published_at, now)) is None else round(a, 1),
        "fix": fixes(i)[:60],
    }


# --- charts -----------------------------------------------------------------------------------------


def queue_cols(pend: list[Item], now: datetime) -> tuple[list[tuple[int, int]], int]:
    """Advisories in limbo by whole weeks waiting: (all, critical or high) per week, the last column holding
    everything older than a year, plus the count with no publication date (shown, never dropped)."""
    cols = [[0, 0] for _ in range(QUEUE_WEEKS + 1)]
    undated = 0
    for i in pend:
        a = days_since(i.adv.published_at, now)
        if a is None:
            undated += 1
            continue
        c = cols[min(int(max(a, 0) // 7), QUEUE_WEEKS)]
        c[0] += 1
        c[1] += (i.adv.severity or "").lower() in ("critical", "high")
    return [(a, b) for a, b in cols], undated


QUEUE_TICKS = [(0, "This week"), (4, "1 month"), (13, "3 months"), (26, "6 months"), (QUEUE_WEEKS, "Over a year")]
_PITCH, _GRAIN, _GAP = 13, 10, 2  # square pitch and size, and the blank columns before "over a year"


def _queue_x(col: int) -> int:
    return (col + (_GAP if col == QUEUE_WEEKS else 0)) * _PITCH


def queue_svg(cols: list[tuple[int, int]], label: str) -> tuple[str, int, int]:
    """The queue: one square per QUEUE_UNIT advisories, stacked by weeks waiting, critical and high at the bottom
    (solid amber), the rest dim. A remainder is drawn as a partial square on top, so heights stay exact.
    Returns the shapes (inside a <g>) and the drawing's width and height."""
    width = _queue_x(QUEUE_WEEKS) + _GRAIN
    tallest = max([-(-total // QUEUE_UNIT) for total, _ in cols] + [1])
    height = tallest * _PITCH
    groups = []
    for col, (total, severe) in enumerate(cols):
        x = _queue_x(col)
        full, rest = divmod(total, QUEUE_UNIT)
        solid = min(full, round(severe / QUEUE_UNIT))
        rects = []
        for k in range(full + (1 if rest else 0)):
            h = _GRAIN if k < full else max(2.0, _GRAIN * rest / QUEUE_UNIT)
            y = height - k * _PITCH - h
            dim = "" if k < solid else ' fill-opacity=".3"'
            rects.append(f'<rect x="{x}" y="{y:g}" width="{_GRAIN}" height="{h:g}" rx="2" fill="#F4A62A"{dim}/>')
        groups.append(f'<g style="--c:{col}">{"".join(rects)}</g>')
    return f'<g role="img" aria-label="{E(label)}">{"".join(groups)}</g>', width, height


def queue_label(cols: list[tuple[int, int]]) -> str:
    total = sum(a for a, _ in cols)
    month = sum(a for a, _ in cols[:4])
    year = cols[QUEUE_WEEKS][0]
    return (
        f"Chart of {total:,} advisories in limbo by weeks waiting: {month:,} published in the last 4 weeks, "
        f"{year:,} waiting more than a year."
    )


def queue_figure(cols: list[tuple[int, int]], undated: int) -> str:
    shapes, w, h = queue_svg(cols, queue_label(cols))
    ticks = "".join(
        f'<span style="left:{100 * _queue_x(c) / w:.2f}%"{' class="end"' if c == QUEUE_WEEKS else ""}>{E(t)}</span>'
        for c, t in QUEUE_TICKS
    )
    note = f" {undated:,} advisories have no publication date and aren’t drawn." if undated else ""
    return (
        f'<figure class="queue"><svg viewBox="0 0 {w} {h}" >{shapes}</svg>'
        f'<div class="qaxis" aria-hidden="true">{ticks}</div>'
        f"<figcaption>Every advisory in limbo, by how long it has waited. Each square is {QUEUE_UNIT} advisories; "
        f'solid squares are critical or high.{note} <a href="/press/queue.svg">Download the chart</a></figcaption></figure>'
    )


def queue_poster(cols: list[tuple[int, int]], m: dict[str, Any]) -> str:
    """The queue as a standalone SVG for reporters, with title, legend and source."""
    li = m["in_limbo"]
    shapes, w, h = queue_svg(cols, queue_label(cols))
    scale = 1080 / w
    ticks = "".join(
        f'<text x="{60 + _queue_x(c) * scale:.1f}" y="{180 + h * scale + 30:.1f}" fill="#A9A8A0" font-size="16"'
        f"{' text-anchor="end"' if c == QUEUE_WEEKS else ''}>{E(t)}</text>"
        for c, t in QUEUE_TICKS
    )
    tick_last = _queue_x(QUEUE_WEEKS) * scale + 60 + _GRAIN * scale
    ticks = ticks.replace(f'x="{60 + _queue_x(QUEUE_WEEKS) * scale:.1f}"', f'x="{tick_last:.1f}"')
    total_h = int(180 + h * scale + 120)
    date = m["generated_at"][:10]
    font = "Helvetica Neue, Helvetica, Arial, sans-serif"
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 {total_h}" width="1200" height="{total_h}" '
        f'font-family="{font}"><rect width="1200" height="{total_h}" fill="#0F1218"/>'
        f'<text x="60" y="76" fill="#F3F1EA" font-size="38" font-weight="600">{li["count"]:,} security advisories waiting for review</text>'
        f'<text x="60" y="114" fill="#A9A8A0" font-size="19">Published by maintainers on GitHub, not yet in GitHub’s reviewed database '
        f"or OSV, so most scanners can’t see them.</text>"
        f'<text x="60" y="144" fill="#A9A8A0" font-size="19">By weeks waiting. Each square is {QUEUE_UNIT} advisories; '
        f'<tspan fill="#F4A62A">solid squares</tspan> are critical or high.</text>'
        f'<g transform="translate(60 180) scale({scale:.4f})">{shapes}</g>{ticks}'
        f'<text x="60" y="{total_h - 30}" fill="#7C818C" font-size="14">Source: limbo.watch, {date}. A floor: only watched '
        f"repositories are counted. Advisory data: GitHub Advisory Database (CC BY 4.0). Chart: Limbowatch, CC BY 4.0.</text></svg>\n"
    )


def eco_table(pend: list[Item], now: datetime) -> str:
    """Advisories in limbo per ecosystem, with the median wait so far."""
    ages: dict[str, list[float]] = defaultdict(list)
    counts: dict[str, int] = defaultdict(int)
    for i in pend:
        a = days_since(i.adv.published_at, now)
        for e in {eco_label(x) for x in i.assessment.ecosystems if reviewable(x)}:
            counts[e] += 1
            if a is not None:
                ages[e].append(a)
    rows = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    top = max(counts.values(), default=1)
    body = "".join(
        f'<tr><th scope="row">{E(e)}</th><td class="ebar"><span style="width:{100 * n / top:.1f}%"></span></td>'
        f'<td class="n">{n:,}</td><td class="n">{fmt_days(statistics.median(ages[e])) if ages[e] else "–"}</td></tr>'
        for e, n in rows
    )
    return (
        '<table class="eco"><thead><tr><th scope="col">Ecosystem</th><th scope="col"><span class="vh">Share</span></th>'
        '<th scope="col" class="n">In limbo</th><th scope="col" class="n">Median wait</th></tr></thead>'
        f"<tbody>{body}</tbody></table>"
    )


CVE_PARTS = [
    (CveLabel.NONE, "No CVE anywhere", "Neither CVE-based nor GitHub-based tools know these exist."),
    (CveLabel.RESERVED, "CVE reserved, not published", "The ID is public, but looking it up returns nothing."),
    (CveLabel.PUBLISHED_UNCITED, "CVE from another CNA", "Another CNA published a CVE the advisory doesn’t cite."),
    (
        CveLabel.PUBLISHED_CITED,
        "CVE published",
        "CVE-based tools can find these; GitHub- and OSV-based scanners can’t.",
    ),
]


def cve_split(m: dict[str, Any]) -> str:
    by = m["in_limbo"]["by_cve"]
    total = sum(by.values()) or 1
    other = total - sum(by.get(k.value, 0) for k, _, _ in CVE_PARTS)
    segs = "".join(
        f'<span class="s{n}" style="flex:{by.get(k.value, 0)}"></span>' for n, (k, _, _) in enumerate(CVE_PARTS)
    )
    keys = "".join(
        f'<li><i class="s{n}" aria-hidden="true"></i><strong>{by.get(k.value, 0):,}</strong> {E(t)}'
        f"<span>{E(d)}</span></li>"
        for n, (k, t, d) in enumerate(CVE_PARTS)
    )
    extra = f'<p class="muted small">{other:,} cite a CVE in another state.</p>' if other else ""
    return f'<div class="split" aria-hidden="true">{segs}</div><ul class="keys">{keys}</ul>{extra}'


# --- home -------------------------------------------------------------------------------------------

DEMO_PR = "https://github.com/limbowatch/demo-app/pull/1"
WATCHER_DOC = f"{REPO_URL}/blob/main/docs/WATCHER.md"
EVIDENCE = f"{REPO_URL}/tree/main/research/2026-11-demo-evidence"
SEARCH_JS = (
    "<script>document.querySelectorAll('form.find').forEach(f=>f.addEventListener('submit',e=>{e.preventDefault();"
    "const q=f.querySelector('input').value.trim();location.href='/tracker/'+(q?'?q='+encodeURIComponent(q):'');}));</script>"
)


def find_form(dark: bool = False) -> str:
    return (
        f'<form class="find{" dark" if dark else ""}" role="search"><label for="find-q">Is a package you use waiting?</label>'
        '<div><input id="find-q" name="q" type="search" placeholder="Package, repository, GHSA or CVE ID" autocomplete="off">'
        '<button type="submit">Search the tracker</button></div></form>'
    )


def dataset_ld(m: dict[str, Any]) -> dict[str, Any]:
    return {
        "@context": "https://schema.org",
        "@type": "Dataset",
        "name": "Limbowatch: security advisories in limbo",
        "description": "Security advisories published by maintainers on GitHub but not yet in GitHub’s reviewed "
        "Advisory Database or OSV, so most dependency scanners can’t see them. Rebuilt daily.",
        "url": SITE + "/",
        "license": "https://creativecommons.org/licenses/by/4.0/",
        "isAccessibleForFree": True,
        "creator": {"@type": "Organization", "name": "Limbowatch", "url": SITE},
        "dateModified": m["generated_at"],
        "keywords": ["security advisories", "vulnerabilities", "GHSA", "CVE", "OSV", "software supply chain"],
        "distribution": [
            {"@type": "DataDownload", "encodingFormat": "application/zip", "contentUrl": f"{SITE}/feed/all.zip"},
            {"@type": "DataDownload", "encodingFormat": "application/json", "contentUrl": f"{SITE}/metrics.json"},
            {"@type": "DataDownload", "encodingFormat": "application/json", "contentUrl": f"{SITE}/tracker/data.json"},
        ],
    }


def home(items: list[Item], m: dict[str, Any], now: datetime) -> str:
    li, cov = m["in_limbo"], m["coverage"]
    flow = m.get("flow_7d") or {}
    pend = pending(items)
    ages = [a for i in pend if (a := days_since(i.adv.published_at, now)) is not None]
    sev = li["by_severity"]
    pct = 100 * cov["on_schedule"] / cov["watchlist_repos"] if cov["watchlist_repos"] else 0
    cols, undated = queue_cols(pend, now)
    fresh = sorted(pend, key=lambda i: i.adv.published_at or now, reverse=True)[:LIST_ROWS]
    # Old advisories GitHub never backfilled would fill this list (some date from 2019), so it covers the last year.
    recent = [i for i in pend if (days_since(i.adv.published_at, now) or 0) <= 365]
    oldest = sorted(recent, key=lambda i: i.adv.published_at or now)[:LIST_ROWS]

    def lst(title: str, rows: list[Item]) -> str:
        body = (
            "".join(
                f'<a class="li" href="/advisory/{E(i.adv.ghsa_id)}/"><span class="adot" aria-hidden="true"></span>'
                f'<span class="m"><strong>{E(pkg_names(i))}</strong> <span class="muted">{E(eco_names(i))}</span><br>'
                f'<small><span>{E(i.adv.ghsa_id)}</span><span class="sep">, </span>'
                f"<span>{E(cves(i) or CVE_TEXT[CVE_KEY[i.assessment.cve_label]].lower())}</span></small></span>"
                f'<span class="r">{E((i.adv.severity or "unknown").capitalize())}<br>{fmt_days(days_since(i.adv.published_at, now))}</span></a>'
                for i in rows
            )
            or '<p class="li muted">None right now.</p>'
        )
        return f'<div class="card list"><h3>{title}</h3>{body}</div>'

    updated = stamp(m["generated_at"])
    flow_html = (
        f'<p class="flow"><strong>{flow["published"]:,}</strong> new advisories were published in the last '
        f"{flow['days']} days. GitHub reviewed <strong>{flow['reviewed']:,}</strong> of the ones waiting.</p>"
        if flow
        else ""
    )
    body = f"""<div class="hero">{header("", dark=True)}
<section class="wrap hero-body">
<p class="eyebrow">Live, re-checked every day. Updated {E(updated)}.</p>
<h1>Published. Often fixed. Invisible to your scanner.</h1>
<p class="lede">Maintainers publish security advisories on GitHub every day. Dependabot, npm audit and OSV-Scanner can’t
see them until GitHub reviews them into its Advisory Database, and that review now takes weeks. Limbowatch tracks every
advisory stuck in between.</p>
{find_form(dark=True)}
<figure class="tl"><figcaption>Where an advisory waits</figcaption>
<div class="tl-cols"><div class="f3 pr"><p class="tl-tag">In limbo</p><p class="tl-note">Public and often already fixed, but
scanners report nothing.</p></div><div class="f1"></div></div>
<div class="tl-row" aria-hidden="true"><span class="dot amber"></span><span class="seg f3"></span><span class="dot ring"></span>
<span class="seg thin f1"></span><span class="dot fill"></span></div>
<div class="tl-cols tl-labels"><div class="f3 pr"><strong>Maintainer publishes</strong><br><span>a repository advisory</span></div>
<div class="f1"><div><strong>GitHub reviews it</strong><br><span>global Advisory DB</span></div>
<div class="r"><strong>Scanners see it</strong><br><span>via OSV, hours later</span></div></div></div>
<ol class="tl-v">
<li class="pub"><b aria-hidden="true"></b><strong>Maintainer publishes</strong><span>a repository advisory</span></li>
<li class="limbo"><p class="tl-tag">In limbo</p><span>Public and often already fixed, but scanners report nothing.</span></li>
<li class="rev"><b aria-hidden="true"></b><strong>GitHub reviews it</strong><span>global Advisory DB</span></li>
<li class="seen"><b aria-hidden="true"></b><strong>Scanners see it</strong><span>via OSV, hours later</span></li></ol></figure>
<div class="count-row"><div><div class="big">{li["count"]:,}</div><div class="big-label">advisories in limbo right now</div></div>
<div class="side">{flow_html}
<dl class="stats three">
<div><dt>Critical or high</dt><dd>{sev["critical"] + sev["high"]:,}</dd></div>
<div><dt>Median wait so far</dt><dd>{fmt_days(li["age_days_median"])}</dd></div>
<div><dt>Waiting over 90 days</dt><dd>{sum(1 for x in ages if x > 90):,}</dd></div>
</dl></div></div>
{queue_figure(cols, undated)}
<div class="ctas"><a class="btn light" href="/tracker/">See all {li["count"]:,} in the tracker</a>
<a class="btn ghost" href="/scan/">Scan your project</a></div>
</section></div>
<div class="strip"><div class="wrap"><span><strong>Every number is a floor.</strong> We watch {cov["watchlist_repos"]:,} upstream
repositories; {cov["on_schedule"]:,} are up to date. Repos with an advisory in limbo are re-checked daily, the rest every 3 to 7 days.</span>
<span class="meter" role="img" aria-label="{pct:.0f}% of the watchlist up to date"><span style="width:{min(pct, 100):.0f}%"></span></span>
<a href="/methodology/#coverage">How coverage works</a></div></div>
<main>
<section class="wrap s proof"><div class="ptext"><h2>Your scanner says clean. It isn’t.</h2>
<p class="sub">We gave three tools the same demo app, with real npm, Go, pip and Bundler lockfiles, in November 2026.
GitHub’s Dependabot alerts and OSV-Scanner reported none of the 16 advisories in limbo that affect it. All 16 were
then rechecked against GitHub and OSV, independently of Limbowatch’s own code.</p>
<p class="sub">It isn’t only demos: in the projects behind our October report, Limbowatch found <strong>269 affected
package-versions in 13 of 14 projects</strong> that scanners reading GitHub’s database or OSV report as clean.</p>
<p class="links"><a href="{EVIDENCE}">The 16 findings, rechecked</a><a href="{FINDINGS_URL}#f-085">The 269, checked live</a></p></div>
<div class="vs" role="img" aria-label="Findings on the same project: Dependabot alerts 0, OSV-Scanner 0, Limbowatch 16">
<div><span>GitHub Dependabot alerts</span><b class="zero">0</b></div>
<div><span>OSV-Scanner 2.7.0</span><b class="zero">0</b></div>
<div class="lw"><span>Limbowatch</span><b>16</b><i style="width:100%"></i></div></div></section>
<section class="wrap s"><div class="two"><div><h2 class="sm">Every ecosystem GitHub reviews</h2>
<p class="sub">Advisories in limbo by package ecosystem, and how long they’ve waited so far.</p>{eco_table(pend, now)}</div>
<div><h2 class="sm">Most have no CVE to fall back on</h2>
<p class="sub">Scanners that start from CVEs can’t fill the gap either.</p>{cve_split(m)}</div></div></section>
<section class="wrap s"><h2>In limbo now</h2><p class="sub">Facts only. Each advisory’s full text stays on GitHub.</p>
<div class="cols">{lst("Newly published", fresh)}{lst("Longest waiting, published this past year", oldest)}</div></section>
<section class="wrap s"><h2>What to do about it</h2><div class="paths">
<div><h3>If you run security for a team</h3><p>Check your lockfiles in CI against everything in limbo. Findings show up in
merge requests, pull requests and issues, on GitLab, GitHub, Gitea and Forgejo.</p>
<p class="links"><a href="/scan/">Set up the scan</a><a href="/feed/critical.atom">Subscribe to new critical and high</a>
<a href="/feed/">Download the OSV feed</a></p></div>
<div><h3>If you maintain a project</h3><p>Request a CVE when you publish, and fill in both the affected range and the fixed
version, so scanners can match your advisory the day it’s reviewed.</p>
<p class="links"><a href="/quality/">Advisories scanners can’t match</a><a href="/methodology/#maintainers">What helps</a></p></div>
<div><h3>If you’re writing about it</h3><p>Live numbers you can cite, charts you can reuse, the method behind every
number, and a person to talk to.</p>
<p class="links"><a href="/press/">Press and research</a><a href="/why/">The story behind it</a></p></div></div></section>
</main>
{footer()}{SEARCH_JS}"""
    return page(
        "limbo.watch: security advisories your scanner can’t see yet",
        f"{li['count']:,} published security advisories are waiting for GitHub review, invisible to Dependabot, npm audit "
        "and OSV-Scanner. Live tracker, open feed and CI scan.",
        body,
        "/",
        dataset_ld(m),
    )


# --- tracker ----------------------------------------------------------------------------------------


def tracker_data(items: list[Item], events: list[dict[str, Any]], now: datetime) -> dict[str, Any]:
    by_id = {i.adv.ghsa_id: i for i in items}
    left: dict[str, dict[str, Any]] = {}
    for e in sorted(events, key=lambda e: e["at"]):
        if not e["event"].startswith("in limbo -> "):
            continue
        at = datetime.fromisoformat(e["at"].replace("Z", "+00:00"))
        i = by_id.get(e["ghsa_id"])
        if i is None or now - at > LEFT_WINDOW or i.assessment.status is Status.LIMBO:
            continue
        r = row(i, now)
        r.update(to=LEFT_TEXT.get(e["event"].removeprefix("in limbo -> "), e["event"]), at=e["at"][:10])
        r["age"] = None if i.adv.published_at is None else round((at - i.adv.published_at).total_seconds() / 86400, 1)
        left[i.adv.ghsa_id] = r
    return {
        "generated_at": now.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "pending": [row(i, now) for i in pending(items)],
        "permanent": [row(i, now) for i in permanent(items)],
        "left": list(left.values()),
    }


def tracker(m: dict[str, Any], data: dict[str, Any]) -> str:
    li, sev = m["in_limbo"], m["in_limbo"]["by_severity"]
    updated = stamp(m["generated_at"])
    legend = "".join(
        f'<div class="card"><p class="t"><span class="cd {k}" aria-hidden="true"></span>{E(CVE_TEXT[k])}</p><p class="d">{d}</p></div>'
        for k, d in [
            ("none", "No CVE ID on the advisory, and no record in the CVE List refers to it. Neither GitHub-based nor CVE-based tools know it exists."),
            ("rbp", "The advisory cites a CVE ID whose record isn’t published. Looking the ID up returns nothing."),
            ("pub", "CVE-based tools can find it. GitHub- and OSV-based scanners still can’t, until GitHub reviews it."),
            ("cna", "Another CNA, usually VulnCheck, published a CVE pointing to the advisory, which doesn’t cite it."),
        ]
    )  # fmt: skip
    cve_opts = "".join(f'<option value="{k}">{E(v)}</option>' for k, v in CVE_TEXT.items() if k != "other")
    body = f"""<header class="top">{header("tracker")}</header>
<main class="wrap">
<div class="head"><div><p class="eyebrow">Updated {E(updated)}</p>
<h1 class="page"><b>{li["count"]:,}</b> advisories in limbo</h1>
<p class="sub" style="max-width:640px">Published by maintainers on GitHub, in ecosystems GitHub reviews, but not yet in GitHub’s
reviewed database or OSV.</p></div>
<dl class="sevs"><div><dt>Critical</dt><dd>{sev["critical"]:,}</dd></div><div><dt>High</dt><dd>{sev["high"]:,}</dd></div>
<div><dt>Medium</dt><dd>{sev["medium"]:,}</dd></div><div><dt>Low</dt><dd>{sev["low"]:,}</dd></div></dl></div>
<div class="tabs" role="tablist" aria-label="Which advisories">
<button role="tab" aria-selected="true" data-tab="pending">Pending<span class="lg"> review</span> <span class="n">{len(data["pending"]):,}</span></button>
<button role="tab" aria-selected="false" data-tab="permanent"><span class="lg">Likely permanent</span><span class="sm">Permanent</span> <span class="n">{len(data["permanent"]):,}</span></button>
<button role="tab" aria-selected="false" data-tab="left">Left limbo<span class="lg">, last 30 days</span> <span class="n">{len(data["left"]):,}</span></button></div>
<form class="filters" role="search" id="filters">
<label class="q">Package, repository or ID<input id="q" type="search" placeholder="e.g. sanitize-html, GHSA-…, CVE-2026-…" autocomplete="off"></label>
<button type="button" class="ftoggle" id="ftoggle" aria-expanded="false">Filters</button>
<label>Ecosystem<select id="eco"><option value="">All</option></select></label>
<label>Severity<select id="sev"><option value="">All</option><option value="critical">Critical</option><option value="high+">High or above</option>
<option value="medium+">Medium or above</option><option value="low">Low</option></select></label>
<label>CVE state<select id="cve"><option value="">All</option>{cve_opts}</select></label>
<label>Published<select id="pub"><option value="">Any time</option><option value="30">Last 30 days</option><option value="90">Last 90 days</option>
<option value="365">Last year</option></select></label>
<label>Sort<select id="sort"><option value="new">Newest</option><option value="sev">Severity, then wait</option><option value="old">Waiting longest</option></select></label>
</form>
<div class="tbl"><table><thead><tr><th scope="col">Package</th><th scope="col">Advisory</th><th scope="col">Severity</th>
<th scope="col" id="h-cve">CVE</th><th scope="col" id="h-wait">Waiting</th><th scope="col">Fixed in</th></tr></thead>
<tbody id="rows"><tr><td colspan="6" class="muted">Loading…</td></tr></tbody></table></div>
<div class="pager"><span id="shown"></span><span class="b"><button id="prev" type="button">Previous</button>
<button id="next" type="button">Next</button><a class="btn solid" href="/feed/">Download as OSV</a></span></div>
<p class="muted" style="font-size:14px;margin-top:8px">Ranges and fixed versions are as entered by maintainers and haven’t been reviewed.</p>
<section style="margin-top:72px"><h2 class="sm">What the CVE states mean</h2><div class="legend">{legend}</div></section>
</main>
{footer(f"Watchlist {m['coverage']['watchlist_repos']:,} repositories, {m['coverage']['on_schedule']:,} up to date on their schedule. Every number is a floor. ")}
<script type="application/json" id="cve-text">{json.dumps(CVE_TEXT)}</script>
<script src="/assets/tracker.js" defer></script>"""
    return page(
        "Tracker · limbo.watch",
        f"{li['count']:,} security advisories published on GitHub and waiting for review: filter by package, ecosystem, severity and CVE state.",
        body,
        "/tracker/",
    )


# --- advisory pages ---------------------------------------------------------------------------------


def advisory(i: Item, events: list[dict[str, Any]], now: datetime) -> str:
    a, f, s = i.adv, i.facts, i.assessment
    age = days_since(a.published_at, now)
    perm = s.likely_permanent
    pill = "Likely permanent: GitHub doesn’t review this ecosystem" if perm else f"In limbo for {fmt_days(age)}"
    pkgs = [p for p in a.packages if package_name(p.ecosystem, p.name)]
    first = pkgs[0] if pkgs else None
    first_name = _name(first).name if first else ""
    sub = (
        f"<strong>{E(first_name)}</strong> on {E(eco_label(first.ecosystem))} · published in "
        f'<a href="https://github.com/{E(a.repo)}">{E(a.repo)}</a>'
        if first
        else f'Published in <a href="https://github.com/{E(a.repo)}">{E(a.repo)}</a>'
    )
    facts: list[tuple[str, str]] = []
    sev = E((a.severity or "unknown").capitalize())
    if a.cvss_score is not None:
        sev += f" · CVSS score {a.cvss_score}"
    vec = a.cvss_v4_vector or a.cvss_v3_vector
    facts.append(("Severity", sev + (f'<small class="mono">{E(vec)}</small>' if vec else "")))
    for p in pkgs or a.packages:
        pn = _name(p)
        name = f" ({E(pn.name)})" if len(pkgs) > 1 and pn.name else ""
        if pn.raw and (pn.cleaned or not pn.valid):
            note = (
                "Cleaned up for matching."
                if pn.valid
                else f"Doesn’t look like a valid {E(eco_label(p.ecosystem))} package name, so scanners can’t match it. "
                f'<a href="/quality/#{E(quality_anchor(a.repo))}">How to fix it</a>'
            )
            facts.append(
                (f"Package name{name}", f'<span class="mono">{E(pn.raw)}</span><small>As entered. {note}</small>')
            )
        facts.append(
            (
                f"Affected versions{name}",
                f'<span class="mono">{E(p.vulnerable_version_range or "not stated")}</span>'
                "<small>As entered by the maintainer. Not reviewed."
                + (
                    " Scanners can’t read this range. "
                    f'<a href="/quality/#{E(quality_anchor(a.repo))}">How to fix it</a>'
                    if pn.name and osv_ranges(p.ecosystem, p.vulnerable_version_range, p.patched_versions) is None
                    else ""
                )
                + "</small>",
            )
        )
        facts.append((f"Fixed in{name}", f'<span class="mono">{E(p.patched_versions or "not stated")}</span>'))
    if f.cited_cve:
        state = {"RESERVED": "reserved, record not published", "PUBLISHED": "published", "REJECTED": "rejected"}.get(
            f.cited_cve_state or "", (f.cited_cve_state or "state unknown").lower()
        )
        note = (
            "<small>The ID is public but empty: looking it up returns nothing. The CVE Program expects publication within 72 hours.</small>"
            if f.cited_cve_state == "RESERVED"
            else ""
        )
        facts.append(("CVE", f'<span class="mono">{E(f.cited_cve)}</span> · <strong>{E(state)}</strong>{note}'))
    else:
        facts.append(("CVE", "None cited by the advisory"))
    facts.append(("GitHub Advisory Database", "Not reviewed" if not f.reviewed else "Reviewed"))
    facts.append(("OSV.dev", "Not present" if f.in_osv is False else "Present" if f.in_osv else "Not checked"))
    facts.append(
        (
            "Other CVEs pointing here",
            ", ".join(f'<span class="mono">{E(c)}</span>' for c in f.uncited_cves) + " (published by another CNA)"
            if f.uncited_cves
            else "None found in the CVE List",
        )
    )
    if f.nvd_status:
        facts.append(("NVD", E(f.nvd_status)))
    facts_html = "".join(f"<div><dt>{k}</dt><dd>{v}</dd></div>" for k, v in facts)

    steps: list[tuple[str, str, str, str]] = []  # (kind, when, heading, detail)
    if a.published_at:
        steps.append(("done", a.published_at.strftime("%Y-%m-%d %H:%M UTC"), "Published by the maintainers",
                      f"Cites {E(f.cited_cve)}" if f.cited_cve else "No CVE cited"))  # fmt: skip
    for e in sorted(events, key=lambda e: e["at"]):
        if e["event"] != "first seen":
            steps.append(("done", stamp(e["at"]), "Change recorded", E(e["event"])))
    seen = stamp(i.first_seen)
    state_bits = [
        "CVE still reserved" if f.cited_cve_state == "RESERVED" else "",
        "not reviewed" if not f.reviewed else "",
        "not in OSV" if f.in_osv is False else "",
    ]
    steps.append(("now", seen, "First seen by Limbowatch", " · ".join(b for b in state_bits if b)))
    if f.cited_cve_state == "RESERVED":
        steps.append(("todo", "Waiting", "CVE record published", ""))
    if perm:
        steps.append(("todo", "Not expected", "Reviewed by GitHub", "GitHub doesn’t review this ecosystem"))
    else:
        steps.append(("todo", "Waiting", "Reviewed by GitHub", ""))
        steps.append(("todo", "Waiting", "In OSV; scanners can see it", ""))
    lis = []
    for n, (kind, when, head, detail) in enumerate(steps):
        last = n == len(steps) - 1
        dot = {"done": "<b></b>", "now": '<b class="o"></b>', "todo": '<b class="p"></b>'}[kind]
        line = "" if last else ('<i class="p"></i>' if kind == "todo" or steps[n + 1][0] == "todo" else "<i></i>")
        pad = ' style="padding-bottom:0"' if last else ""
        lis.append(
            f'<li><div class="rail" aria-hidden="true">{dot}{line}</div><div class="step"{pad}>'
            f'<p class="w">{E(when)}</p><p class="h{" p" if kind == "todo" else ""}">{E(head)}</p>'
            + (f'<p class="d">{detail}</p>' if detail else "")
            + "</div></li>"
        )
    raw_fix = (first.patched_versions or "").strip() if first else ""
    fix = fixed_versions(raw_fix)
    if first and fix and len(fix) == 1:
        advice = f"Upgrade to {E(fix[0])} or later."
    elif first and fix:
        advice = f"Upgrade to the fixed version for your release line: {E(', '.join(fix))}."
    elif first and not no_fix(raw_fix):
        advice = f"The fixed-version field says “{E(raw_fix)}”. Check the advisory for which version fixes it."
    elif first:
        advice = "No fixed version is listed yet. Check the advisory for workarounds."
    else:
        advice = "The advisory doesn’t name a package. Check it for the affected component."
    scanners = "probably never will" if perm else "won’t flag this yet"
    who = f"If you use {E(first_name)} {E(first.vulnerable_version_range or '')}" if first else "If you’re affected"
    body = f"""<header class="top">{header("tracker")}</header>
<main class="wrap">
<nav class="crumb" aria-label="Breadcrumb"><a href="/tracker/">Tracker</a>{f" / {E(eco_label(first.ecosystem))} / {E(first_name)}" if first else ""}</nav>
<div class="adv-head"><div style="min-width:0"><p class="pill"><i aria-hidden="true"></i>{E(pill)}</p>
<h1 class="ghsa">{E(a.ghsa_id)}</h1><p class="sub">{sub}</p></div>
<a class="btn solid" style="min-height:48px" href="{E(a.html_url)}">Read the advisory on GitHub ↗</a></div>
<div class="adv-body">
<section style="flex:3 1 560px"><h2 class="xs">Facts</h2><dl class="facts card">{facts_html}</dl>
<div class="advice"><h2>{who.strip()}</h2><p>{advice} Dependabot, npm audit and OSV-Scanner {scanners}.</p></div></section>
<section style="flex:2 1 340px"><h2 class="xs">Timeline</h2><ol class="steps">{"".join(lis)}</ol>
<p class="muted" style="margin-top:24px;font-size:13px">Machine-readable record:
<a class="mono" href="/feed/{E(a.ghsa_id)}.json">feed/{E(a.ghsa_id)}.json</a></p></section>
</div></main>
{footer("We show facts only; the advisory’s title, description and credits are on GitHub. ")}"""
    name = first_name or a.repo
    return page(
        f"{a.ghsa_id} ({name}) · limbo.watch",
        f"{a.ghsa_id} for {name}: published on GitHub {fmt_days(age)} ago and not yet visible to scanners that read GitHub’s Advisory Database.",
        body,
        f"/advisory/{a.ghsa_id}/",
    )


# --- feed -------------------------------------------------------------------------------------------


def feed(m: dict[str, Any], sample: dict[str, Any] | None) -> str:
    li = m["in_limbo"]
    total = li["count"] + m["likely_permanent"]["count"]
    sample_html = E(json.dumps(sample, indent=2, ensure_ascii=False)) if sample else "No records yet."
    sample_id = E(sample["id"]) if sample else "GHSA-…"
    body = f"""<header class="top">{header("feed")}</header>
<main class="wrap">
<div style="padding-top:48px"><p class="eyebrow">OSV schema 1.6 · rebuilt daily · CC BY 4.0</p>
<h1 class="page">The limbo feed</h1>
<p class="sub" style="max-width:680px;font-size:18px">Every advisory in limbo ({total:,} today) as an OSV record, in the same
layout as OSV’s own bulk downloads. Use it to see what your scanner can’t yet.</p></div>
<div class="adv-body" style="margin-top:48px">
<section style="flex:3 1 560px"><h2 class="xs">Files</h2><div class="card files">
<div><div class="x"><a class="mono" href="/feed/all.zip">feed/all.zip</a><p>One <span class="mono">GHSA-….json</span> per advisory
in limbo, OSV bulk layout. Byte-stable, so you can diff it.</p></div><a class="btn solid" href="/feed/all.zip">Download</a></div>
<div><div class="x"><a class="mono" href="/osv/limbo-db.zip">osv/limbo-db.zip</a><p>The feed split by ecosystem, laid out
as OSV-Scanner’s offline database. Unzip it and scan.</p></div><a class="btn" href="/osv/limbo-db.zip">Download</a></div>
<div><div class="x"><a class="mono" href="/osv/ecosystems.txt">osv/&lt;Ecosystem&gt;/all.zip</a><p>One zip per OSV ecosystem, the
way OSV serves its own, with the <span class="mono">X-Goog-Hash</span> checksum it sends.</p></div></div>
<div><div class="x"><a class="mono" href="/feed/repos.txt">feed/repos.txt</a><p>Every watched repo with a published
advisory, one per line. Names only, for trackers that poll repos.</p></div></div>
<div><div class="x"><a class="mono" href="/feed/index.json">feed/index.json</a><p>Every ID in the feed, to fetch only what changed.</p></div></div>
<div><div class="x"><a class="mono" href="/feed/{sample_id}.json">feed/&lt;GHSA-ID&gt;.json</a><p>A single record, linked from each advisory page.</p></div></div>
<div><div class="x"><a class="mono" href="/metrics.json">metrics.json</a><p>Today’s counts by severity, CVE state and age, plus coverage.</p></div></div>
</div>
<h2 class="xs" style="margin-top:48px">Use it</h2><ol class="steps" style="display:flex;flex-direction:column;gap:20px">
<li><span class="num">1</span><div style="flex:1;min-width:0"><p style="margin:2px 0 10px;font-weight:600">Download and unpack the feed</p>
<pre>curl -O https://limbo.watch/feed/all.zip
unzip -q all.zip -d limbo</pre></div></li>
<li><span class="num">2</span><div style="flex:1;min-width:0"><p style="margin:2px 0 10px;font-weight:600">Look for your packages</p>
<pre>jq -r 'select(.affected[].package.name == "sanitize-html") | .id' limbo/*.json</pre></div></li>
<li><span class="num">3</span><div style="flex:1;min-width:0"><p style="margin:2px 0 10px;font-weight:600">Or scan with OSV-Scanner</p>
<pre>curl -O https://limbo.watch/osv/limbo-db.zip
unzip -q limbo-db.zip -d limbo-db
osv-scanner scan source --offline-vulnerabilities \\
  --local-db-path limbo-db -r .</pre>
<p class="ink2" style="margin:10px 0 0;font-size:15px">This checks your dependencies against the limbo feed only, so run it
next to your usual scan: everything it finds is something OSV doesn’t have yet. Tested with OSV-Scanner 2.7.0, which skips npm
lockfile entries that have no <span class="mono">resolved</span> field
(<a href="https://github.com/google/osv-scanner/issues/3177">#3177</a>).
We’re proposing upstream that OSV-Scanner add the feed to a normal scan, rather than building another scanner.</p></div></li></ol></section>
<section style="flex:2 1 380px"><h2 class="xs">One record</h2><pre class="light">{sample_html}</pre>
<div class="note"><h3>What’s in it, and what isn’t</h3><ul>
<li>Facts only: IDs, packages, ranges, severity, CVE state. No titles, descriptions or credits; each record links to the advisory.</li>
<li>Ranges are as entered by maintainers and haven’t been reviewed. Expect some to be wrong. Where one can’t be
converted exactly, it’s left out of <span class="mono">ranges</span> and kept as text, so it can’t raise a false alarm.</li>
<li>Package names are cleaned where the fix is certain: stray spaces and URLs removed, PyPI and Packagist names in their
canonical spelling. The original is kept in <span class="mono">name_as_entered</span>; names that still aren’t valid
have <span class="mono">name_valid: false</span>. Each record’s <span class="mono">quality</span> field sums this up, and
<a href="/quality/">this page</a> lists every one with its fix.</li>
<li>An advisory leaves the feed when GitHub reviews it, so OSV takes over.</li>
<li>Licensed CC BY 4.0. Credit “Limbowatch (limbo.watch)” and GitHub, as each record’s <span class="mono">attribution</span> field says.</li>
</ul></div></section></div></main>
{footer()}"""
    return page(
        "The limbo feed · limbo.watch",
        "Every security advisory in limbo as OSV-schema records, rebuilt daily.",
        body,
        "/feed/",
    )


# --- scan: the watcher -----------------------------------------------------------------------------


def scan(m: dict[str, Any]) -> str:
    li = m["in_limbo"]
    body = f"""<header class="top">{header("scan")}</header>
<main class="wrap">
<div style="padding-top:48px"><p class="eyebrow">The Limbowatch watcher · open source · GitLab, GitHub, Gitea, Forgejo</p>
<h1 class="page">Find what your scanner can’t see yet.</h1>
<p class="sub" style="max-width:720px;font-size:18px"><span class="mono">limbowatch scan</span> checks your lockfiles against
all {li["count"]:,} advisories in limbo, the ones Dependabot, npm audit and OSV-Scanner don’t report yet, and shows what it
finds where your team already looks: the merge request, the pull request, the issue tracker.</p></div>

<section class="s" style="padding-top:40px"><h2>What it finds</h2><div class="facts3">
<div><div class="n">269</div><p>affected package-versions in <strong>13 of 14</strong> popular projects, GitLab alone 125, that
scanners reading GitHub’s database or OSV report as clean. Checked live: 630 of 657 findings in the advisory’s current
range, 12 possible, <strong>none contradicted</strong>.</p></div>
<div><div class="n">16 vs 0</div><p>on a demo app with real npm, Go, pip and Bundler lockfiles: Limbowatch found 16 advisories
in limbo in six packages (undici, rack, nokogiri, pgx, chi, dnspython). OSV-Scanner and GitHub’s Dependabot alerts
reported <strong>none of them</strong>.</p></div>
<div><div class="n">51</div><p>new findings flagged when a change adds one affected package: in GitLab’s merge request
widget, and on GitHub inline on the changed lockfile line.</p></div></div>
<p class="sub">Measured 2026-11-05 to 2026-11-07 against the live feed; every advisory checked against GitHub and OSV.
<a href="{EVIDENCE}">All 16 findings, rechecked →</a> · <a href="{DEMO_PR}">The pull request →</a></p></section>

<section class="s"><h2>Where findings show up</h2><div class="cards3">
<div class="card"><h3>GitLab merge requests</h3><p>A CI/CD component writes a Code Quality report, which works on every GitLab
tier: “Code Quality scans found 51 new findings”. Optionally, one confidential issue per finding, updated when a CVE is
assigned and closed when you upgrade.</p></div>
<div class="card"><h3>GitHub pull requests</h3><p>The action writes SARIF, so findings become code scanning alerts, annotated on
the lockfile line a pull request changes, and a table in the job summary.</p></div>
<div class="card"><h3>Gitea and Forgejo</h3><p>The same action runs on Gitea and Forgejo Actions, and keeps one issue per
finding up to date. It won’t open issues in a public repo unless you allow it.</p></div></div></section>

<section class="s"><h2>Use it</h2><ol class="steps" style="display:flex;flex-direction:column;gap:20px;max-width:860px">
<li><span class="num">1</span><div style="flex:1;min-width:0"><p style="margin:2px 0 10px;font-weight:600">GitLab CI</p>
<pre>include:
  - component: $CI_SERVER_FQDN/limbowatch/limbowatch-component/limbowatch@0.1.0
    inputs:
      fail_on: high</pre></div></li>
<li><span class="num">2</span><div style="flex:1;min-width:0"><p style="margin:2px 0 10px;font-weight:600">GitHub, Gitea or Forgejo Actions</p>
<pre>- uses: actions/checkout@v4
- uses: limbowatch/limbowatch/integrations/action@v0.1.0
  with:
    fail-on: high
    sarif: limbowatch.sarif</pre></div></li>
<li><span class="num">3</span><div style="flex:1;min-width:0"><p style="margin:2px 0 10px;font-weight:600">On your machine</p>
<pre>pipx install limbowatch-cli      # needs OSV-Scanner 2.7.0
limbowatch scan .</pre>
<p class="ink2" style="margin:10px 0 10px;font-size:15px">Version 0.1.0 is being released. Until it’s on PyPI and in
the GitLab CI/CD Catalog, install from GitHub:</p>
<pre>uv tool install "limbowatch-cli @ git+{REPO_URL}#subdirectory=packages/cli" \\
  --with "limbowatch @ git+{REPO_URL}#subdirectory=packages/core"</pre>
<p class="ink2" style="margin:10px 0 0;font-size:15px"><a href="{WATCHER_DOC}">Full guide →</a></p></div></li></ol></section>

<section class="s"><div class="note" style="max-width:860px"><h3>What it does, and what it doesn’t</h3><ul>
<li>Reads lockfiles with OSV-Scanner, offline. The feed is downloaded whole, so limbo.watch learns nothing about your project.</li>
<li>Never drops a dependency. A range-only requirement, a git install or an unreadable lockfile is listed with the reason.</li>
<li>It’s a head start. Most of these advisories are reviewed eventually, after weeks; then your usual scanner reports them and
Limbowatch notes that they’re visible. In ecosystems GitHub doesn’t review, the wait may never end.</li>
<li>Ranges are as entered by maintainers and haven’t been reviewed. A range that contradicts its own fix is reported as
possible, never silently passed.</li>
<li>Large projects need a read-only GitHub token, to check the upstream repos the tracker doesn’t watch.</li>
</ul></div></section></main>
{footer()}"""
    return page(
        "Scan your project · limbo.watch",
        "Check your dependencies against security advisories your scanner can’t see yet, in GitLab, GitHub, Gitea or Forgejo CI.",
        body,
        "/scan/",
    )


# --- data quality --------------------------------------------------------------------------------


QUALITY_IDS = 8  # advisory links shown per row


def quality_anchor(repo: str) -> str:
    return "r-" + re.sub(r"[^a-z0-9._-]+", "-", repo.lower())


def _visible(raw: str) -> str:
    """Escape, showing leading and trailing whitespace, which is often the whole problem."""
    core = raw.strip()
    if not core:
        return E(raw)
    i = raw.index(core)
    lead, trail = raw[:i], raw[i + len(core) :]
    return "␣" * len(lead) + E(core) + "␣" * len(trail)


def _ticks(text: str) -> str:
    """Escape, then show `code` spans in the mono face."""
    return re.sub(r"`([^`]+)`", r'<span class="mono">\1</span>', E(text))


def quality(items: list[Item]) -> str:
    """Advisory fields scanners can't use, grouped by repo, with the edit that fixes each (F-069)."""
    probs = problems(items)
    by_repo: dict[str, list[Problem]] = defaultdict(list)
    for pr in probs:
        by_repo[pr.repo].append(pr)
    repos = sorted(by_repo, key=lambda r: (-len({p.ghsa_id for p in by_repo[r]}), r))
    names_bad = sum(1 for p in probs if p.field == NAME and not p.certain)
    names_fix = sum(1 for p in probs if p.field == NAME and p.certain)
    ranges = sum(1 for p in probs if p.field != NAME)
    sections = []
    for r in repos:
        # Advisories in one repo often share the same mistake: one row per distinct problem.
        same: dict[tuple[str, str, str, str, str], list[str]] = defaultdict(list)
        for p in sorted(by_repo[r], key=lambda p: p.ghsa_id):
            same[(p.ecosystem, p.field, p.as_entered, p.issue, p.fix)].append(p.ghsa_id)
        rows = ""
        for (eco, fld, was, issue, fix), ids in sorted(same.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            links = ", ".join(f'<a class="mono" href="/advisory/{E(g)}/">{E(g)}</a>' for g in ids[:QUALITY_IDS])
            more = f" and {len(ids) - QUALITY_IDS:,} more" if len(ids) > QUALITY_IDS else ""
            rows += (
                f'<div class="qrow"><div class="qh">{E(eco)} · {E(fld)} · {len(ids):,} advisor'
                f"{'y' if len(ids) == 1 else 'ies'}: {links}{more}</div>"
                f'<p><span class="mono was">{_visible(was) or "(empty)"}</span></p>'
                f"<p>{_ticks(issue)}. <strong>{_ticks(fix)}</strong></p></div>"
            )
        n = len({p.ghsa_id for p in by_repo[r]})
        sections.append(
            f'<section class="qrepo" id="{E(quality_anchor(r))}"><h3><a href="https://github.com/{E(r)}/security/advisories">'
            f'{E(r)}</a><small>{n:,} advisor{"y" if n == 1 else "ies"}</small></h3><div class="card">{rows}</div></section>'
        )
    body = f"""<header class="top">{header("")}</header>
<main class="wrap">
<div style="padding-top:48px"><p class="eyebrow">Data quality · rebuilt daily</p>
<h1 class="page">Advisories scanners can’t match</h1>
<p class="sub" style="max-width:720px;font-size:18px">Scanners compare package names exactly and skip version ranges they can’t
read. These advisories in limbo have a field like that, so they’ll stay invisible to scanners until the field is
fixed, even after GitHub reviews them. If you maintain one of these repos, you can edit a published advisory on GitHub.</p></div>
<div class="facts3"><div><div class="n">{len({p.ghsa_id for p in probs}):,}</div><p>advisories in <strong>{len(repos):,} repos</strong>
with at least one field scanners can’t use.</p></div>
<div><div class="n">{names_bad + names_fix:,}</div><p>package names: <strong>{names_fix:,}</strong> with an exact fix (case, spaces, a URL
around the name), <strong>{names_bad:,}</strong> that don’t fit the ecosystem’s naming rules.</p></div>
<div><div class="n">{ranges:,}</div><p>version ranges scanners can’t read, or that would mark the fixed version as affected.</p></div></div>
<div class="note" style="margin-top:32px;max-width:760px"><h3>How to read this</h3><ul>
<li>Repos with the most affected advisories come first. Search the page for yours.</li>
<li>Each row shows the field as entered and why it fails. Fixes for names in the wrong spelling are exact; the rest
are suggestions, because only the maintainer knows the right package and release lines.</li>
<li>The limbo feed already uses the corrected spelling where it’s certain, so <a href="/feed/">feed</a> users are
covered. Scanners that read GitHub’s database only get it when the advisory itself is fixed.</li>
<li>The name rules check the form, not that the package exists.</li></ul></div>
{"".join(sections)}
</main>
{footer()}"""
    return page(
        "Advisories scanners can’t match · limbo.watch",
        "Published security advisories whose package name or version range scanners can’t use, with the fix for each.",
        body,
        "/quality/",
    )


STORY_ADVISORY = "https://github.com/NationalSecurityAgency/skills-service/security/advisories/GHSA-hqfg-c8wf-w2g8"


def why(m: dict[str, Any]) -> str:
    """The story behind the project: one advisory, followed through every database (FINDINGS F-066)."""
    li = m["in_limbo"]
    steps = [
        ("16 Jun 2026", "The advisory is published. GitHub reserved CVE-2026-54694 for it the day before."),
        ("26 Jun", "The CVE is still only reserved. I ask GitHub to check whether something went wrong."),
        ("30 Jun", "GitHub replies: a record backlog of CVE requests, about three weeks to clear, no expediting. "
                   "Dependabot alerts come from the advisory, not the CVE."),
        ("11 Aug", "I follow up. GitHub is still publishing CVEs for advisories from May."),
        ("9 Sep", "After my third follow-up, the CVE is published: 85 days after the advisory."),
        ("28 Oct", "The advisory is still not in GitHub’s Advisory Database or in OSV."),
    ]  # fmt: skip
    tl = "".join(
        f"<li{' class="now"' if n == len(steps) - 1 else ''}><time>{E(d)}</time><span>{E(t)}</span></li>"
        for n, (d, t) in enumerate(steps)
    )
    body = f"""<header class="top">{header("why")}</header>
<main class="wrap"><article class="story">
<p class="eyebrow">The story behind limbo.watch</p>
<h1 class="page">Why I built Limbowatch</h1>
<p style="margin-top:32px">On 16 June 2026, the maintainers of <span class="mono">NationalSecurityAgency/skills-service</span>
published <a href="{STORY_ADVISORY}">a security advisory</a> for a vulnerability I had reported: a stored XSS, reachable through
user registration, that lets an attacker take over an admin account. GitHub rated it <strong>critical</strong>, and the fix
shipped in 4.4.2.</p>
<p>I assumed the rest would take care of itself. The CVE would go public, scanners would pick it up, and anyone running 4.4.1
or earlier would be told to upgrade. That isn’t what happened.</p>
<ol class="story-tl">{tl}</ol>
<p>The reassurance in that June reply is true of how GitHub works, but it didn’t apply here. Dependabot only alerts on
advisories GitHub has reviewed into its Advisory Database, and this one was never going to be reviewed: it affects a release
<span class="mono">.jar</span> and a Docker image, not a package from an ecosystem GitHub supports. Scanners that start from
the CVE had nothing to find either, because for 85 days the CVE was only a reserved ID. Even now OSV’s copy of the record
lists git commits but no package, and NVD has deferred it.</p>
<p><strong>A critical vulnerability, fixed and publicly documented, has been invisible for more than four months
to every scanner that reads GitHub’s database, OSV or NVD.</strong> The people involved were doing their jobs. The review queue is simply far longer than the tools downstream
assume.</p>
<p>I wanted to know whether my advisory was unusual. It isn’t. In October I measured the upstream advisories of fifteen popular
projects: about 1 in 6 was in limbo, and the median wait for review was 23 days. Today limbo.watch counts
<strong>{li["count"]:,} advisories waiting for review</strong>, with a median wait of {fmt_days(li["age_days_median"])},
and that’s a floor: it only sees the repositories it watches.</p>
<p>Limbowatch makes that wait visible. It lists what’s waiting, publishes it in the format scanners already read, and will help
maintainers and reviewers get advisories through faster. If you maintain a project, request a CVE when you publish and fill in
both the affected range and the fixed version. If you run a scanner, <a href="/feed/">the feed is open</a>.</p>
<p class="sig">Yujia Lin, creator of Limbowatch</p>
</article></main>
{footer()}"""
    return page(
        "Why I built Limbowatch · limbo.watch",
        "One critical advisory, 85 days waiting for its CVE and still invisible to scanners: the story behind limbo.watch.",
        body,
        "/why/",
    )


# --- press and methodology --------------------------------------------------------------------------


def notable(items: list[Item], now: datetime, n: int = 6) -> list[Item]:
    """Critical advisories with a fixed version, published this past year, waiting longest: the clearest cases."""
    rows = [
        i
        for i in pending(items)
        if (i.adv.severity or "").lower() == "critical"
        and any(fixed_versions(p.patched_versions or "") for p in i.adv.packages)
        and (days_since(i.adv.published_at, now) or 0) <= 365
    ]
    return sorted(rows, key=lambda i: i.adv.published_at or now)[:n]


def press(items: list[Item], m: dict[str, Any], now: datetime) -> str:
    li, perm, flow = m["in_limbo"], m["likely_permanent"], m.get("flow_7d") or {}
    sev = li["by_severity"]
    date = now.strftime("%-d %B %Y")
    pend = pending(items)
    ages = [a for i in pend if (a := days_since(i.adv.published_at, now)) is not None]
    cols, undated = queue_cols(pend, now)
    facts = [
        (f"On {date}, <strong>{li['count']:,}</strong> security advisories published by maintainers on GitHub were waiting "
         f"for GitHub’s review, invisible to scanners that read GitHub’s Advisory Database or OSV. "
         f"{sev['critical'] + sev['high']:,} are rated critical or high.", "/tracker/", "Live tracker"),
        (f"In the {flow.get('days', 7)} days to {date}, maintainers published <strong>{flow.get('published', 0):,}</strong> "
         f"new advisories in the repositories we watch. GitHub reviewed <strong>{flow.get('reviewed', 0):,}</strong> of "
         "the ones waiting.", "/methodology/#flow", "How the weekly flow is counted"),
        (f"The advisories in limbo have waited a median of <strong>{fmt_days(li['age_days_median'])}</strong> so far. "
         f"{sum(1 for x in ages if x > 90):,} have waited more than 3 months, and {sum(1 for x in ages if x > 365):,} more "
         "than a year.", "/methodology/#wait", "How waits are measured"),
        (f"<strong>{li['by_cve'].get(CveLabel.NONE.value, 0):,}</strong> of them have no CVE at all, so scanners that "
         "start from CVEs can’t see them either.", "/tracker/", "CVE states in the tracker"),
        (f"Another <strong>{perm['count']:,}</strong> published advisories are in ecosystems GitHub doesn’t review, such as "
         "C/C++ and container images. Scanners that read GitHub’s database will probably never see them.",
         "/methodology/#permanent", "What “likely permanent” means"),
        ("In October 2026, <strong>1 in 6</strong> upstream advisories behind 15 popular open-source projects was in "
         "limbo, and the median wait for GitHub’s review was 23 days.", REPORT_URL, "State of the Gap, October 2026"),
        ("On a demo app with real lockfiles, Limbowatch found <strong>16</strong> advisories in limbo that GitHub’s "
         "Dependabot alerts and OSV-Scanner did not report (7 November 2026). Each was rechecked against GitHub and OSV.",
         EVIDENCE, "The evidence"),
    ]  # fmt: skip
    facts_html = "".join(f'<li><p>{t}</p><a href="{E(u)}">{E(lbl)}</a></li>' for t, u, lbl in facts)
    examples = "".join(
        f'<tr><td><a href="/advisory/{E(i.adv.ghsa_id)}/"><strong>{E(pkg_names(i))}</strong></a><small>{E(eco_names(i))}</small></td>'
        f'<td class="mono"><a href="{E(i.adv.html_url)}">{E(i.adv.ghsa_id)}</a></td><td class="mono">{E(fixes(i)[:40])}</td>'
        f'<td class="n">{fmt_days(days_since(i.adv.published_at, now))}</td></tr>'
        for i in notable(items, now)
    )
    cite = (
        f"Limbowatch (limbo.watch), data as of {now:%Y-%m-%d}. Advisory data from GitHub repository security "
        "advisories and the GitHub Advisory Database, CC BY 4.0."
    )
    kit = "".join(
        f'<li><a href="/press/kit/{f}">{E(t)}</a></li>'
        for f, t in [("wordmark-on-dark.png", "Wordmark on dark (PNG)"), ("wordmark-on-light.png", "Wordmark on light (PNG)"),
                     ("mark.svg", "Mark (SVG)"), ("avatar.png", "Square icon (PNG)")]
    )  # fmt: skip
    body = f"""<header class="top">{header("press")}</header>
<main class="wrap">
<div class="head"><div><p class="eyebrow">For reporters and researchers. Numbers updated {E(stamp(m["generated_at"]))}.</p>
<h1 class="page">Press and research</h1>
<p class="sub lead">Limbowatch measures how long published security advisories wait before scanners can see them.
Everything here is free to cite with credit, and every number links to how it was measured.</p></div>
<div class="contact card"><h2 class="xs">Talk to us</h2><p>Yujia Lin built Limbowatch and answers questions about the data
and the method.</p><a class="btn solid" href="mailto:{CONTACT}?subject=limbo.watch%20press%20question">{CONTACT}</a></div></div>

<section class="s"><h2>The numbers today</h2><p class="sub">Ready to quote. They update every day; please give the date.</p>
<ol class="quotes">{facts_html}</ol>
<p class="muted small">Every live number is a floor: Limbowatch sees only the {m["coverage"]["watchlist_repos"]:,} repositories
it watches. <a href="/methodology/">Methodology</a></p></section>

<section class="s"><h2>The queue, as a chart</h2><p class="sub">Free to republish with credit. The SVG scales to any size.</p>
<div class="poster">{queue_figure(cols, undated)}</div>
<p class="links"><a href="/press/queue.svg" download>Download the chart (SVG)</a><a href="/press/limbo.csv" download>Every advisory
in limbo (CSV)</a><a href="/metrics.json">Today’s counts (JSON)</a></p></section>

<section class="s"><h2>Stories in the data</h2><div class="paths">
<div><h3>The queue grows faster than it drains</h3><p>In the last {flow.get("days", 7)} days, maintainers published
{flow.get("published", 0):,} new advisories and GitHub reviewed {flow.get("reviewed", 0):,} of those waiting. The
<a href="{ISSUE_URL}">daily report</a> shows what entered and left each day.</p></div>
<div><h3>Critical, fixed, and still invisible</h3><p>Maintainers often ship the fix with the advisory. Users of the
vulnerable version get no alert until the review happens. Examples are below.</p></div>
<div><h3>Advisories nobody will review</h3><p>{perm["count"]:,} advisories are in ecosystems outside GitHub’s review, like
C/C++ libraries and container images. No scanner that reads GitHub’s database will flag them.</p></div>
<div><h3>CVE IDs that stay empty</h3><p>{li["rbp"]["count"]:,} advisories cite a CVE that is reserved but not published,
so looking it up returns nothing. The CVE Program expects publication within 72 hours.</p></div>
<div><h3>One advisory, followed for months</h3><p>A critical advisory for an NSA open-source project waited 85 days for
its CVE. It still isn’t in GitHub’s database, and OSV lists the CVE without a package, so scanners can’t match it.
<a href="/why/">The story</a></p></div></div></section>

<section class="s"><h2>Examples you can check</h2><p class="sub">Critical advisories with a released fix, published this
past year, still waiting longest. Each links to our facts page and to the maintainers’ advisory on GitHub.</p>
<div class="tbl"><table><thead><tr><th scope="col">Package</th><th scope="col">Advisory</th><th scope="col">Fixed in</th>
<th scope="col" class="n">Waiting</th></tr></thead><tbody>{examples or '<tr><td colspan="4" class="muted">None right now.</td></tr>'}</tbody></table></div></section>

<section class="s two"><div><h2 class="sm">How to cite</h2><pre class="light wrapcode">{E(cite)}</pre>
<p class="sub">Data is licensed CC BY 4.0. Advisory facts come from GitHub; we don’t republish advisory text, so quote
the maintainers’ advisory directly.</p></div>
<div><h2 class="sm">Logo</h2><p class="sub">An hourglass whose last grain is stuck in the neck: published above, not yet
reviewed below.</p><ul class="kit">{kit}</ul></div></section>

<section class="s"><div class="note"><h3>About Limbowatch</h3><ul>
<li>An independent open-source project, created by Yujia Lin after the advisory for a vulnerability Yujia reported spent
months invisible to scanners. Not affiliated with GitHub, OSV, MITRE or NIST.</li>
<li>It reads only public data: published advisories, GitHub’s reviewed database, OSV, the CVE List and NVD.</li>
<li>The people reviewing advisories are doing their jobs. The point is the length of the queue, not who is in it.</li>
<li>Code under Apache-2.0 and data under CC BY 4.0, both on <a href="{REPO_URL}">GitHub</a>.</li></ul></div></section>
</main>
{footer()}"""
    return page(
        "Press and research · limbo.watch",
        "Live, citable numbers on security advisories waiting for GitHub review, with charts, examples, methodology and contact.",
        body,
        "/press/",
        dataset_ld(m),
    )


def methodology(m: dict[str, Any]) -> str:
    cov, flow = m["coverage"], m.get("flow_7d") or {}
    sections = [
        ("limbo", "What “in limbo” means", """<p>An advisory is in limbo when all of these are true:</p><ul>
<li>A maintainer has published it as a GitHub repository security advisory.</li>
<li>It isn’t in GitHub’s reviewed Advisory Database, either under its own ID or as a duplicate: an already reviewed
advisory for the same CVE.</li>
<li>It isn’t in OSV.</li>
<li>Its package is in an ecosystem GitHub reviews, such as npm, PyPI, Maven, Go, RubyGems, crates.io, NuGet or Packagist.</li></ul>
<p>Dependabot alerts, npm audit, pip-audit, OSV-Scanner and most tools built on them read GitHub’s reviewed database or
OSV, so they don’t report these advisories until GitHub reviews them.</p>"""),
        ("permanent", "Likely permanent", f"""<p>Advisories in ecosystems GitHub doesn’t review (C/C++, container images,
free-text package names, “other”) are counted separately, as likely permanent: {m["likely_permanent"]["count"]:,} today.
Scanners that read GitHub’s database will probably never see them. They aren’t in the headline number.</p>"""),
        ("sources", "Sources", """<ul>
<li><strong>GitHub repository security advisories</strong>, read through the GitHub REST API from each watched repository.</li>
<li><strong>GitHub’s reviewed Advisory Database</strong>, synced every day.</li>
<li><strong>OSV.dev</strong>, queried by advisory ID.</li>
<li><strong>The CVE List</strong> (cvelistV5) and CVE Services, for whether a CVE is reserved or published, and for CVEs
other CNAs published that point to an advisory.</li>
<li><strong>The NVD API</strong>, for NVD’s status. This product uses the NVD API but is not endorsed or certified by the NVD.</li></ul>
<p>Facts are recorded only when they change, and each change is kept as an event, so every advisory page shows its history.</p>"""),
        ("coverage", "Coverage: every number is a floor", f"""<p>GitHub has no public list of every repository advisory,
so Limbowatch watches a list of repositories: {cov["watchlist_repos"]:,} today. It includes every repository where a
reviewed advisory originated, the dependencies of the 100 most-starred GitHub projects and of the projects in our
October report, and repositories named in CVEs GitHub assigned.</p><ul>
<li>Repositories with an advisory in limbo are re-checked daily, those with other advisories every 3 days, and the rest weekly.
{cov["on_schedule"]:,} are up to date on that schedule right now.</li>
<li>An advisory in a repository nobody watches isn’t counted. The real numbers are higher.</li>
<li>When the watchlist grows, older advisories are found for the first time. The daily report separates these from newly
published ones, so coverage growth isn’t mistaken for new limbo.</li></ul>"""),
        ("flow", "The weekly flow", f"""<p>“Published in the last 7 days” counts advisories whose maintainer published them in
that window, in watched repositories and ecosystems GitHub reviews: {flow.get("published", 0):,} this week. “Reviewed”
counts advisories that left limbo in the same window because GitHub reviewed them: {flow.get("reviewed", 0):,}.
{flow.get("left", 0):,} left limbo in total, including duplicates and withdrawals. Both counts are floors, and a
repository checked every few days can add its new advisories a few days late.</p>"""),
        ("wait", "How waits are measured", """<p>A wait runs from the maintainer’s publication time on GitHub. “Median wait so
far” is for advisories still waiting, so it understates how long they will wait in the end. Completed waits, from
publication to review, are in the <a href="/tracker/">tracker’s “left limbo” tab</a> and the October report, which
measured a median of 23 days for 990 reviewed advisories.</p>"""),
        ("accuracy", "How we check ourselves", f"""<ul>
<li>Findings are checked against primary sources only (GitHub, OSV, the CVE List, NVD), never web search or AI summaries.</li>
<li>In November 2026 we rechecked 657 project findings live: none was contradicted (<a href="{FINDINGS_URL}#f-085">F-085</a>).
The 16 demo findings were rechecked one by one (<a href="{EVIDENCE}">evidence</a>).</li>
<li>Version ranges are as entered by maintainers and haven’t been reviewed. A range that contradicts its own fix is reported as
“possibly affected”, never as certain. Versions are compared with each ecosystem’s own rules, never as text.</li>
<li>Package names are cleaned only where the fix is certain (stray spaces, a URL around the name, canonical spelling), and
the original is kept. <a href="/quality/">Advisories scanners can’t match</a> lists the rest.</li>
<li>Everything we learn goes into a public <a href="{FINDINGS_URL}">research log</a>, with method, sample and caveats.</li></ul>"""),
        ("publish", "What we publish, and what we don’t", """<p>Facts only: IDs, repository, package, ecosystem, version
range, fixed version, severity, CVE state, dates and links. We don’t copy advisory titles, descriptions, authors or credits;
every record links to the maintainers’ advisory.</p>"""),
        ("maintainers", "What helps, if you maintain a project", """<ul>
<li>Request a CVE when you publish the advisory, so CVE-based tools have something to find.</li>
<li>Fill in both the affected range and the fixed version, with the package’s exact name in the right ecosystem.</li>
<li>Check <a href="/quality/">advisories scanners can’t match</a>: a typo in a package name keeps an advisory invisible
even after it’s reviewed.</li></ul>"""),
        ("corrections", "Corrections", f"""<p>If a number or an advisory page is wrong, email <a href="mailto:{CONTACT}">{CONTACT}</a>
or open an issue on <a href="{REPO_URL}/issues">GitHub</a>. Corrections are fixed in the code and logged in the research log.</p>"""),
        ("reproduce", "Reproduce it", f"""<p>The tracker, the site and the analysis are open source under Apache-2.0. The tracker’s
daily state is committed to the <a href="{REPO_URL}/tree/tracker-data">tracker-data branch</a>, so any number here can be
recomputed. The data is CC BY 4.0.</p>"""),
    ]  # fmt: skip
    toc = "".join(f'<li><a href="#{k}">{E(t)}</a></li>' for k, t, _ in sections)
    secs = "".join(f'<section id="{k}"><h2 class="sm">{E(t)}</h2>{b}</section>' for k, t, b in sections)
    body = f"""<header class="top">{header("methodology")}</header>
<main class="wrap"><div class="doc">
<div><p class="eyebrow">How every number on limbo.watch is made</p><h1 class="page">Methodology</h1>
<nav class="toc" aria-label="On this page"><ol>{toc}</ol></nav></div>
<article class="prose">{secs}</article></div></main>
{footer()}"""
    return page(
        "Methodology · limbo.watch",
        "How limbo.watch decides an advisory is in limbo, where the data comes from, what it covers and how it’s checked.",
        body,
        "/methodology/",
    )


# --- machine-readable extras ------------------------------------------------------------------------


def _iso(d: datetime) -> str:
    return d.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def atom(rows: list[Item], now: datetime, path: str, title: str, subtitle: str) -> str:
    """An Atom feed of advisories entering limbo, newest first. Facts only, like the pages."""
    entries = []
    for i in sorted(rows, key=lambda i: i.adv.published_at or now, reverse=True)[:100]:
        a = i.adv
        when = _iso(a.published_at or now)
        fix = fixes(i) or "not stated"
        cve = cves(i) or CVE_TEXT[CVE_KEY[i.assessment.cve_label]].lower()
        summary = (
            f"{(a.severity or 'unknown').capitalize()} advisory for {pkg_names(i)} ({eco_names(i)}), published in {a.repo}. "
            f"Fixed in: {fix}. CVE: {cve}. Not yet in GitHub’s reviewed database or OSV, so most scanners don’t report it."
        )
        entries.append(
            f"<entry><id>{SITE}/advisory/{E(a.ghsa_id)}/</id><title>{E((a.severity or 'unknown').capitalize())}: "
            f"{E(pkg_names(i))} ({E(eco_names(i))}), {E(a.ghsa_id)}</title><updated>{when}</updated><published>{when}</published>"
            f'<link rel="alternate" type="text/html" href="{SITE}/advisory/{E(a.ghsa_id)}/"/>'
            f'<link rel="related" type="text/html" href="{E(a.html_url)}"/><summary>{E(summary)}</summary></entry>'
        )
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n<feed xmlns="http://www.w3.org/2005/Atom">'
        f"<id>{SITE}{path}</id><title>{E(title)}</title><subtitle>{E(subtitle)}</subtitle><updated>{_iso(now)}</updated>"
        f'<link rel="self" href="{SITE}{path}"/><link rel="alternate" type="text/html" href="{SITE}/tracker/"/>'
        f"<author><name>Limbowatch</name><uri>{SITE}</uri></author><rights>{E(ATTRIBUTION)}</rights>"
        + "".join(entries)
        + "</feed>\n"
    )


def _cell(v: str) -> str:
    """Spreadsheets run a cell that starts with = + - @ as a formula; maintainer-entered names could, so quote those."""
    return f"'{v}" if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


def limbo_csv(items: list[Item], now: datetime) -> str:
    """Every advisory in limbo as CSV, for spreadsheets. Text cells that would start a formula get a leading '."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["ghsa_id", "status", "package", "ecosystem", "repository", "severity", "cve_state", "cves",
                "published", "days_waiting", "fixed_in", "advisory_url", "limbo_url"])  # fmt: skip
    for kind, rows in (("pending review", pending(items)), ("likely permanent", permanent(items))):
        for i in sorted(rows, key=lambda i: i.adv.published_at or now):
            a = days_since(i.adv.published_at, now)
            w.writerow([_cell(str(v)) for v in [i.adv.ghsa_id, kind, pkg_names(i), eco_names(i), i.adv.repo, i.adv.severity or "unknown",
                        CVE_TEXT[CVE_KEY[i.assessment.cve_label]], cves(i),
                        _iso(i.adv.published_at) if i.adv.published_at else "", "" if a is None else f"{a:.1f}",
                        fixes(i), i.adv.html_url, f"{SITE}/advisory/{i.adv.ghsa_id}/"]])  # fmt: skip
    return buf.getvalue()


SITEMAP_PAGES = ["/", "/tracker/", "/scan/", "/feed/", "/methodology/", "/press/", "/why/", "/quality/"]


def sitemap(advisories: list[str], now: datetime) -> str:
    day = now.strftime("%Y-%m-%d")
    urls = [*SITEMAP_PAGES, *(f"/advisory/{g}/" for g in sorted(advisories))]
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + "".join(f"<url><loc>{SITE}{E(u)}</loc><lastmod>{day}</lastmod></url>\n" for u in urls)
        + "</urlset>\n"
    )


ROBOTS = f"User-agent: *\nAllow: /\nSitemap: {SITE}/sitemap.xml\n"


# Google Analytics 4 with Consent Mode: every storage type is denied until the visitor accepts, so a visitor who
# declines (or never answers) sends only cookieless pings. Ads storage is never granted. The choice is kept in
# localStorage, and the footer gets a "Cookie settings" link to change it.
ANALYTICS_JS = """(()=>{const id=document.currentScript.dataset.id,K='lw-consent';let choice=null;
try{choice=localStorage.getItem(K)}catch(e){}
window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments)}
gtag('consent','default',{ad_storage:'denied',ad_user_data:'denied',ad_personalization:'denied',
 analytics_storage:choice==='granted'?'granted':'denied'});
gtag('set','ads_data_redaction',true);gtag('js',new Date());gtag('config',id);
const s=document.createElement('script');s.async=true;s.src='https://www.googletagmanager.com/gtag/js?id='+encodeURIComponent(id);
document.head.appendChild(s);
const b=document.createElement('div');b.className='consent';b.setAttribute('role','region');b.setAttribute('aria-label','Cookie consent');
b.innerHTML='<p>limbo.watch uses Google Analytics to count visits. Allow cookies? If you don\u2019t, it sends only anonymous counts without cookies.</p>'
 +'<div><button type="button" class="btn solid" data-v="granted">Allow cookies</button><button type="button" class="btn line" data-v="denied">No thanks</button></div>';
b.hidden=!!choice;document.body.appendChild(b);
b.addEventListener('click',e=>{const v=e.target.closest('button')?.dataset.v;if(!v)return;
 try{localStorage.setItem(K,v)}catch(e){}gtag('consent','update',{analytics_storage:v});b.hidden=true;
 if(v==='denied')document.cookie.split(';').map(c=>c.split('=')[0].trim()).filter(n=>n.startsWith('_ga')).forEach(n=>{
  for(const d of ['',';domain='+location.hostname,';domain=.'+location.hostname])document.cookie=n+'=;Max-Age=0;path=/'+d;});});
const f=document.querySelector('footer .f p:last-child');
if(f){const a=document.createElement('a');a.href='#';a.textContent='Cookie settings';f.append(' \u00b7 ',a);
 a.addEventListener('click',e=>{e.preventDefault();b.hidden=false;b.querySelector('button').focus();});}
})();
"""
GA_ID = re.compile(r"G-[A-Z0-9]{4,16}")


def build(
    items: list[Item],
    metrics: dict[str, Any],
    now: datetime,
    events: list[dict[str, Any]] | None = None,
    sample: dict[str, Any] | None = None,
    analytics_id: str | None = None,
) -> dict[str, str]:
    """Every page of the site, keyed by its path under the output directory. With a GA4 measurement ID,
    every page loads Google Analytics behind a consent banner."""
    if analytics_id and not GA_ID.fullmatch(analytics_id):
        raise ValueError(f"not a GA4 measurement ID: {analytics_id!r}")
    events = events or []
    now = now.astimezone(UTC)
    by_ghsa: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in events:
        by_ghsa[e["ghsa_id"]].append(e)
    data = tracker_data(items, events, now)
    out = {
        "index.html": home(items, metrics, now),
        "tracker/index.html": tracker(metrics, data),
        "tracker/data.json": json.dumps(data, separators=(",", ":")),
        "feed/index.html": feed(metrics, sample),
        "scan/index.html": scan(metrics),
        "why/index.html": why(metrics),
        "quality/index.html": quality(items),
        "methodology/index.html": methodology(metrics),
        "press/index.html": press(items, metrics, now),
        "press/queue.svg": queue_poster(queue_cols(pending(items), now)[0], metrics),
        "press/limbo.csv": limbo_csv(items, now),
        "feed/limbo.atom": atom(
            pending(items),
            now,
            "/feed/limbo.atom",
            "New advisories in limbo · limbo.watch",
            "Security advisories published on GitHub that scanners can’t see yet, newest first.",
        ),
        "feed/critical.atom": atom(
            [i for i in pending(items) if (i.adv.severity or "").lower() in ("critical", "high")],
            now,
            "/feed/critical.atom",
            "New critical and high advisories in limbo · limbo.watch",
            "Critical and high security advisories published on GitHub that scanners can’t see yet.",
        ),
        "sitemap.xml": sitemap([i.adv.ghsa_id for i in items if i.assessment.status is Status.LIMBO], now),
        "robots.txt": ROBOTS,
        "assets/site.css": CSS,
        "assets/tracker.js": TRACKER_JS,
    }
    for i in items:
        if i.assessment.status is Status.LIMBO:
            out[f"advisory/{i.adv.ghsa_id}/index.html"] = advisory(i, by_ghsa.get(i.adv.ghsa_id, []), now)
    if analytics_id:
        tag = f'<script src="/assets/analytics.js" data-id="{analytics_id}" defer></script>\n</head>'
        out = {k: v.replace("</head>", tag, 1) if k.endswith(".html") else v for k, v in out.items()}
        out["assets/analytics.js"] = ANALYTICS_JS
    return out
