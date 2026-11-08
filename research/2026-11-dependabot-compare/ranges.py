"""Independent version check of every Limbowatch finding in data/<date>/compare.json (research/2026-11-dependabot-compare).

For each finding, the maintainer's own ranges for that package come from GET /repos/{repo}/security-advisories/{ghsa}
(vulnerabilities[].vulnerable_version_range), and the installed version is tested against them with each ecosystem's
own library, not with Limbowatch's code (which uses univers):
  npm, Rust  semver (npm package; Cargo versions are SemVer 2.0)
  pip        packaging.specifiers
  RubyGems   Gem::Requirement (system Ruby)
  Go         golang.org/x/mod/semver; when the advisory names paths below the matched module, the Go module proxy
             says whether each is a package in that module or a module of its own (then the finding is a false positive)
Writes data/<date>/ranges.json (gitignored) and adds the counts to data/<date>/summary.json. Raw advisories are cached
in .cache/advisories/ (gitignored: they hold advisory text). Needs gh, uv, node + npm, ruby, go, network.

    python3 research/2026-11-dependabot-compare/ranges.py
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Any

from compare import CACHE, gh_json, load, log, run, save

NPM_JS = r"""
const semver = require(process.argv[1]); const out = {};
for (const [k, v, r] of JSON.parse(require('fs').readFileSync(0, 'utf8'))) {
  const c = semver.valid(v) || (semver.coerce(v) || {}).version;
  out[k] = c ? semver.satisfies(c, r.replace(/,/g, ' ').replace(/(^|\s)=\s*/g, '$1'), {includePrerelease: true}) : null;
}
console.log(JSON.stringify(out));
"""
PY = r"""
import json, sys
from packaging.specifiers import SpecifierSet
from packaging.version import Version, InvalidVersion
out = {}
for k, v, r in json.load(sys.stdin):
    def one(p):
        p = p.strip()
        if p.startswith("=") and not p.startswith("=="):
            return "==" + p[1:].strip()
        return p if p[:1] in "<>=!~" else "==" + p
    spec = ",".join(one(p) for p in r.split(","))
    try:
        out[k] = SpecifierSet(spec).contains(Version(v), prereleases=True)
    except (InvalidVersion, ValueError):
        out[k] = None
print(json.dumps(out))
"""
RUBY = r"""
require 'json'
out = {}
JSON.parse(STDIN.read).each do |k, v, r|
  begin
    out[k] = Gem::Requirement.new(*r.split(',').map(&:strip)).satisfied_by?(Gem::Version.new(v))
  rescue StandardError
    out[k] = nil
  end
end
puts JSON.generate(out)
"""
GO = r"""
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"golang.org/x/mod/semver"
)

func main() {
	var in [][3]string
	json.NewDecoder(os.Stdin).Decode(&in)
	out := map[string]any{}
	for _, t := range in {
		v := "v" + strings.TrimPrefix(t[1], "v")
		if !semver.IsValid(v) {
			out[t[0]] = nil
			continue
		}
		ok := true
		for _, part := range strings.Split(t[2], ",") {
			p := strings.TrimSpace(part)
			op := "="
			for _, o := range []string{">=", "<=", "==", ">", "<", "="} {
				if strings.HasPrefix(p, o) {
					op = o
					break
				}
			}
			b := "v" + strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(p, op)), "v")
			c := semver.Compare(v, b)
			switch op {
			case ">=": ok = ok && c >= 0
			case ">": ok = ok && c > 0
			case "<=": ok = ok && c <= 0
			case "<": ok = ok && c < 0
			case "=", "==": ok = ok && c == 0
			default: ok = false
			}
		}
		out[t[0]] = ok
	}
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
}
"""


_GO_MODULES: dict[str, bool] = {}


def go_module(path: str) -> bool:
    """Whether the Go module proxy knows `path` as a module of its own (GET https://proxy.golang.org/<path>/@v/list)."""
    if path not in _GO_MODULES:
        esc = "".join(f"!{c.lower()}" if c.isupper() else c for c in path)  # the proxy's case encoding
        try:
            with urllib.request.urlopen(f"https://proxy.golang.org/{esc}/@v/list", timeout=30) as r:
                _GO_MODULES[path] = r.status == 200 and bool(r.read().strip())
        except urllib.error.HTTPError as e:
            if e.code not in (404, 410):
                raise
            _GO_MODULES[path] = False
    return _GO_MODULES[path]


def advisory(repo: str, ghsa: str) -> dict[str, Any]:
    p = CACHE / "advisories" / f"{ghsa}.json"
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(gh_json(f"repos/{repo}/security-advisories/{ghsa}") or {}))
    return json.loads(p.read_text())


def norm(eco: str, name: str) -> str:
    n = name.lower()
    return re.sub(r"[-_.]+", "-", n) if eco == "pip" else n


GH_ECO = {"npm": "npm", "pip": "pip", "go": "go", "rubygems": "rubygems", "rust": "rust"}


def check(eco: str, items: list[tuple[str, str, str]]) -> dict[str, bool | None]:
    data = json.dumps(items)
    if eco in ("npm", "rust"):
        d = CACHE / "node"
        if not (d / "node_modules" / "semver").exists():
            d.mkdir(parents=True, exist_ok=True)
            run(["npm", "install", "--silent", "--prefix", str(d), "semver@7"], check=True)
        r = run(["node", "-e", NPM_JS, str(d / "node_modules" / "semver")], input=data)
    elif eco == "pip":
        r = run(["uv", "run", "--no-project", "--with", "packaging", "python", "-I", "-c", PY], input=data)
    elif eco == "rubygems":
        r = run(["ruby", "-e", RUBY], input=data)
    elif eco == "go":
        d = CACHE / "gocheck"
        if not (d / "go.sum").exists():
            d.mkdir(parents=True, exist_ok=True)
            (d / "main.go").write_text(GO)
            run(["go", "mod", "init", "gocheck"], cwd=d)
            run(["go", "get", "golang.org/x/mod@v0.29.0"], cwd=d, check=True)
        r = run(["go", "run", "."], cwd=d, input=data)
    else:
        return {k: None for k, _, _ in items}
    if r.returncode != 0:
        raise SystemExit(f"{eco} check failed: {r.stderr[-500:]}")
    return json.loads(r.stdout)


def main() -> None:
    compare = load("compare.json")
    batches: dict[str, list[tuple[str, str, str]]] = {}
    meta: dict[str, dict[str, Any]] = {}
    for name, c in compare.items():
        for i, f in enumerate(c["findings"]):
            eco = f["ecosystem"]
            adv = advisory(f["repo"], f["ghsa"])
            vulns = [v for v in adv.get("vulnerabilities") or []
                     if (v.get("package") or {}).get("ecosystem") == GH_ECO.get(eco) and v.get("vulnerable_version_range")]
            ranges = [v["vulnerable_version_range"] for v in vulns if norm(eco, (v["package"]["name"] or "").strip()) == norm(eco, f["package"])]
            go_paths: dict[str, bool] = {}
            if not ranges and eco == "go":  # the advisory names paths below the module: packages in it, or modules of their own?
                for v in vulns:
                    path = (v["package"]["name"] or "").strip()  # maintainers' typing: " go.mongodb.org/..." occurs
                    if path.startswith(f["package"] + "/"):
                        go_paths[path] = go_module(path)
                        if not go_paths[path]:
                            ranges.append(v["vulnerable_version_range"])
            key = f"{name}#{i}"
            meta[key] = {"project": name, "ghsa": f["ghsa"], "ecosystem": eco, "package": f["package"], "version": f["version"],
                         "limbowatch_affected": f["affected"], "ranges": ranges, "go_subpaths_are_modules": go_paths}
            for j, rng in enumerate(ranges):
                batches.setdefault(eco, []).append((f"{key}|{j}", f["version"], rng))
    results: dict[str, bool | None] = {}
    for eco, items in batches.items():
        log(f"{eco}: {len(items)} range checks")
        results |= check(eco, items)
    rows = []
    for key, m in meta.items():
        verdicts = [results.get(f"{key}|{j}") for j in range(len(m["ranges"]))]
        m["in_range"] = True if any(v is True for v in verdicts) else (None if not verdicts or None in verdicts else False)
        if m["limbowatch_affected"] is not True:
            m["verdict"] = "reported-as-possible"
        elif m["in_range"] is True:
            m["verdict"] = "confirmed"
        elif m["go_subpaths_are_modules"] and all(m["go_subpaths_are_modules"].values()):
            m["verdict"] = "false-positive-separate-go-module"
        elif m["ranges"]:
            m["verdict"] = "depends-on-malformed-range"
        else:
            m["verdict"] = "unchecked"
        rows.append(m)
    save("ranges.json", rows)
    count = {"in_range": sum(r["in_range"] is True for r in rows), "out_of_range": sum(r["in_range"] is False for r in rows),
             "undecided": sum(r["in_range"] is None for r in rows)}
    sure = [r for r in rows if r["limbowatch_affected"]]
    count_sure = {"in_range": sum(r["in_range"] is True for r in sure), "out_of_range": sum(r["in_range"] is False for r in sure),
                  "undecided": sum(r["in_range"] is None for r in sure)}
    log(f"all {len(rows)}: {count}; reported as affected ({len(sure)}): {count_sure}")
    summary = load("summary.json")
    verdicts_all = sorted({r["verdict"] for r in rows})
    by_verdict = {v: sum(r["verdict"] == v for r in rows) for v in verdicts_all}
    log(f"verdicts: {by_verdict}")
    summary["native_range_check"] = {"all_findings": len(rows), **count, "reported_affected": len(sure),
                                     "reported_affected_result": count_sure,
                                     "possibly_affected": len(rows) - len(sure), "by_verdict": by_verdict}
    for name in compare:
        mine = [r for r in rows if r["project"] == name]
        summary["projects"][name]["native_in_range"] = sum(r["in_range"] is True for r in mine)
        summary["projects"][name]["by_verdict"] = {v: sum(r["verdict"] == v for r in mine) for v in verdicts_all}
    save("summary.json", summary)


if __name__ == "__main__":
    main()
