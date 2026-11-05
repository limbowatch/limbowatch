"""Run the GitLab component's job script and the Action's steps in a clean container (PHASE0_PLAN §10, Phase 4).

Not part of the test suite: needs Docker and the network (OSV-Scanner's release, the live limbo feed).
Limbowatch is installed from `git archive HEAD`, served as a local file in place of GitHub's archive URL.

    uv run --with pyyaml python scripts/check_integrations.py
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
IMAGE = "python:3.12-slim"
GO_MOD = "module example.com/ci\n\ngo 1.22\n\nrequire github.com/andybalholm/brotli v1.2.1\n"


def sh(*cmd: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def gitlab_script(inputs: dict[str, Any]) -> str:
    spec, job = yaml.safe_load_all((ROOT / "integrations/gitlab/templates/limbowatch.yml").read_text())
    values = {k: v.get("default") for k, v in spec["spec"]["inputs"].items()} | inputs
    j = job["limbowatch"]
    env = {k: re.sub(r"\$\[\[ inputs\.(\w+) \]\]", lambda m: str(values[m.group(1)]).lower()
                     if isinstance(values[m.group(1)], bool) else str(values[m.group(1)]), str(v))
           for k, v in j["variables"].items()}  # fmt: skip
    exports = "".join(f"export {k}='{v}'\n" for k, v in env.items())
    return exports + "\n".join(j["script"])


def action_script(inputs: dict[str, str]) -> str:
    a = yaml.safe_load((ROOT / "integrations/action/action.yml").read_text())
    values = {k: str(v.get("default", "")) for k, v in a["inputs"].items()} | inputs
    out = []
    for step in a["runs"]["steps"]:
        env = {k: re.sub(r"\$\{\{ inputs\.([\w-]+) \}\}", lambda m: values[m.group(1)], str(v))
               for k, v in (step.get("env") or {}).items()}  # fmt: skip
        env = {k: ("main" if "default_branch" in v else v) for k, v in env.items()}
        out.append("(\n" + "".join(f"export {k}='{v}'\n" for k, v in env.items()) + step["run"] + "\n)")
    return "set -e\n" + "\n".join(out)


def run(name: str, script: str, work: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    (work / f"{name}.sh").write_text(script)
    args = ["docker", "run", "--rm", "-v", f"{work}:/work", "-w", "/work/proj"]
    for k, v in env.items():
        args += ["-e", f"{k}={v}"]
    return sh(*args, IMAGE, "bash", "-c", f"bash /work/{name}.sh")


def check(cond: bool, what: str, detail: str = "") -> None:
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        print(detail[-3000:])
        raise SystemExit(1)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        (work / "src").mkdir()
        r = sh("git", "-C", str(ROOT), "archive", "--prefix=limbowatch-main/", "-o", str(work / "src/main.tar.gz"), "HEAD")
        if r.returncode:
            sys.exit(r.stderr)
        (work / "proj").mkdir()
        (work / "proj/go.mod").write_text(GO_MOD)
        local = {"limbowatch_source": "file:///work/src", "limbowatch_ref": "main"}

        r = run("gitlab", gitlab_script(local), work, {"CI_COMMIT_BRANCH": "feature", "CI_DEFAULT_BRANCH": "main"})
        cq = work / "proj/gl-code-quality-report.json"
        check(r.returncode == 1, "GitLab job fails on a finding (fail_on low)", r.stdout + r.stderr)
        check(cq.exists() and "GHSA-c9gr-gmg4-2vqv" in cq.read_text(), "GitLab job writes the Code Quality report")
        check("limbowatch.md" in sh("ls", str(work / "proj")).stdout, "GitLab job writes the Markdown report")
        r = run("gitlab2", gitlab_script(local | {"fail_on": "none"}), work, {"CI_COMMIT_BRANCH": "feature"})
        check(r.returncode == 0, "GitLab job passes with fail_on none", r.stdout + r.stderr)

        a = action_script({"limbowatch-source": "file:///work/src", "sarif": "results.sarif"})
        env = {"RUNNER_TEMP": "/tmp/rt", "GITHUB_PATH": "/tmp/gh_path", "GITHUB_STEP_SUMMARY": "/work/summary.md",
               "GITHUB_REF_NAME": "feature"}  # fmt: skip
        r = run("action", "mkdir -p /tmp/rt && touch /tmp/gh_path && export PATH=/tmp/rt/limbowatch-bin:$PATH\n" + a,
                work, env)  # fmt: skip
        check(r.returncode == 1, "Action fails on a finding", r.stdout + r.stderr)
        check("GHSA-c9gr-gmg4-2vqv" in (work / "proj/results.sarif").read_text(), "Action writes SARIF")
        check("GHSA-c9gr-gmg4-2vqv" in (work / "summary.md").read_text(), "Action writes the job summary")
    print("integrations passed")


if __name__ == "__main__":
    main()
