"""The CI integrations' own files: limits GitLab enforces when it loads the component, and the action's wiring."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "integrations/gitlab/templates/limbowatch.yml"
ACTION = ROOT / "integrations/action/action.yml"


def test_gitlab_component_spec_fits_gitlab_limits() -> None:
    spec, jobs = yaml.safe_load_all(TEMPLATE.read_text())
    desc = spec["spec"]["description"]
    assert len(desc) <= 256, f"spec description is {len(desc)} characters; GitLab allows 256 (FINDINGS F-095)"
    inputs = spec["spec"]["inputs"]
    used = set(re.findall(r"\$\[\[ inputs\.(\w+) \]\]", TEMPLATE.read_text().split("\n---\n", 1)[1]))
    assert used == set(inputs), f"inputs declared but unused, or used but undeclared: {used ^ set(inputs)}"
    for name, spec_in in inputs.items():
        assert spec_in.get("description"), f"{name}: the Catalog shows input descriptions as the documentation"
        if "options" in spec_in:
            assert spec_in["default"] in spec_in["options"], name
    scan = jobs["$[[ inputs.job_name ]]"]
    reports = scan["artifacts"]
    assert reports["paths"] == ["limbowatch/"] and reports["expose_as"]  # a trailing slash, or no link (F-094)
    assert set(reports["reports"]) == {"codequality", "junit", "sarif"}


def test_gitlab_component_pins_its_image_by_digest() -> None:
    spec, _ = yaml.safe_load_all(TEMPLATE.read_text())
    image = spec["spec"]["inputs"]["image"]["default"]
    # mirror-image in the component project copies exactly this digest from ghcr.io
    assert re.fullmatch(r"registry\.gitlab\.com/limbowatch/limbowatch-component:[\w.-]+@sha256:[0-9a-f]{64}", image)


def test_gitlab_component_exit_codes_and_gate() -> None:
    """Exit 1 (findings) may warn, exit 2 (couldn't run) always fails; the gate job exists only for security_report
    and otherwise follows the scan job's rules (F-106)."""
    _, jobs = yaml.safe_load_all(TEMPLATE.read_text())
    scan, gate = jobs["$[[ inputs.job_name ]]"], jobs["$[[ inputs.job_name ]]-gate"]
    assert scan["allow_failure"] == gate["allow_failure"] == {"exit_codes": [3]}
    script = scan["script"][0]
    assert "rc=3" in script and "rc=0" in script and 'exit "$rc"' in script
    assert gate["rules"][0] == {"if": '$LW_SECURITY_REPORT != "true"', "when": "never"}
    assert gate["rules"][1] == "$[[ inputs.rules ]]" and scan["rules"] == "$[[ inputs.rules ]]"
    assert gate["needs"] == [{"job": "$[[ inputs.job_name ]]", "artifacts": True}]
    assert "\\e" not in script  # dash's printf (python:slim's /bin/sh) knows \033, not \e


def test_gitlab_component_script_is_valid_sh() -> None:
    import shutil
    import subprocess

    _, jobs = yaml.safe_load_all(TEMPLATE.read_text())
    shell = shutil.which("dash") or "sh"
    for job in jobs.values():
        for line in job["script"]:
            script = re.sub(r"\$\[\[ inputs\.\w+ \]\]", "x", line)
            subprocess.run([shell, "-n"], input=script, text=True, check=True)


def test_action_inputs_and_outputs_are_wired() -> None:
    action = yaml.safe_load(ACTION.read_text())
    text = ACTION.read_text()
    used = set(re.findall(r"inputs\.([\w-]+)", text))
    declared = set(action["inputs"])
    assert used == declared, f"inputs declared but unused, or used but undeclared: {used ^ declared}"
    scripts = "".join((ACTION.parent / n).read_text() for n in ("install.sh", "scan.sh"))
    for name, out in action["outputs"].items():
        step_output = re.fullmatch(r"\$\{\{ steps\.scan\.outputs\.([\w-]+) \}\}", out["value"])
        assert step_output and f"{step_output.group(1)}=" in scripts, name
    for step in action["runs"]["steps"]:  # the scripts live beside action.yml, so logs show one line, not the script
        # $GITHUB_ACTION_PATH, not ${{ github.action_path }}: the latter is the host path inside container jobs
        script = re.fullmatch(r'bash "\$GITHUB_ACTION_PATH/([\w.]+)"', step["run"])
        assert script and (ACTION.parent / script.group(1)).is_file(), step["run"]


def test_action_and_component_pin_the_same_image() -> None:
    """One release, one image: the action pulls it from ghcr.io, the component from its GitLab copy (same digest)."""
    action = yaml.safe_load(ACTION.read_text())
    spec, _ = yaml.safe_load_all(TEMPLATE.read_text())
    a = action["inputs"]["image"]["default"]
    g = spec["spec"]["inputs"]["image"]["default"]
    assert a.startswith("ghcr.io/limbowatch/limbowatch:") and "@sha256:" in a
    assert a.split("@")[1] == g.split("@")[1] and a.split("@")[0].rsplit(":", 1)[1] == g.split("@")[0].rsplit(":", 1)[1]
    ref = action["inputs"]["limbowatch-ref"]["default"]
    assert ref == "v" + a.split("@")[0].rsplit(":", 1)[1], "the pip fallback installs the image's release"


def test_action_scripts_are_valid_bash() -> None:
    import subprocess

    for name in ("install.sh", "scan.sh"):
        subprocess.run(["bash", "-n", str(ACTION.parent / name)], check=True)


# Stands in for `docker run` of a compromised image: it writes what a scan would, as symlinks to the runner's files
# where it can, forged outputs and annotations, and workflow commands on stdout.
FAKE_DOCKER = r"""#!/usr/bin/env bash
printf '%s\n' "$@" >> "$RUNNER_TEMP/docker-args"
out="$RUNNER_TEMP/limbowatch/out"
echo '::set-output name=failed::from-stdout'
case " $* " in
  *" python3 - "*)
    cat > /dev/null
    printf 'findings=1\nfailing=$(id)\nfailed=pwned\nevil=1\nverdict=::add-path::/evil\nverdict=PASSED  fine\n' \
      > "$out/limbowatch.outputs" ;;
  *" scan "*)
    printf '{}' > "$out/limbowatch.json"
    ln -s "$SECRET" "$out/limbowatch.md"
    ln -s "$SECRET" "$out/limbowatch.sarif"
    printf '::warning file=go.mod::real\n::add-path::/evil\n::set-output name=x::y\n' > "$out/limbowatch.annotations"
    ln -s "$SECRET" "$RUNNER_TEMP/limbowatch/reports/report.html"
    echo regular > "$RUNNER_TEMP/limbowatch/reports/report.json"
    exit 1 ;;
esac
"""


def test_action_image_mode_keeps_a_compromised_image_off_the_runner(tmp_path: Path) -> None:
    """Image mode: the checkout read-only, never the runner's temp directory (GITHUB_ENV and GITHUB_PATH are there),
    a hardened container, workflow commands off while it prints, nothing it wrote followed or passed on unchecked."""
    import os
    import subprocess

    ws, rt, bin_ = tmp_path / "ws", tmp_path / "rt", tmp_path / "bin"
    for d in (ws / "proj", rt, bin_):
        d.mkdir(parents=True)
    (bin_ / "docker").write_text(FAKE_DOCKER)
    (bin_ / "docker").chmod(0o755)
    secret = tmp_path / "secret"
    secret.write_text("RUNNER-SECRET")
    gh_output, summary = tmp_path / "gh_output", tmp_path / "summary.md"
    gh_output.touch()
    env = os.environ | {
        "PATH": f"{bin_}:{os.environ['PATH']}", "SECRET": str(secret), "RUNNER_TEMP": str(rt),
        "GITHUB_WORKSPACE": str(ws), "GITHUB_OUTPUT": str(gh_output), "GITHUB_STEP_SUMMARY": str(summary),
        "LW_MODE": "image", "LW_IMAGE": "img", "LW_PATH": "proj", "LW_FAIL_ON": "low", "LW_FAIL_ON_UNKNOWN": "true",
        "LW_ALLOW_FAILURE": "false", "LW_SARIF": "out.sarif", "LW_ANNOTATIONS": "true",
        "LW_REPORTS": "limbowatch-report", "LW_ISSUES": "", "LW_EXTRA": "", "LW_DEFAULT_BRANCH": "main",
    }  # fmt: skip
    r = subprocess.run(["bash", str(ACTION.parent / "scan.sh")], cwd=ws, env=env, capture_output=True, text=True)
    assert r.returncode == 1, r.stdout + r.stderr

    args = (rt / "docker-args").read_text().splitlines()
    for flag in ("--read-only", "no-new-privileges", "--pids-limit"):
        assert flag in args
    assert args[args.index("--cap-drop") + 1] == "ALL"
    mounts = [args[i + 1] for i, a in enumerate(args) if a == "-v"]
    assert f"{ws}:{ws}:ro" in mounts
    assert all(not m.startswith(f"{rt}:") for m in mounts), mounts  # never the whole runner temp directory
    assert f"{rt}/limbowatch/reports:{ws}/limbowatch-report" in mounts

    lines = r.stdout.splitlines()
    stop = [i for i, line in enumerate(lines) if line.startswith("::stop-commands::")]
    assert len(stop) == 1  # the scan; what the outputs step prints goes to /dev/null
    token = lines[stop[0]].removeprefix("::stop-commands::")
    assert re.fullmatch(r"limbowatch-[0-9a-f]{32}", token)
    assert lines[stop[0] + 1] == "::set-output name=failed::from-stdout" and lines[stop[0] + 2] == f"::{token}::"
    outside = lines[: stop[0]] + lines[stop[0] + 3 :]  # what GitHub still reads as commands
    assert [line for line in outside if line.startswith("::")] == [
        "::group::Annotations: one per affected package", "::warning file=go.mod::real", "::endgroup::"]  # fmt: skip
    assert lines[-1] == "PASSED  fine"  # the image's own words, but never a command
    assert gh_output.read_text() == "findings=1\nreport=limbowatch-report/report.json\n"

    assert not summary.exists() and not (ws / "out.sarif").exists()  # symlinks to the secret: not followed
    reports = ws / "limbowatch-report"
    assert (reports / "report.json").read_text() == "regular\n" and not (reports / "report.html").exists()
    assert not [p for p in ws.rglob("*") if p.is_symlink()]


def test_action_readme_lists_every_input_and_output_and_the_release() -> None:
    """The Marketplace page is limbowatch/limbowatch-action's README, a copy of integrations/action/README.md."""
    action = yaml.safe_load(ACTION.read_text())
    readme = (ACTION.parent / "README.md").read_text()
    for name in [*action["inputs"], *action["outputs"]]:
        assert f"| `{name}` |" in readme, name
    ref = action["inputs"]["limbowatch-ref"]["default"]
    assert f"limbowatch/limbowatch-action@{ref}" in readme
    assert f"Release {ref.removeprefix('v')}" in readme
    assert (ACTION.parent / "LICENSE").read_text() == (ROOT / "LICENSE").read_text()


def test_action_self_test_pins_its_actions() -> None:
    wf = (ACTION.parent / ".github/workflows/self-test.yml").read_text()
    for line in wf.splitlines():
        if "uses:" in line and "uses: ./" not in line:
            assert re.search(r"@[0-9a-f]{40} # v", line), line


def test_docs_pull_the_image_by_release_tag() -> None:
    """ghcr.io/limbowatch/limbowatch has no `latest` while releases are alphas (image.yml): untagged pulls fail."""
    for doc in ("README.md", "docs/WATCHER.md", "integrations/gitlab/README.md", "integrations/action/README.md"):
        text = (ROOT / doc).read_text()
        assert not re.search(r"ghcr\.io/limbowatch/limbowatch\s+limbowatch", text), doc


def _requirements(text: str) -> dict[str, tuple[str, set[str]]]:
    """name -> (version, hashes) of a pip requirements file written with --generate-hashes."""
    out: dict[str, tuple[str, set[str]]] = {}
    for block in re.split(r"\n(?=[A-Za-z0-9])", re.sub(r"(?m)^#.*\n", "", text).strip()):
        m = re.match(r"([A-Za-z0-9_.-]+)==([^\s;\\]+)", block)
        assert m, block
        out[m.group(1).lower().replace("_", "-")] = (m.group(2), set(re.findall(r"sha256:([0-9a-f]{64})", block)))
    return out


def test_action_python_install_is_pinned_with_uv_lock_hashes() -> None:
    """install: python installs exactly uv.lock's runtime dependencies, each checked against uv.lock's own hashes,
    plus the build backend; regenerate with scripts/action_requirements.py when uv.lock changes."""
    reqs = _requirements((ACTION.parent / "requirements.txt").read_text())
    lock = tomllib.loads((ROOT / "uv.lock").read_text())["package"]
    locked = {p["name"]: p for p in lock}
    runtime = {"limbowatch", "limbowatch-cli"}
    todo = ["limbowatch-cli"]
    while todo:  # the CLI's runtime dependency closure in uv.lock (markers ignored: the file covers every platform)
        for d in locked[todo.pop()].get("dependencies", []):
            if d["name"] not in runtime:
                runtime.add(d["name"])
                todo.append(d["name"])
    runtime -= {"limbowatch", "limbowatch-cli"}
    assert runtime <= set(reqs), f"missing from requirements.txt: {sorted(runtime - set(reqs))}"
    for name in runtime:
        version, hashes = reqs[name]
        p = locked[name]
        lock_hashes = {f["hash"].removeprefix("sha256:") for f in [*p.get("wheels", []), p.get("sdist") or {}] if f}
        assert version == p["version"], f"{name}: requirements.txt has {version}, uv.lock {p['version']}"
        assert hashes and hashes <= lock_hashes, f"{name}: hashes differ from uv.lock"
    assert {"hatchling", "packaging", "pluggy", "pathspec", "trove-classifiers"} <= set(reqs)  # the build backend
    assert all(h for _, h in reqs.values()), "every requirement has hashes"
    install = (ACTION.parent / "install.sh").read_text()
    assert '--require-hashes -r "$(dirname "$0")/requirements.txt"' in install and "--no-build-isolation" in install


OWN_FEED_GITHUB = ROOT / "deploy/own-feed/github/limbo-feed.yml"
OWN_FEED_GITLAB = ROOT / "deploy/own-feed/gitlab/.gitlab-ci.yml"


def test_own_feed_pipelines_build_with_the_release_the_action_pins() -> None:
    """docs/OWN_FEED.md: the same image (digest) and the same release's seed lists as the action, bumped with it."""
    action = yaml.safe_load(ACTION.read_text())
    image, ref = action["inputs"]["image"]["default"], action["inputs"]["limbowatch-ref"]["default"]
    gh = yaml.safe_load(OWN_FEED_GITHUB.read_text())
    assert (gh["env"]["LIMBOWATCH_IMAGE"], gh["env"]["LIMBOWATCH_REF"]) == (image, ref)
    gl = yaml.safe_load(OWN_FEED_GITLAB.read_text())
    assert gl["variables"]["LIMBOWATCH_IMAGE"].split("@")[1] == image.split("@")[1]
    assert gl["variables"]["LIMBOWATCH_IMAGE"].startswith("registry.gitlab.com/limbowatch/limbowatch-component:")
    assert gl["variables"]["LIMBOWATCH_REF"] == ref
    for line in OWN_FEED_GITHUB.read_text().splitlines():
        if "uses:" in line:
            assert re.search(r"@[0-9a-f]{40} # v", line), line


def test_own_feed_pipelines_build_only_the_feed_and_keep_their_state() -> None:
    gh = yaml.safe_load(OWN_FEED_GITHUB.read_text())
    steps = gh["jobs"]["build"]["steps"]
    run = "\n".join(s.get("run", "") for s in steps)
    assert "limbowatch publish --state state/state --out site --feed-only" in run and "limbo.watch" not in run
    assert "git push" in run and "limbo-feed-state" in run
    attest = next(s for s in steps if "actions/attest@" in s.get("uses", ""))
    assert attest["continue-on-error"] == "${{ github.event.repository.private }}"  # Free plans: public repos only
    assert set(attest["with"]["subject-path"].split()) == {"site/feed/all.zip", "site/feed/watchlist.json",
                                                           "site/feed/index.json"}  # fmt: skip
    # focused: `limbowatch repos` over the orgs, then only those repos; branch: one commit, force-pushed
    focus = next(s for s in steps if s.get("if") == "env.WATCH == 'focused'")
    assert "limbowatch repos" in focus["run"] and "--out focus/repos.txt" in focus["run"]
    assert "--only-seeds --seed /work/focus/repos.txt" in run
    branch = next(s for s in steps if s.get("if") == "env.PUBLISH == 'branch'")
    assert "push -q --force" in branch["run"] and "limbo-feed" in branch["run"] and "SHA256SUMS.txt" in branch["run"]
    assert gh["jobs"]["deploy"]["if"] == "(vars.LIMBO_FEED_PUBLISH || 'pages') == 'pages'"
    gl = yaml.safe_load(OWN_FEED_GITLAB.read_text())
    job = gl["pages"]
    script = "\n".join(job["script"])
    assert "limbowatch publish --state state --out public --feed-only" in script and "limbo.watch" not in script
    assert job["artifacts"]["paths"] == ["public"] and job["resource_group"]
    # state in the package registry, read and written with the job token: GitLab Free refuses it the job artifacts of
    # earlier pipelines (F-220); restored before track, saved after publish, two copies kept
    assert "/packages/generic/limbo-feed-state/1/state.tar.gz" in script and "JOB-TOKEN" in script
    assert script.index("no saved state") < script.index("limbowatch track") < script.index('method="PUT"')
    assert "[:-2]" in script and 'filter="data"' in script and "jobs/artifacts" not in script
    assert "--cve-list /tmp/cvelist/*_all_CVEs_at_midnight.zip.zip" in script  # its date in its name (F-220)
    assert "SameHostToken" in script  # urllib would send the job token on to object storage on a redirect
    for py in re.findall(r"python3 - [^\n]*<<'PY'\n(.*?)\nPY\n", script, re.S):  # every embedded script compiles
        compile(py, "<.gitlab-ci.yml>", "exec")
    assert len(re.findall(r"<<'PY'", script)) == 3
    # the shell parts are valid sh / bash
    import subprocess

    subprocess.run(["sh", "-n"], input=script, text=True, check=True)
    for s in steps:
        if "run" in s:
            subprocess.run(["bash", "-n"], input=s["run"], text=True, check=True)


OWN_FEED_GITHUB_CLI = ROOT / "deploy/own-feed/github/limbo-feed-cli.yml"
OWN_FEED_GITLAB_CLI = ROOT / "deploy/own-feed/gitlab/.gitlab-ci.cli.yml"


def test_own_feed_cli_pipelines_install_the_release_and_no_image() -> None:
    """The CLI-only own-feed pipelines (docs/OWN_FEED.md#cli-only): limbowatch-cli from PyPI at this release,
    OSV-Scanner checked against its release's sums, no Limbowatch image and, on GitHub, no actions at all. Bumped with
    each release."""
    from limbowatch import __version__

    gh = yaml.safe_load(OWN_FEED_GITHUB_CLI.read_text())
    gl = yaml.safe_load(OWN_FEED_GITLAB_CLI.read_text())
    assert gh["env"]["LIMBOWATCH_VERSION"] == gl["variables"]["LIMBOWATCH_VERSION"] == __version__
    steps = gh["jobs"]["build"]["steps"]
    run = "\n".join(s["run"] for s in steps)
    script = "\n".join(gl["pages"]["script"])
    for text in (run, script):
        assert '"limbowatch-cli==$LIMBOWATCH_VERSION"' in text and "sha256sum -c -" in text
        assert "limbowatch repos" in text and "--only-seeds" in text and "--feed-only" in text
        assert "limbowatch/limbowatch" not in text.replace("limbowatch/limbowatch-", "")  # no image, no seed lists
    assert all("uses" not in s for s in steps) and "docker" not in run
    assert 'push -q "$remote" limbo-feed-state' in run and 'push -q --force "$remote" limbo-feed' in run
    assert gl["pages"]["image"] == "python:3.12" and gl["pages"]["artifacts"]["paths"] == ["public"]
    # state in the package registry; the job token only to GitLab (a redirect is followed without it)
    assert (
        "/packages/generic/limbo-feed-state/1/state.tar.gz" in script
        and "-L" not in script.split("state_url")[1].split("\n")[1]
    )
    assert '30[1278]*) curl -sSfL -o state.tar.gz "${got#* }"' in script and "[:-2]" in script
    import subprocess

    subprocess.run(["bash", "-n"], input=script, text=True, check=True)
    for s in steps:
        subprocess.run(["bash", "-n"], input=s["run"], text=True, check=True)
    for py in re.findall(r"python3 - [^\n]*<<'PY'[^\n]*\n(.*?)\nPY\n", script, re.S):
        compile(py, "<.gitlab-ci.cli.yml>", "exec")


SEALED = ROOT / "deploy/sealed/github/limbowatch.yml"

# Every file name OSV-Scanner reads in `scan source` (its lockfile and sbom presets: each extractor's FileRequired
# in osv-scalibr c80efcc, which OSV-Scanner 2.7.1 pins), one example path each. Check again on a new OSV-Scanner.
OSV_SCANNER_FILES = [
    "package-lock.json", "npm-shrinkwrap.json", "web/pnpm-lock.yaml", "yarn.lock", "bun.lock",
    "requirements.txt", "api/requirements-dev.txt", "dev-requirements.txt", "Pipfile.lock", "poetry.lock", "pdm.lock",
    "uv.lock", "pylock.toml", "pylock.dev.toml", "go.mod", "Cargo.lock", "Gemfile.lock", "gems.locked",
    "composer.lock", "mix.lock", "pubspec.lock", "app/.dart_tool/package_config.json", "renv.lock",
    "ios/Package.resolved", "cabal.project.freeze", "stack.yaml.lock", "pom.xml", "lib/x-1.0.pom", "gradle.lockfile",
    "buildscript-gradle.lockfile", "gradle/verification-metadata.xml", "CsApp/App.csproj", "VbLib/Lib.vbproj",
    "Fn/Fn.fsproj", "bin/App.deps.json", "packages.config", "packages.lock.json", "Directory.Packages.props",
    "Directory.Build.props", "sbom.cdx.json", "sbom.cdx.xml", "bom.json", "sbom.spdx", "sbom.spdx.json",
]  # fmt: skip


def _sealed() -> dict[str, Any]:
    return yaml.safe_load(SEALED.read_text())


def _sparse_checkout(repo: Path, patterns: str, paths: list[str]) -> set[str]:
    """The paths git checks out with these non-cone patterns, as actions/checkout sets them (case-sensitive, as on
    a Linux runner)."""
    import subprocess

    for p in paths:
        (repo / p).parent.mkdir(parents=True, exist_ok=True)
        (repo / p).write_text("x\n")

    def git(*args: str, stdin: str | None = None) -> str:
        cfg = ["-c", "core.ignorecase=false", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
               "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null"]  # fmt: skip
        r = subprocess.run(["git", *cfg, *args], cwd=repo, input=stdin, capture_output=True, text=True, check=True)
        return r.stdout

    git("init", "-q")
    git("add", "-A", "--force")
    git("commit", "-q", "-m", "x")
    git("config", "core.ignorecase", "false")
    git("sparse-checkout", "set", "--no-cone", "--stdin", stdin=patterns)
    return {line[2:] for line in git("ls-files", "-t").splitlines() if line.startswith("H ")}


def test_sealed_template_checks_out_every_file_the_scan_reads_and_nothing_else(tmp_path: Path) -> None:
    """deploy/sealed/: the collect job's sparse checkout is the whole of what reaches the scan, so it must hold every
    file OSV-Scanner and Limbowatch read (else a dependency would go unreported) and nothing more."""
    from limbowatch.inventory import osv_scanner, upstream

    assert osv_scanner.TESTED_VERSION == "2.7.1", "a new OSV-Scanner: check OSV_SCANNER_FILES against its extractors"
    checkout = next(s for s in _sealed()["jobs"]["collect"]["steps"] if "actions/checkout@" in s.get("uses", ""))
    assert checkout["with"]["sparse-checkout-cone-mode"] is False and checkout["with"]["persist-credentials"] is False
    ours = [*upstream.UPSTREAM_FILES, *(f"cmake/x{s}" for s in upstream.UPSTREAM_SUFFIXES),
            f"{upstream.MESON_WRAP_DIR}/zlib.wrap", *osv_scanner.GRADLE_BUILDS,
            *(f"m/{m}" for m in upstream.MANAGED_VENDOR)]  # fmt: skip
    ours = [p if "/" in p else f"b/{p}" for p in ours]
    assert all(upstream._wanted(p) for p in ours if p.rsplit("/", 1)[-1] in upstream.UPSTREAM_FILES)
    licenses = [f"{root}/lib/{n}" for root in upstream.VENDOR_ROOTS for n in ("LICENSE", "COPYING.txt", "license.md")]
    assert all(upstream.LICENSE.match(p.rsplit("/", 1)[-1]) for p in licenses)
    wanted = [*OSV_SCANNER_FILES, *ours, *licenses]
    not_wanted = ["src/app.py", "third_party/zlib/zlib.c", "node_modules/left/package.json",
                  "node_modules/left/yarn.lock", "src/license.go", "LICENSE", "docs/COPYING", "src/workspace/app.ts",
                  "README.md", ".github/workflows/ci.yml", "Makefile", "requirements.md"]  # fmt: skip
    got = _sparse_checkout(tmp_path, checkout["with"]["sparse-checkout"], wanted + not_wanted)
    assert sorted(set(wanted) - got) == [] and sorted(got & set(not_wanted)) == []


def test_sealed_template_runs_the_image_with_nothing_to_reach() -> None:
    """deploy/sealed/: no repository, permissions or secrets in the scan job; the image with no network, read-only,
    as nobody; the feed and the image checked against their attestations outside it; the release's image."""
    wf = _sealed()
    text = SEALED.read_text()
    assert set(wf.get("on", wf.get(True))) == {"schedule", "workflow_dispatch"}
    assert wf["permissions"] == {} and "${{ secrets." not in text
    collect, scan = wf["jobs"]["collect"], wf["jobs"]["scan"]
    assert collect["permissions"] == {"contents": "read"} and scan["permissions"] == {} and scan["needs"] == "collect"
    assert set(wf["jobs"]) == {"collect", "scan"} and all(j["runs-on"] == "ubuntu-latest" for j in wf["jobs"].values())
    action = yaml.safe_load(ACTION.read_text())
    assert wf["env"]["IMAGE"] == action["inputs"]["image"]["default"]  # bumped with each release
    for line in text.splitlines():
        if "uses:" in line and not line.lstrip().startswith("#"):
            assert re.search(r"@[0-9a-f]{40} # v", line), line
    steps = scan["steps"]
    run = "\n".join(s.get("run", "") for s in steps)
    docker = next(s["run"] for s in steps if "docker run" in s.get("run", ""))
    for flag in ("--network none", "--read-only", "--cap-drop ALL", "no-new-privileges", "--user 65534:65534",
                 '"$PWD/in:/scan:ro"', '"$PWD/feed:/feed:ro"', "--feed /feed", "--no-upstream", "--no-resolve-maven",
                 "--no-osv-commits"):  # fmt: skip
        assert flag in docker, flag
    assert "-e " not in docker.replace("-e HOME=/tmp", "")  # no token or other variable reaches the image
    assert "limbowatch/limbowatch/.github/workflows/site.yml --source-ref refs/heads/main" in run
    assert "index($z) != null and index($w) != null" in run  # all.zip and watchlist.json from one build
    assert "limbowatch/limbowatch/.github/workflows/image.yml" in run
    assert run.index("gh attestation verify all.zip") < run.index("docker run")
    assert run.index('gh attestation verify "oci://$IMAGE"') < run.index("docker run")
    import subprocess

    for s in [*collect["steps"], *steps]:
        if "run" in s:
            subprocess.run(["bash", "-n"], input=s["run"], text=True, check=True)
