"""The CI integrations' own files: limits GitLab enforces when it loads the component, and the action's wiring."""

from __future__ import annotations

import re
from pathlib import Path

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
    """ghcr.io/limbowatch/limbowatch has no `latest` while releases are alphas (image.yml), so an untagged pull fails."""
    for doc in ("README.md", "docs/WATCHER.md", "integrations/gitlab/README.md", "integrations/action/README.md"):
        text = (ROOT / doc).read_text()
        assert not re.search(r"ghcr\.io/limbowatch/limbowatch\s+limbowatch", text), doc
