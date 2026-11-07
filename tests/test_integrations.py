"""The CI integrations' own files: limits GitLab enforces when it loads the component, and the action's wiring."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "integrations/gitlab/templates/limbowatch.yml"
ACTION = ROOT / "integrations/action/action.yml"


def test_gitlab_component_spec_fits_gitlab_limits() -> None:
    spec, job = yaml.safe_load_all(TEMPLATE.read_text())
    desc = spec["spec"]["description"]
    assert len(desc) <= 256, f"spec description is {len(desc)} characters; GitLab allows 256 (FINDINGS F-095)"
    inputs = spec["spec"]["inputs"]
    used = set(re.findall(r"\$\[\[ inputs\.(\w+) \]\]", TEMPLATE.read_text().split("\n---\n", 1)[1]))
    assert used == set(inputs), f"inputs declared but unused, or used but undeclared: {used ^ set(inputs)}"
    for name, spec_in in inputs.items():
        if "options" in spec_in:
            assert spec_in["default"] in spec_in["options"], name
    reports = job["limbowatch"]["artifacts"]
    assert reports["paths"] == ["limbowatch/"] and reports["expose_as"]  # a trailing slash, or no link (F-094)


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
        script = re.fullmatch(r'bash "\$\{\{ github\.action_path \}\}/([\w.]+)"', step["run"])
        assert script and (ACTION.parent / script.group(1)).is_file(), step["run"]
