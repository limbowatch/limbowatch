"""Shallow clones for org-wide mode: the default branch's tip, nothing else (FINDINGS F-130).

- The token goes in an `http.<base>.extraHeader` set through git's environment (GIT_CONFIG_COUNT), never on
  the command line or in the URL, so `ps` and git's own messages can't show it, and git sends it only to
  URLs under the project's host.
- No prompts (GIT_TERMINAL_PROMPT=0), no LFS downloads, no submodules, no tags.
- `core.symlinks=false`: a symlink in a cloned repo becomes a small file holding its target, so a lockfile
  linked to a path outside the checkout can't make OSV-Scanner read that path.
"""

from __future__ import annotations

import base64
import os
import subprocess
from pathlib import Path

from limbowatch.hosts import HostKind, Project

TIMEOUT = 600


class CloneError(RuntimeError):
    pass


def basic_auth(kind: HostKind, token: str) -> str:
    """GitLab takes any token as the password with the user name `oauth2`; Gitea and Forgejo take it as the
    password with any user name (FINDINGS F-130)."""
    user = "oauth2" if kind is HostKind.GITLAB else "limbowatch"
    return "Basic " + base64.b64encode(f"{user}:{token}".encode()).decode()


def environment(project: Project, token: str | None, base: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ if base is None else base)
    env |= {"GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1", "GCM_INTERACTIVE": "never"}
    if token:
        n = int(env.get("GIT_CONFIG_COUNT") or 0)
        env |= {
            "GIT_CONFIG_COUNT": str(n + 1),
            f"GIT_CONFIG_KEY_{n}": f"http.{project.base_url}/.extraHeader",
            f"GIT_CONFIG_VALUE_{n}": f"Authorization: {basic_auth(project.kind, token)}",
        }
    return env


def command(project: Project, dest: Path) -> list[str]:
    return [
        "git", "-c", "core.symlinks=false", "clone", "--depth", "1", "--single-branch", "--no-tags",
        "--no-recurse-submodules", "--quiet", "--", project.clone_url, str(dest),
    ]  # fmt: skip


def clone(project: Project, dest: Path, token: str | None, timeout: int = TIMEOUT) -> str:
    """Clone into `dest` (which must not exist yet); returns the commit checked out."""
    try:
        proc = subprocess.run(command(project, dest), capture_output=True, text=True, timeout=timeout, check=False,
                              env=environment(project, token))  # fmt: skip
    except subprocess.TimeoutExpired as e:
        raise CloneError(f"clone timed out after {timeout} s") from e
    except OSError as e:
        raise CloneError(f"couldn't run git: {e}") from e
    if proc.returncode:
        raise CloneError(_last(proc.stderr) or f"git clone exited with {proc.returncode}")
    head = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"], capture_output=True, text=True, check=False)
    return head.stdout.strip()


def _last(stderr: str) -> str:
    lines = [ln.strip() for ln in stderr.splitlines() if ln.strip()]
    return " ".join(lines[-2:])[:300]
