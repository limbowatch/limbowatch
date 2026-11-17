"""The command line exposes every command (a decorator moved onto a helper once hid `scan`)."""

import re
from pathlib import Path

import pytest
import typer
from limbowatch_cli.main import app
from typer.core import TyperGroup


def test_every_command_is_registered() -> None:
    cli = typer.main.get_command(app)
    assert isinstance(cli, TyperGroup)
    assert {"track", "publish", "report", "inventory", "scan", "watch"} <= set(cli.commands)


def test_version_flag() -> None:
    from limbowatch import __version__
    from limbowatch_cli.main import app
    from typer.testing import CliRunner

    r = CliRunner().invoke(app, ["--version"])
    assert r.exit_code == 0 and r.output.strip() == f"limbowatch {__version__}"


def test_output_specs() -> None:
    from pathlib import Path

    import pytest
    import typer
    from limbowatch_cli.main import _outputs

    assert _outputs(None, []) == ("table", [])
    assert _outputs(None, ["json", "sarif=a.sarif", "junit=out/j.xml"]) == (
        "json", [("sarif", Path("a.sarif")), ("junit", Path("out/j.xml"))])  # fmt: skip
    assert _outputs("markdown", []) == ("markdown", [])
    assert _outputs(None, ["csv=-"]) == ("csv", [])  # FILE "-" is stdout
    for bad in (["table", "json"], ["nope=x"], ["sarif="]):
        with pytest.raises(typer.BadParameter):
            _outputs(None, bad)
    with pytest.raises(typer.BadParameter):
        _outputs("json", ["table"])  # two formats on stdout


def test_colour_modes(monkeypatch: pytest.MonkeyPatch) -> None:
    """auto colours CI logs (pipes) in GitHub Actions and GitLab CI; links only on a real terminal."""
    from limbowatch_cli.main import _color

    for var in ("NO_COLOR", "FORCE_COLOR", "GITHUB_ACTIONS", "GITLAB_CI", "CI"):
        monkeypatch.delenv(var, raising=False)
    assert _color("auto") == (False, False)  # a pipe, not CI
    assert _color("always") == (True, False)
    monkeypatch.setenv("GITLAB_CI", "true")
    monkeypatch.setenv("CI", "true")
    assert _color("auto") == (True, False)
    monkeypatch.setenv("NO_COLOR", "1")
    assert _color("auto") == (False, False) and _color("never") == (False, False)


def test_a_crash_exits_2_not_1(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    """Exit 1 means a finding meets --fail-on; anything unexpected must not look like one."""
    from limbowatch_cli import main as cli

    def boom() -> None:
        raise KeyError("feed")

    monkeypatch.setattr(cli, "app", boom)
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert e.value.code == 2 and "unexpected KeyError" in capsys.readouterr().err


def _plain(out: str) -> str:
    """Usage errors as text: CI forces colour, and Rich wraps its error panel at 80 columns."""
    import re

    return " ".join(re.sub(r"[│╭╮╰╯─]", " ", re.sub(r"\x1b\[[0-9;]*m", "", out)).split())


def test_watch_never_sends_one_token_to_two_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    from limbowatch_cli.main import app
    from typer.testing import CliRunner

    monkeypatch.setenv("LIMBOWATCH_SOURCE_TOKEN", "glpat-secret")
    args = ["watch", "--gitlab-group", "https://gitlab.com/acme", "--gitea-org", "https://codeberg.org/acme"]
    r = CliRunner().invoke(app, args)
    assert r.exit_code == 2 and "one token would be sent to all" in _plain(r.output) and "secret" not in r.output
    r = CliRunner().invoke(app, ["watch"])
    assert r.exit_code == 2 and "at least one --gitlab-group" in _plain(r.output)
    r = CliRunner().invoke(app, ["watch", "--git", "https://user:pw@git.example.org/a/b.git"])
    assert r.exit_code == 2 and "pw@" not in r.output


def test_tokens_are_refused_over_plain_http(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Over http to another machine a token crosses the network readable: refused unless --allow-insecure-http."""
    from limbowatch_cli.main import app
    from typer.testing import CliRunner

    monkeypatch.setenv("LIMBOWATCH_SOURCE_TOKEN", "glpat-secret")
    monkeypatch.setenv("LIMBOWATCH_ISSUES_TOKEN", "glpat-secret")
    monkeypatch.delenv("LIMBOWATCH_ALLOW_INSECURE_HTTP", raising=False)
    r = CliRunner().invoke(app, ["watch", "--gitlab-group", "http://gitlab.example.com/acme"])
    out = _plain(r.output)
    assert r.exit_code == 2 and "LIMBOWATCH_SOURCE_TOKEN would be sent over plain http" in out
    assert "--allow-insecure-http" in out and "secret" not in r.output
    scan = ["scan", str(tmp_path), "--issues", "gitlab", "--issues-url", "http://gitlab.example.com",
            "--issues-project", "a/b"]  # fmt: skip
    r = CliRunner().invoke(app, scan)
    assert r.exit_code == 2 and "LIMBOWATCH_ISSUES_TOKEN would be sent over plain http" in _plain(r.output)
    # GitHub: the token goes to the API Actions names (GITHUB_API_URL), checked as well as the server
    gh_env = {"GITHUB_SERVER_URL": "https://ghe.example", "GITHUB_API_URL": "http://ghe.example/api/v3"}
    r = CliRunner().invoke(app, ["scan", str(tmp_path), "--issues", "github", "--issues-url", "https://ghe.example",
                                 "--issues-project", "a/b"], env=gh_env)  # fmt: skip
    assert r.exit_code == 2 and "http://ghe.example/api/v3" in _plain(r.output)
    r = CliRunner().invoke(app, ["watch", "--github-org", "acme"], env=gh_env)
    assert r.exit_code == 2 and "http://ghe.example/api/v3" in _plain(r.output) and "secret" not in r.output
    for kind in ("gitlab", "github"):  # an unreadable URL is a usage error, not a traceback ("Invalid IPv6 URL")
        r = CliRunner().invoke(app, ["scan", str(tmp_path), "--issues", kind, "--issues-url", "http://[::1",
                                     "--issues-project", "a/b"])  # fmt: skip
        assert r.exit_code == 2 and "not a URL" in _plain(r.output), kind
    for opt in ("--git", "--gitlab-group", "--gitea-org", "--github-org"):
        r = CliRunner().invoke(app, ["watch", opt, "http://[::1/a/b"])
        assert r.exit_code == 2 and "not a URL" in _plain(r.output), opt
    # allowed, or this machine: past the check (the run then stops at OSV-Scanner, which isn't there)
    for args, env in ((["watch", "--git", "http://git.example.org/a/b.git", "--allow-insecure-http"], {}),
                      (["watch", "--git", "http://git.example.org/a/b.git"], {"LIMBOWATCH_ALLOW_INSECURE_HTTP": "1"}),
                      (["watch", "--git", "http://127.0.0.1:3000/a/b.git"], {})):  # fmt: skip
        r = CliRunner().invoke(app, [*args, "--osv-scanner", "/nonexistent/osv-scanner"], env=env)
        assert "plain http" not in _plain(r.output), args


def test_security_and_data_names_every_host_and_option() -> None:
    """docs/WATCHER.md#security-and-data lists every host the scan can contact, and only options that exist, so the
    promise "nothing else leaves" can't drift from the code."""
    from urllib.parse import urlsplit

    from limbowatch.sources import cve, github, osv
    from limbowatch.watch import feedtrust, mapping, registries, scan, upstream_check

    doc = (Path(__file__).resolve().parent.parent / "docs/WATCHER.md").read_text()
    section = doc.split("## Security and data", 1)[1].split("\n## ", 1)[0]
    urls = [scan.FEED_URL, scan.WATCHLIST_URL, mapping.DEPS_DEV, mapping.RUBYGEMS, mapping.PACKAGIST,
            mapping.ECOSYSTEMS, mapping.MAVEN_CENTRAL, registries.BCR, registries.RAW, registries.CONAN_REMOTE,
            github.API, cve.CVE_API, osv.API, upstream_check.CLONE_URL.format(repo="o/r"),
            feedtrust.ATTESTATIONS.format(digest="0")]  # fmt: skip
    for host in {urlsplit(u).hostname for u in urls}:
        assert host in section, f"{host} isn't listed in WATCHER.md's Security and data"
    cli = typer.main.get_command(app)
    assert isinstance(cli, TyperGroup)
    options = {o for p in cli.commands["scan"].params for o in (*p.opts, *p.secondary_opts)}
    for opt in set(re.findall(r"`(--[a-z-]+)", section)):
        assert opt in options, f"{opt} is documented but `limbowatch scan` has no such option"


def test_cve_list_release_date_from_its_file_name() -> None:
    """track warns when the bulk export is older than the CVE delta a new tracker reads (F-216)."""
    from datetime import UTC, datetime

    from limbowatch_cli.main import _release_date

    assert _release_date("2026-11-17_all_CVEs_at_midnight.zip.zip") == datetime(2026, 11, 17, tzinfo=UTC)
    assert _release_date("all-cve_2026-10-25_0900Z.zip.zip") == datetime(2026, 10, 25, tzinfo=UTC)
    assert _release_date("all.zip.zip") is None and _release_date("2026-13-40_all.zip") is None
