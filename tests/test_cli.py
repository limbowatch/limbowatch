"""The command line exposes every command (a decorator moved onto a helper once hid `scan`)."""

import typer
from limbowatch_cli.main import app
from typer.core import TyperGroup


def test_every_command_is_registered() -> None:
    cli = typer.main.get_command(app)
    assert isinstance(cli, TyperGroup)
    assert {"track", "publish", "report", "inventory", "scan"} <= set(cli.commands)


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
