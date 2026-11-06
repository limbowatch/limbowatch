"""The command line exposes every command (a decorator moved onto a helper once hid `scan`)."""

from limbowatch_cli.main import app
from typer.testing import CliRunner


def test_every_command_is_registered() -> None:
    out = CliRunner().invoke(app, ["--help"], env={"COLUMNS": "200"}).output
    for cmd in ("track", "publish", "report", "inventory", "scan"):
        assert f" {cmd} " in out, cmd
