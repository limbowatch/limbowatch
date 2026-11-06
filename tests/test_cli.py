"""The command line exposes every command (a decorator moved onto a helper once hid `scan`)."""

import typer
from limbowatch_cli.main import app
from typer.core import TyperGroup


def test_every_command_is_registered() -> None:
    cli = typer.main.get_command(app)
    assert isinstance(cli, TyperGroup)
    assert {"track", "publish", "report", "inventory", "scan"} <= set(cli.commands)
