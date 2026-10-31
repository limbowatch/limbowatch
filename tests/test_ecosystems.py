"""Package-name cleaning (FINDINGS F-069): only fixes whose result is certain; the rest are flagged."""

import pytest
from limbowatch.ecosystems import package_name


@pytest.mark.parametrize(
    ("eco", "raw", "name", "valid"),
    [
        ("npm", "lodash", "lodash", True),
        ("npm", "@tak-ps/CloudTAK", "@tak-ps/CloudTAK", True),  # npm names are case-sensitive: kept
        ("npm", "application/modules/invoices/controllers/Invoices.php", None, False),
        ("pip", "GitPython", "gitpython", True),
        ("pip", "awslabs.dynamodb-mcp-server", "awslabs-dynamodb-mcp-server", True),
        ("pip", "https://github.com/reactive-firewall/multicast.git#egg=multicast", "multicast", True),
        ("composer", " baserproject/basercms ", "baserproject/basercms", True),
        ("composer", "givanz/Vvveb", "givanz/vvveb", True),
        ("composer", "WeGIA", "wegia", False),  # no vendor: can't be guessed
        ("go", " github.com/rancher/rancher", "github.com/rancher/rancher", True),
        ("go", "https://github.com/siyuan-note/siyuan", "github.com/siyuan-note/siyuan", True),
        (
            "go",
            "[github.com/theagentrouter/agent-router](https://github.com/theagentrouter/agent-router)",
            "github.com/theagentrouter/agent-router",
            True,
        ),
        ("go", "github.com/0xJacky/Nginx-UI", "github.com/0xJacky/Nginx-UI", True),  # module paths keep case
        ("go", "maximhq/bifrost", "maximhq/bifrost", False),  # no host: not guessed
        ("maven", " io.openremote:openremote-manager", "io.openremote:openremote-manager", True),
        ("maven", "io.dataease", "io.dataease", False),
        ("rust", "`nono-proxy` component of `nono`", None, False),
        ("swift", "https://github.com/apple/swift-nio.git", "github.com/apple/swift-nio", True),
        ("swift", "Sparkle", "Sparkle", False),
        ("actions", "https://github.com/owner/action", "owner/action", True),
    ],
)
def test_package_name(eco: str, raw: str, name: str | None, valid: bool) -> None:
    pn = package_name(eco, raw)
    assert pn is not None and pn.raw == raw and pn.valid is valid
    if name is not None:
        assert pn.name == name


def test_empty_names() -> None:
    assert package_name("npm", None) is None
    assert package_name("npm", "  ") is None
