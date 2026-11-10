import pytest
from limbowatch.versions import affected, already_fixed, go_relation, osv_ranges

# Ranges as maintainers actually wrote them (FINDINGS F-030, F-044)
CASES = [
    ("npm", "1.5.0", ">= 1.0.0, < 1.2.3", False),
    ("npm", "1.1.0", ">= 1.0.0, < 1.2.3", True),
    ("npm", "6.0.0", ">=5.0.0-beta.0 <7.1.0", True),
    ("npm", "8.0.0-beta.1", "8.0.0-alpha.0 - 8.0.0-rc.5", True),
    ("npm", "1.20.0", "=>0.31.1", True),
    ("pip", "1.4.0", ">=1.3.3 and <= 1.4.1", True),
    ("pip", "1.7.4", "1.7.4", True),
    ("npm", "1.2.9", "^1.2.3", True),
    ("npm", "2.0.0", "^1.2.3", False),
    ("npm", "3.0.1", "<2.0.0 || >=3.0.0 <3.0.2", True),
    ("go", "v5.3.2", "<=5.4.0", True),
    ("pip", "0.0.29", ">= 0.0.1a9, < 0.0.84", True),
    ("pip", "12.3.0", "≤ 12.2.0", False),
    ("pip", "0.14.0", "0.15.0 and earlier", True),
    ("npm", "6.28.0", "< 6.24.0; 7.0.0 < 7.24.0", False),
    ("npm", "7.10.0", "< 6.24.0; 7.0.0 < 7.24.0", True),
    ("npm", "5.0.6", "<1.1.17, >= 2.0.0 < 2.1.3, >= 3.0.0 < 3.0.3, 4.0.0 - 5.0.7", True),
    ("npm", "3.5.0", "<1.1.17, >= 2.0.0 < 2.1.3, >= 3.0.0 < 3.0.3, 4.0.0 - 5.0.7", False),
    ("pip", "2.13.4", "all", True),  # all versions (F-069)
    ("npm", "1.0.0", None, None),
]


@pytest.mark.parametrize(("eco", "version", "rng", "expected"), CASES)
def test_affected(eco: str, version: str, rng: str | None, expected: bool | None) -> None:
    assert affected(eco, version, rng) is expected


@pytest.mark.parametrize(
    ("eco", "version", "patched", "expected"),
    [
        ("rust", "0.11.19", "0.11.17", True),  # range said ">= 0.11.15" with no upper bound
        ("go", "v4.1.4", "v4.1.4", True),
        ("rust", "2.3.0", "<= 2.3.0", None),
        ("npm", "0.27.10", "0.24.52 0.25.25 0.26.9 0.27.12 0.28.22", False),  # per-branch fixes
        ("npm", "0.27.13", "0.26.9 0.27.12", True),
        ("pip", "3.1.50", ">= 3.2.0", False),
    ],
)
def test_already_fixed(eco: str, version: str, patched: str, expected: bool | None) -> None:
    assert already_fixed(eco, version, patched) is expected


def test_versions_are_never_compared_as_strings() -> None:
    assert affected("npm", "1.10.0", "< 1.9.0") is False  # "1.10.0" < "1.9.0" as strings
    assert affected("pip", "10.0", ">= 9.0") is True


@pytest.mark.parametrize(
    ("advisory", "module", "expected"),
    [
        ("github.com/pelletier/go-toml/v2", "github.com/pelletier/go-toml", "major_version_variant"),
        ("github.com/dlclark/regexp2", "github.com/dlclark/regexp2/v2", "major_version_variant"),
        ("github.com/foo/bar/pkg/x", "github.com/foo/bar", "package_in_module"),
        ("github.com/foo/bar", "github.com/foo/bar", "same"),
        ("github.com/foo/bar", "github.com/foo/bar/sdk", None),
    ],
)
def test_go_relation(advisory: str, module: str, expected: str | None) -> None:
    assert go_relation(advisory, module) == expected


def test_osv_ranges_semver() -> None:
    assert osv_ranges("npm", ">= 1.0.0, < 1.2.3") == (
        [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.3"}]}],
        [],
    )


def test_osv_ranges_upper_only_and_last_affected() -> None:
    ranges, _ = osv_ranges("go", "<= 2.4.2") or ([], [])
    assert ranges == [{"type": "SEMVER", "events": [{"introduced": "0"}, {"last_affected": "2.4.2"}]}]


def test_osv_ranges_pypi_is_ecosystem_type_and_versions_enumerated() -> None:
    ranges, versions = osv_ranges("pip", "< 1.0; 1.7.4") or ([], [])
    assert ranges == [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0"}]}]
    assert versions == ["1.7.4"]


def test_osv_ranges_refuses_what_osv_cannot_express() -> None:
    assert osv_ranges("npm", "> 1.0.0, < 2.0.0") is None  # strict lower bound


def test_osv_ranges_open_range_closed_by_patched_version() -> None:
    # GHSA-xmpp-f9v3-r7qh: affected ">= 4.29.0", patched ">=4.32.0"
    assert osv_ranges("npm", ">= 4.29.0", ">=4.32.0") == (
        [{"type": "SEMVER", "events": [{"introduced": "4.29.0"}, {"fixed": "4.32.0"}]}],
        [],
    )
    assert osv_ranges("pip", ">= 1.0", "1.7.2") == (
        [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "1.7.2"}]}],
        [],
    )
    # per-branch fixes: the one on the range's own line applies
    ranges, _ = osv_ranges("npm", ">= 2.3.0", "1.9.9, 2.3.5") or ([], [])
    assert ranges[0]["events"] == [{"introduced": "2.3.0"}, {"fixed": "2.3.5"}]
    # a fix below the range's start, ambiguous per-branch fixes or an unreadable fixed field: not
    # converted, since an open range would mark the fix itself as affected (F-069)
    assert osv_ranges("npm", ">= 4.29.0", "4.1.0") is None
    assert osv_ranges("npm", ">= 1.0.0", "1.5.0, 2.5.0") is None
    assert osv_ranges("pip", ">= 0.2.1", "< 0.2.2") is None
    # no fix stated: open is right
    for none in (None, "", "None", "N/A", "tbd", "None — migrate to x", "Will not fix"):
        assert osv_ranges("npm", ">= 1.0.0", none) == ([{"type": "SEMVER", "events": [{"introduced": "1.0.0"}]}], [])
    # an explicit upper bound wins over the patched field
    ranges, _ = osv_ranges("npm", ">= 1.0.0, < 1.2.3", "1.4.0") or ([], [])
    assert ranges[0]["events"] == [{"introduced": "1.0.0"}, {"fixed": "1.2.3"}]


def test_more_range_forms() -> None:
    """Forms maintainers type that have one meaning (F-069)."""
    assert osv_ranges("pip", "All", "1.106.0") == (
        [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.106.0"}]}],
        [],
    )
    assert osv_ranges("pip", ">=3.0.0 & <=3.2.1") == (
        [{"type": "ECOSYSTEM", "events": [{"introduced": "3.0.0"}, {"last_affected": "3.2.1"}]}],
        [],
    )
    ranges, _ = osv_ranges("go", ">= v0.27.0 && < v0.55.1") or ([], [])
    assert ranges[0]["events"] == [{"introduced": "0.27.0"}, {"fixed": "0.55.1"}]
    ranges, _ = osv_ranges("nuget", ">= 2.1.0, < 3.0.0; 3.0.0 to 3.2.1; 4.0.0 through 4.0.2") or ([], [])
    assert [r["events"] for r in ranges][1:] == [
        [{"introduced": "3.0.0"}, {"last_affected": "3.2.1"}],
        [{"introduced": "4.0.0"}, {"last_affected": "4.0.2"}],
    ]
    assert osv_ranges("composer", "1.11.12, 1.11.14, 1.11.16") == ([], ["1.11.12", "1.11.14", "1.11.16"])
    assert (
        osv_ranges("rust", "0.25.0 .. 0.26.0") is None
    )  # ambiguous: Rust's ".." excludes its end, maintainers often don't


def test_fixed_versions() -> None:
    from limbowatch.versions import fixed_versions

    assert fixed_versions("1.2.3") == ["1.2.3"]
    assert fixed_versions(">= 0.5.16, >= 0.6.3") == ["0.5.16", "0.6.3"]
    assert fixed_versions("=> 26.09.2") == ["26.09.2"]
    assert fixed_versions("V1.0.3") == ["v1.0.3"]
    assert fixed_versions("3.2.2; 4.0.3") == ["3.2.2", "4.0.3"]
    for text in ("< 2.5.1", "tbd", "main", "c86e4cb9ce7546324970ceb6e85ad7001df4318c", None, ""):
        assert fixed_versions(text) is None, text


def test_exact_version_beside_a_bound_is_an_alternative() -> None:
    from limbowatch.versions import affected

    assert affected("npm", "3.0.10", "<= 3.0.10, 4.0.0") is True  # live range of GHSA-jf9x-2fg2-hx4w
    assert affected("npm", "4.0.0", "<= 3.0.10, 4.0.0") is True
    assert affected("npm", "3.5.0", "<= 3.0.10, 4.0.0") is False
    assert affected("npm", "1.5.0", ">= 1.0.0, < 2.0.0") is True  # an ordinary AND is unchanged


def test_commas_read_as_or_keep_each_interval_whole() -> None:
    """Re-reading commas as OR pairs each lower bound with the upper bound after it; equal inclusive bounds are
    one version, not a contradiction (F-123). Each of these used to cover every version."""
    from limbowatch.versions import affected, alternatives, osv_ranges

    two = ">= 2.2.0, < 2.2.10, >= 2.3.0, < 2.3.7"  # GHSA-5p7c-hggf-c748
    assert alternatives("go", two) == [[(">=", "2.2.0"), ("<", "2.2.10")], [(">=", "2.3.0"), ("<", "2.3.7")]]
    assert [affected("go", v, two) for v in ("2.1.0", "2.2.5", "2.2.12", "2.3.1", "2.3.7")] == [
        False, True, False, True, False,
    ]  # fmt: skip
    assert osv_ranges("rust", ">=4.1.0, <4.1.7, >=4.2.0, <4.2.3", "4.2.3, 4.1.7") == (
        [
            {"type": "SEMVER", "events": [{"introduced": "4.1.0"}, {"fixed": "4.1.7"}]},
            {"type": "SEMVER", "events": [{"introduced": "4.2.0"}, {"fixed": "4.2.3"}]},
        ],
        [],
    )
    one = ">= 3.8.8, <= 3.8.8"  # GHSA-4mwh-6232-9frp
    assert alternatives("npm", one) == [[(">=", "3.8.8"), ("<=", "3.8.8")]]
    assert [affected("npm", v, one) for v in ("3.8.7", "3.8.8", "3.8.9")] == [False, True, False]
    assert affected("npm", "3.8.8", "> 3.8.8, <= 3.8.8") is None  # contradictory either way: can't be evaluated
    assert affected("go", "0.6.0", "< 0.6.2, >= 0.7.0 < 0.7.2") is True  # a leading upper bound stays alone
    assert affected("go", "0.6.5", "< 0.6.2, >= 0.7.0 < 0.7.2") is False


def test_wildcard_versions_are_intervals() -> None:
    """A wildcard such as "2.16.*" used to parse as "= 2.16." and match nothing (F-123)."""
    from limbowatch.versions import affected, alternatives

    assert alternatives("composer", "2.16.*,>=3.9.0,<3.26.0") == [
        [(">=", "2.16.0"), ("<", "2.17.0")],
        [(">=", "3.9.0"), ("<", "3.26.0")],
    ]
    assert affected("composer", "2.16.5", "2.16.*,>=3.9.0,<3.26.0") is True
    assert affected("composer", "3.0.0", "2.16.*,>=3.9.0,<3.26.0") is False
    assert affected("npm", "5.3.1", "5.*") is True
    assert affected("npm", "6.0.0", "5.x") is False
    assert affected("npm", "2.9.0", "<= 2.*") is True
    assert affected("npm", "3.0.0", "<= 2.*") is False
    assert affected("npm", "1.9.9", ">= 1.0.0, < 2.*") is True
    assert alternatives("npm", ">=v2.0.1-beta.0, <=v2.0.0-rc.8") is None  # reversed bounds: can't be evaluated


def test_intervals_without_commas_between_them() -> None:
    from limbowatch.versions import affected, alternatives

    r = ">= 2.8.0, < 2.8.8 >= 2.9.0, < 2.9.6 >= 2.10.0, < 2.10.8"
    assert alternatives("composer", r) == [
        [(">=", "2.8.0"), ("<", "2.8.8")],
        [(">=", "2.9.0"), ("<", "2.9.6")],
        [(">=", "2.10.0"), ("<", "2.10.8")],
    ]
    r = ">= 4.4.0, < 4.4.8 and >= 4.5.0, < 4.5.4"
    assert [affected("pip", v, r) for v in ("4.4.7", "4.4.9", "4.5.3", "4.5.4")] == [True, False, True, False]
    assert alternatives("npm", ">= 0.11.0, < 0.6.10") is None  # reversed bounds


def test_composer_orders_four_part_and_patch_versions() -> None:
    """univers read a fourth part as build metadata: 6.7.13.0 was neither below nor equal to 6.7.13.1 (F-123)."""
    from limbowatch.versions import affected

    r = ">=6.7.0.0 <6.7.13.1"  # Shopware-style
    assert [affected("composer", v, r) for v in ("6.7.0.0", "6.7.13.0", "6.7.13.1", "6.7.14.0")] == [
        True, True, False, False,
    ]  # fmt: skip
    assert affected("composer", "1.7.53.4", ">= 1.7.53, < 1.7.53.5") is True
    assert affected("composer", "v1.2", "= 1.2.0") is True
    assert affected("composer", "2.0.0-RC1", "< 2.0.0") is True
    assert affected("composer", "2.0.0-beta2", ">= 2.0.0-alpha1, < 2.0.0-RC1") is True
    assert affected("composer", "1.0.0-patch1", "<= 1.0.0") is False
    assert affected("composer", "dev-main", "< 2.0.0") is None


def test_comma_parts_that_together_cover_every_version_cant_be_evaluated() -> None:
    from limbowatch.versions import alternatives

    assert alternatives("nuget", ">= 9.0.0, < 9.0.0 >= 8.0.0, < 8.0.11") is None
    assert alternatives("maven", ">= 0.11.0, 0 < 0.18.5") is None
    # ordinary readings are kept
    assert alternatives("composer", "< 19.4.6, 20 < 20.0.2") == [[("<", "19.4.6")], [(">=", "20"), ("<", "20.0.2")]]
    assert alternatives("npm", "< 1.5.0, >= 2.0.0") == [[("<", "1.5.0")], [(">=", "2.0.0")]]
    assert alternatives("go", "1.4.0~1.4.10, 1.5.0~1.5.2") == [
        [(">=", "1.4.0"), ("<=", "1.4.10")],
        [(">=", "1.5.0"), ("<=", "1.5.2")],
    ]
    assert alternatives("npm", "~1.2.3") == [[(">=", "1.2.3"), ("<", "1.3.0")]]


def test_hyphen_spans_without_spaces() -> None:
    """Packagist advisories often write "11.0.0-11.5.50"; read as one pre-release, it matched nothing (F-123)."""
    from limbowatch.versions import affected

    r = "<10.4.57, 11.0.0-11.5.50, 12.0.0-12.4.45"
    assert [affected("composer", v, r) for v in ("10.4.56", "11.2.0", "11.5.51", "12.4.45", "12.4.46")] == [
        True, True, False, True, False,
    ]  # fmt: skip
    assert affected("composer", "3.6.6.1", "<=3.5.8.1, 3.6.0-3.6.6.1") is True
    assert affected("npm", "1.0.0-0.3.7", "= 1.0.0-0.3.7") is True  # a numeric pre-release stays one version
    assert affected("maven", "3.0-20251107.114627", "< 3.0-20251107.114628") is True  # a timestamped version
