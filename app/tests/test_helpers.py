# pure functions, no Panorama needed

# tests/test_helpers.py
import pytest
import ipaddress
from ruleGenerator.core.inventory import ip_in_cidr as _ip_in_cidr
from ruleGenerator.core.metrics import _subset, _cidrs_cover
from ruleGenerator.core.overrides import _cidr_complement

# ---------------------------------------------------------------------------
# _ip_in_cidr  ───────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "ip, cidr, expected",
    [
        # ── happy IPv4 ──────────────────────────────────────────────────────
        ("10.1.0.5",  "10.1.0.0/24",      True),
        ("10.2.0.5",  "10.1.0.0/24",      False),
        ("10.1.0.0/25", "10.1.0.0/24",    True),
        ("10.1.0.0/23", "10.1.0.0/24",    False),

        # ── happy IPv6 ──────────────────────────────────────────────────────
        ("2001:db8::1",      "2001:db8::/64",  True),
        ("2001:db8:1::1",    "2001:db8::/64",  False),

        # ── catch-all & error handling ─────────────────────────────────────
        ("10.1.0.5",  "0.0.0.0/0",        False),   # /0 is ignored
        ("not_an_ip", "10.1.0.0/24",      False),   # invalid subject
        ("10.1.0.5",  "not_a_cidr",       False),   # invalid container
    ],
)
def test_ip_in_cidr(ip, cidr, expected):
    assert _ip_in_cidr(ip, cidr) is expected


# ---------------------------------------------------------------------------
# PanoramaData._subset  ─────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "needle, haystack, expected",
    [
        ([],          ["X"],               True),   # empty == wildcard
        (["a"],       ["any"],             True),   # haystack wildcard
        (["a", "b"],  ["a", "b", "c"],     True),
        (["a", "b"],  ["b", "c"],          False),
    ],
)
def test_subset(needle, haystack, expected):
    assert _subset(needle, haystack) is expected


# ---------------------------------------------------------------------------
# PanoramaData._cidrs_cover  ────────────────────────────────────────────────
CIDR = lambda s: s            # readability helper
RNG  = lambda lo, hi: {"gte": lo, "lte": hi}

@pytest.mark.parametrize(
    "child, parent, expected",
    [
        # basic CIDR containment
        ([CIDR("10.1.0.0/24")],
         [CIDR("10.1.0.0/16")],
         True),

        # child wider than parent
        ([CIDR("10.1.0.0/16")],
         [CIDR("10.1.0.0/24")],
         False),

        # parent wildcard
        ([CIDR("10.1.0.0/24")],
         ["any"],
         True),

        # empty child list == wildcard
        ([], [CIDR("0.0.0.0/0")], True),

        # range fully inside parent CIDR
        ([RNG("10.1.0.5", "10.1.0.20")],
         [CIDR("10.1.0.0/24")],
         True),

        # range partially outside parent CIDR
        ([RNG("10.1.0.5", "10.1.1.5")],
         [CIDR("10.1.0.0/24")],
         False),

        # child CIDR inside parent range
        ([CIDR("10.1.0.0/25")],
         [RNG("10.1.0.0", "10.1.0.255")],
         True),

        # IPv6 mix
        ([CIDR("2001:db8::/126")],
         [CIDR("2001:db8::/120")],
         True),
    ],
)
def test_cidrs_cover(child, parent, expected):
    assert _cidrs_cover(child, parent) is expected


# ---------------------------------------------------------------------------
# ADDITIONAL edge-cases 
# ---------------------------------------------------------------------------

# --- _subset : empty haystack ------------------------------------------------
def test_subset_empty_haystack():
    assert _subset(["a"], []) is False


# --- _ip_in_cidr : version mismatch ------------------------------------------
@pytest.mark.parametrize(
    "ip, cidr",
    [
        ("10.1.1.1",        "2001:db8::/64"),   # v4 inside v6
        ("2001:db8::1",     "10.0.0.0/8"),      # v6 inside v4
    ]
)
def test_ip_in_cidr_version_mismatch(ip, cidr):
    assert _ip_in_cidr(ip, cidr) is False


# --- _cidrCompliment ---------------------------------------------------------

def test_cidr_complement_simple_halves():
    # "0.0.0.0/1" is the lower half; complement should be the upper half
    comp = _cidr_complement(["0.0.0.0/1"])
    assert comp == ["128.0.0.0/1"]

    # IPv6 analogue
    comp6 = _cidr_complement(["::/1"])
    assert comp6 == ["8000::/1"]


def test_cidr_complement_excludes_originals():
    internal = ["10.0.0.0/8"]
    comp = _cidr_complement(internal)

    # No overlap between internal net and any complement net
    internal_net = ipaddress.ip_network("10.0.0.0/8")
    for c in comp:
        assert not internal_net.overlaps(ipaddress.ip_network(c))