# tests/test_is_external.py
"""
Covers PanoramaInventory.is_external():

- "any" in groups does NOT imply external
- EXT-INTERNET group implies external
- External zone membership implies external
- CIDRs outside internalPrefixes ⇒ external
- CIDRs inside internalPrefixes ⇒ not external
- Ranged dicts that straddle the boundary ⇒ external
- With no internalPrefixes configured, default to NOT external
"""

import ipaddress
import pytest

from ruleGenerator.core.inventory import PanoramaInventory


@pytest.fixture
def inv(monkeypatch, pano_stub):
    """
    Minimal PanoramaInventory with all refreshall() calls stubbed to return empty.
    Tests set _internalNets / _externalZones directly for clarity.
    """
    empty = lambda *_: []
    base = "ruleGenerator.core.inventory"
    monkeypatch.setattr(f"{base}.AddressObject.refreshall",        empty)
    monkeypatch.setattr(f"{base}.AddressGroup.refreshall",         empty)
    monkeypatch.setattr(f"{base}.ServiceObject.refreshall",        empty)
    monkeypatch.setattr(f"{base}.ServiceGroup.refreshall",         empty)
    monkeypatch.setattr(f"{base}.ApplicationObject.refreshall",    empty)
    monkeypatch.setattr(f"{base}.ApplicationGroup.refreshall",     empty)
    monkeypatch.setattr(f"{base}.ApplicationContainer.refreshall", empty)
    monkeypatch.setattr(f"{base}.DeviceGroup.refreshall",          empty)
    monkeypatch.setattr(f"{base}.Template.refreshall",             empty)

    inv = PanoramaInventory(pano_stub)
    inv._internalNets = []          # set per-test
    inv._externalZones = set()      # set per-test
    return inv


def _set_internal(inv, cidrs):
    inv._internalNets = [ipaddress.ip_network(c, strict=False) for c in cidrs]


def test_group_any_is_not_external(inv):
    _set_internal(inv, ["10.0.0.0/8"])
    assert inv.is_external(["10.1.2.0/24"], ["any"], None) is False


def test_ext_internet_group_is_external(inv):
    _set_internal(inv, ["10.0.0.0/8"])
    assert inv.is_external(["10.1.2.0/24"], ["EXT-INTERNET"], None) is True


def test_external_zone_marks_external(inv):
    _set_internal(inv, ["10.0.0.0/8"])
    inv._externalZones = {"untrust", "dmz"}
    # Case-insensitive zone match
    assert inv.is_external(["10.1.2.0/24"], [], ["Untrust"]) is True


def test_cidr_outside_internal_is_external(inv):
    _set_internal(inv, ["10.0.0.0/8"])
    assert inv.is_external(["8.8.8.8/32"], [], None) is True


def test_cidr_inside_internal_is_not_external(inv):
    _set_internal(inv, ["10.0.0.0/8"])
    assert inv.is_external(["10.1.2.0/24"], [], None) is False


def test_range_that_straddles_boundary_is_external(inv):
    _set_internal(inv, ["10.0.0.0/8"])
    rng = {"gte": "10.0.0.1", "lte": "11.0.0.1"}
    assert inv.is_external([rng], [], None) is True


def test_no_internal_config_defaults_to_not_external(inv):
    inv._internalNets = []
    inv._externalZones = set()
    # With no explicit external hints, be conservative (not external)
    assert inv.is_external(["1.2.3.4/32"], [], None) is False
