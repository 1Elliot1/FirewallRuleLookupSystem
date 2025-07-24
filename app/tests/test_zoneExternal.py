# tests/test_zone_external.py
"""
Covers **external / internal-net handling** in the new modular stack.

1.  _cidr_complement()           – pure helper (unchanged algorithm)
2.  apply_static_overrides()     – populates
        • inv._internalNets
        • inv._externalZones
        • EXT-INTERNET address/group synthesis
"""

from types import SimpleNamespace
import ipaddress
import textwrap

import pytest

# core helpers under test ----------------------------------------------------
from ruleGenerator.core.inventory import PanoramaInventory
from ruleGenerator.core.overrides import _cidr_complement, apply_static_overrides


# ----------------------------------------------------------------------------
# _cidr_complement -- quick sanity check
# ----------------------------------------------------------------------------
def test_cidr_complement_simple_halves():
    # lower half removed ⇒ only upper half stays
    assert _cidr_complement(["0.0.0.0/1"]) == ["128.0.0.0/1"]


def test_cidr_complement_excludes_originals():
    inside = ["10.0.0.0/8"]
    comp = _cidr_complement(inside)
    # no block we just passed in should re-appear in the complement
    assert not any(ipaddress.ip_network(c).subnet_of(ipaddress.ip_network("10.0.0.0/8"))
                   for c in comp)


# ----------------------------------------------------------------------------
# apply_static_overrides – internal/external caches & synth objects
# ----------------------------------------------------------------------------
_INTERNALS = ["10.0.0.0/8", "2001:db8:abcd::/48"]


@pytest.fixture
def inv(monkeypatch, pano_stub, tmp_path):
    """
    Minimal PanoramaInventory with an overrides YAML that defines
    *internalPrefixes* and *externalZones*.
    """
    # --- keep raw inventory empty -----------------------------------------
    empty = lambda *_: []
    base   = "ruleGenerator.core.inventory"
    monkeypatch.setattr(f"{base}.AddressObject.refreshall",   empty)
    monkeypatch.setattr(f"{base}.AddressGroup.refreshall",    empty)
    monkeypatch.setattr(f"{base}.DeviceGroup.refreshall",     empty)
    monkeypatch.setattr(f"{base}.Template.refreshall",        empty)
    monkeypatch.setattr(f"{base}.ApplicationObject.refreshall", empty)
    monkeypatch.setattr(f"{base}.ApplicationGroup.refreshall",  empty)
    monkeypatch.setattr(f"{base}.ApplicationContainer.refreshall", empty)
    monkeypatch.setattr(f"{base}.ServiceObject.refreshall",   empty)
    monkeypatch.setattr(f"{base}.ServiceGroup.refreshall",    empty)

    # --- Inventory --------------------------------------------------------
    inv = PanoramaInventory(pano_stub)

    # --- overrides.yml ----------------------------------------------------
    yaml_path = tmp_path / "overrides.yml"
    yaml_path.write_text(textwrap.dedent(f"""
        internalPrefixes:
          - {_INTERNALS[0]}
          - {_INTERNALS[1]}
        externalZones:
          - DMZ
    """))

    apply_static_overrides(inv, yaml_path)
    return inv


def test_internal_and_external_caches(inv):
    # _internalNets  -------------------------------------------------------
    nets = {n.with_prefixlen for n in inv._internalNets}
    assert set(_INTERNALS).issubset(nets)

    # _externalZones  ------------------------------------------------------
    assert inv._externalZones == {"dmz"}

    # EXT-INTERNET object & group synthesised -----------------------------
    assert "EXT-INTERNET" in inv.addressObjectByName
    assert "EXT-INTERNET" in inv.addressGroupByName
