# tests/test_inventory_maps.py
"""
Covers:
    • _refresh_inventory
    • _build_fast_maps
    • nested_objects_in_network / expand_address_groups helpers

Relies on fixtures from tests/conftest.py:
    - pano_stub  (fake Panorama connection)
"""

from types import SimpleNamespace
import ipaddress

from ruleGenerator.core.inventory import PanoramaInventory as PanoramaData
from tests.conftest import AO, AG

BASE = "ruleGenerator.core.inventory"        # convenience for monkey-patches


# ---------------------------------------------------------------------------
# helper that wires predictable dummy inventory into refreshall() stubs
# ---------------------------------------------------------------------------
def _build_inventory(monkeypatch):
    ao1 = AO("NET1", "192.168.10.0/24")
    ao2 = AO("NET2", "192.168.20.0/24")
    ao_bad = AO("BROKEN", "not_a_cidr")          # should be ignored by _nets

    ag1 = AG("GROUP1", ["NET1", "NET2"])

    monkeypatch.setattr(f"{BASE}.AddressObject.refreshall",
                        lambda *_: [ao1, ao2, ao_bad])
    monkeypatch.setattr(f"{BASE}.AddressGroup.refreshall",
                        lambda *_: [ag1])

    # all other object types → empty list
    empty = lambda *_: []
    monkeypatch.setattr(f"{BASE}.DeviceGroup.refreshall",          empty)
    monkeypatch.setattr(f"{BASE}.Template.refreshall",             empty)
    monkeypatch.setattr(f"{BASE}.ApplicationObject.refreshall",    empty)
    monkeypatch.setattr(f"{BASE}.ApplicationGroup.refreshall",     empty)
    monkeypatch.setattr(f"{BASE}.ApplicationContainer.refreshall", empty)
    monkeypatch.setattr(f"{BASE}.ServiceObject.refreshall",        empty)
    monkeypatch.setattr(f"{BASE}.ServiceGroup.refreshall",         empty)

    return ao1, ao2, ao_bad, ag1


# ---------------------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------------------
def test_inventory_lists_and_maps(monkeypatch, pano_stub):
    ao1, ao2, ao_bad, ag1 = _build_inventory(monkeypatch)

    pdata = PanoramaData(pano_stub)

    # --- raw lists ---------------------------------------------------------
    assert pdata.addressObjects == [ao1, ao2, ao_bad]
    assert pdata.addressGroups == [ag1]

    # --- fast look-up maps -------------------------------------------------
    assert pdata.addressObjectByName["NET1"] is ao1
    assert pdata.addressGroupByName["GROUP1"] is ag1

    # --- address-to-group map ---------------------------------------------
    assert pdata._addrToGroup["NET1"] == ["GROUP1"]
    assert pdata._addrToGroup["NET2"] == ["GROUP1"]

    # --- _nets only contains valid CIDRs ----------------------------------
    nets_dict = {name: net for net, name in pdata._nets}
    assert nets_dict["NET1"] == ipaddress.ip_network("192.168.10.0/24")
    assert nets_dict["NET2"] == ipaddress.ip_network("192.168.20.0/24")
    assert "BROKEN" not in nets_dict


def test_nested_objects_in_network(monkeypatch, pano_stub):
    """NET1 (/24) contains NET1_SUB (/25) but not NET2 (different /24)."""
    ao_parent = AO("NET1", "10.0.0.0/24")
    ao_child  = AO("NET1_SUB", "10.0.0.0/25")
    ao_else   = AO("NET2", "10.0.1.0/24")

    monkeypatch.setattr(f"{BASE}.AddressObject.refreshall",
                        lambda *_: [ao_parent, ao_child, ao_else])
    monkeypatch.setattr(f"{BASE}.AddressGroup.refreshall",
                        lambda *_: [AG('DUMMY', [])])      # unused here

    pdata = PanoramaData(pano_stub)

    nested = pdata.nested_objects_in_network("10.0.0.0/24")
    assert nested == ("NET1_SUB",)


def test_object_belonging_to_multiple_groups(monkeypatch, pano_stub):
    ao  = AO("WEB_NET", "172.16.0.0/24")
    agA = AG("SERVERS", ["WEB_NET"])
    agB = AG("DMZ",     ["WEB_NET"])

    monkeypatch.setattr(f"{BASE}.AddressObject.refreshall", lambda *_: [ao])
    monkeypatch.setattr(f"{BASE}.AddressGroup.refreshall",  lambda *_: [agA, agB])

    pdata = PanoramaData(pano_stub)

    assert pdata.addressObjects == [ao]
    assert set(pdata._addrToGroup["WEB_NET"]) == {"SERVERS", "DMZ"}


def test_expand_address_groups_recursion_and_circular(monkeypatch, pano_stub):
    ag_leaf = AG("LEAF", [])
    ag_mid  = AG("MID",  ["LEAF"])
    ag_root = AG("ROOT", ["MID"])
    ag_leaf.static_value.append("ROOT")          # circular ref

    monkeypatch.setattr(f"{BASE}.AddressObject.refreshall", lambda *_: [])
    monkeypatch.setattr(f"{BASE}.AddressGroup.refreshall",
                        lambda *_: [ag_leaf, ag_mid, ag_root])

    pdata = PanoramaData(pano_stub)

    assert pdata.expand_address_groups("ROOT") == []
    assert set(pdata.all_nested_group_names("ROOT")) == {"ROOT", "MID", "LEAF"}


def test_nets_handles_ipv6(monkeypatch, pano_stub):
    ao_big = AO("V6_BIG", "2001:db8::/64")
    ao_sub = AO("V6_SUB", "2001:db8::/80")

    monkeypatch.setattr(f"{BASE}.AddressObject.refreshall", lambda *_: [ao_big, ao_sub])
    monkeypatch.setattr(f"{BASE}.AddressGroup.refreshall",  lambda *_: [])

    pdata = PanoramaData(pano_stub)

    nested = pdata.nested_objects_in_network("2001:db8::/64")
    assert nested == ("V6_SUB",)


def test_build_fast_maps_scalability(monkeypatch, pano_stub):
    """Large inventory spot-check to guard against O(n²) surprises."""
    big = [AO(f"N{i}", f"10.{i//256}.{i%256}.0/24") for i in range(2_000)]

    monkeypatch.setattr(f"{BASE}.AddressObject.refreshall", lambda *_: big)
    monkeypatch.setattr(f"{BASE}.AddressGroup.refreshall",  lambda *_: [])

    pdata = PanoramaData(pano_stub)

    # sample a few objects
    assert pdata.addressObjectByName["N0"].value    == "10.0.0.0/24"
    assert pdata.addressObjectByName["N1999"].value == "10.7.207.0/24"

    # every AddressObject should appear in _nets unless its CIDR was invalid
    net_names = {name for _, name in pdata._nets}
    assert len(net_names) >= len(pdata.addressObjects)
    for ao in big:
        assert ao.name in net_names
