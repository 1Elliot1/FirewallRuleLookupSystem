# _refreshPanoramaInventory + _buildFastMaps
# tests/test_inventory_maps.py
"""
Covers:
    • _refreshPanoramaInventory
    • _buildFastMaps

Relies on fixtures from tests/conftest.py:
    - pano_stub  (fake Panorama object)
"""

from types import SimpleNamespace
import ipaddress
import pytest
from ruleGenerator.src.panoramaData import PanoramaData


# helper constructors (mirror the ones in conftest, redefine locally for clarity)
AO = lambda n, v: SimpleNamespace(name=n, value=v)
AG = lambda n, members: SimpleNamespace(name=n, static_value=list(members))


def _build_inventory(monkeypatch):
    """Return two address objects + one group and patch refreshall() accordingly."""
    ao1 = AO("NET1", "192.168.10.0/24")
    ao2 = AO("NET2", "192.168.20.0/24")
    ao_bad = AO("BROKEN", "not_a_cidr")           # should be ignored by _nets

    ag1 = AG("GROUP1", ["NET1", "NET2"])

    monkeypatch.setattr("ruleGenerator.src.panoramaData.AddressObject.refreshall",
                        lambda *_: [ao1, ao2, ao_bad])
    monkeypatch.setattr("ruleGenerator.src.panoramaData.AddressGroup.refreshall",
                        lambda *_: [ag1])

    # keep other refreshall calls empty
    empty = lambda *_: []
    monkeypatch.setattr("ruleGenerator.src.panoramaData.DeviceGroup.refreshall",         empty)
    monkeypatch.setattr("ruleGenerator.src.panoramaData.Template.refreshall",            empty)
    monkeypatch.setattr("ruleGenerator.src.panoramaData.ApplicationObject.refreshall",   empty)
    monkeypatch.setattr("ruleGenerator.src.panoramaData.ApplicationGroup.refreshall",    empty)
    monkeypatch.setattr("ruleGenerator.src.panoramaData.ApplicationContainer.refreshall", empty)
    monkeypatch.setattr("ruleGenerator.src.panoramaData.ServiceObject.refreshall",       empty)
    monkeypatch.setattr("ruleGenerator.src.panoramaData.ServiceGroup.refreshall",        empty)

    return ao1, ao2, ao_bad, ag1


# ---------------------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------------------

def test_inventory_lists_and_maps(monkeypatch, pano_stub):
    ao1, ao2, ao_bad, ag1 = _build_inventory(monkeypatch)

    pdata = PanoramaData(pano_stub)

    # --- Lists -----------------------------------------------------
    assert pdata.addressObjects == [ao1, ao2, ao_bad]
    assert pdata.addressGroups == [ag1]

    # --- Fast maps -------------------------------------------------
    assert pdata.addressObjectByName["NET1"] is ao1
    assert pdata.addressGroupByName["GROUP1"] is ag1

    # --- _addrToGroup contents ------------------------------------
    assert pdata._addrToGroup["NET1"] == ["GROUP1"]
    assert pdata._addrToGroup["NET2"] == ["GROUP1"]

    # --- _nets contains only valid CIDRs --------------------------
    nets_dict = {name: net for net, name in pdata._nets}
    assert nets_dict["NET1"] == ipaddress.ip_network("192.168.10.0/24")
    assert nets_dict["NET2"] == ipaddress.ip_network("192.168.20.0/24")
    # invalid object not inserted
    assert "BROKEN" not in nets_dict


def test_nested_objects_in_network(monkeypatch, pano_stub):
    """
    Indirectly checks that _nets is complete by using nestedObjectsInNetwork().
    NET1 (24) contains NET1_SUB (25) but not NET2 (different /24).
    """
    ao_parent = AO("NET1", "10.0.0.0/24")
    ao_child  = AO("NET1_SUB", "10.0.0.0/25")
    ao_else   = AO("NET2", "10.0.1.0/24")
    ag_dummy  = AG("DUMMY", [])

    monkeypatch.setattr("ruleGenerator.src.panoramaData.AddressObject.refreshall",
                        lambda *_: [ao_parent, ao_child, ao_else])
    monkeypatch.setattr("ruleGenerator.src.panoramaData.AddressGroup.refreshall",
                        lambda *_: [ag_dummy])  # not used here

    pdata = PanoramaData(pano_stub)

    nested = pdata.nestedObjectsInNetwork("10.0.0.0/24")
    assert nested == ("NET1_SUB",)

def test_object_belonging_to_multiple_groups(monkeypatch, pano_stub):
    ao = AO("WEB_NET", "172.16.0.0/24")
    agA = AG("SERVERS", ["WEB_NET"])
    agB = AG("DMZ",     ["WEB_NET"])

    monkeypatch.setattr("ruleGenerator.src.panoramaData.AddressObject.refreshall",
                        lambda *_: [ao])
    monkeypatch.setattr("ruleGenerator.src.panoramaData.AddressGroup.refreshall",
                        lambda *_: [agA, agB])

    pdata = PanoramaData(pano_stub)

    # appears once in list
    assert pdata.addressObjects == [ao]

    # but two groups reference it
    assert set(pdata._addrToGroup["WEB_NET"]) == {"SERVERS", "DMZ"}

def test_expandAddressGroups_recursion_and_circular(monkeypatch, pano_stub):
    ag_leaf  = AG("LEAF", [])
    ag_mid   = AG("MID", ["LEAF"])
    ag_root  = AG("ROOT", ["MID"])
    # Introduce circular reference: LEAF points back to ROOT
    ag_leaf.static_value.append("ROOT")

    monkeypatch.setattr("ruleGenerator.src.panoramaData.AddressObject.refreshall",
                        lambda *_: [])            # no address objects
    monkeypatch.setattr("ruleGenerator.src.panoramaData.AddressGroup.refreshall",
                        lambda *_: [ag_leaf, ag_mid, ag_root])

    pdata = PanoramaData(pano_stub)

    # Should resolve to nothing but leaf names; no infinite loop
    assert pdata.expandAddressGroups("ROOT") == []
    # All group names reachable
    assert set(pdata.allNestedGroupNames("ROOT")) == {"ROOT", "MID", "LEAF"}

def test_nets_handles_ipv6(monkeypatch, pano_stub):
    ao_v6_big  = AO("V6_BIG", "2001:db8::/64")
    ao_v6_sub  = AO("V6_SUB", "2001:db8::/80")

    monkeypatch.setattr("ruleGenerator.src.panoramaData.AddressObject.refreshall",
                        lambda *_: [ao_v6_big, ao_v6_sub])
    monkeypatch.setattr("ruleGenerator.src.panoramaData.AddressGroup.refreshall",
                        lambda *_: [])

    pdata = PanoramaData(pano_stub)

    nested = pdata.nestedObjectsInNetwork("2001:db8::/64")
    assert nested == ("V6_SUB",)

#! LARGE INVENTORY, PERFORMANCE TESTS (OPTIONAL BUT WOULD BE WISE TO THINK START THINKING ABOUT)
def test_buildFastMaps_scalability(monkeypatch, pano_stub):
    big_list = [AO(f"N{i}", f"10.{i//256}.{i%256}.0/24") for i in range(2000)]

    monkeypatch.setattr("ruleGenerator.src.panoramaData.AddressObject.refreshall",
                        lambda *_: big_list)
    monkeypatch.setattr("ruleGenerator.src.panoramaData.AddressGroup.refreshall",
                        lambda *_: [])

    pdata = PanoramaData(pano_stub)

    # spot-check a few
    assert pdata.addressObjectByName["N0"].value == "10.0.0.0/24"
    assert pdata.addressObjectByName["N1999"].value == "10.7.207.0/24"
    # maps and nets have same length (invalid CIDRs would shrink them)
    assert len(pdata.addressObjects) == len(pdata._nets)
