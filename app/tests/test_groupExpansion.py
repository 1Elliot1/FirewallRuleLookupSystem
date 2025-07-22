# address/app/service expansion helpers
# tests/test_group_expansion.py
from types import SimpleNamespace
import pytest
from ruleGenerator.src.panoramaData import PanoramaData
from tests.conftest import AO, AG, SV

# AO, AG, SV helpers from conftest or redefine locally as needed

# ------------------------------------------------------------------
# Address group expansion
def test_expandAddressGroups_nested(monkeypatch, pano_stub):
    # leaf objects
    a1 = AO("HR_NET", "10.1.0.0/24")
    a2 = AO("ENG_NET", "10.2.0.0/24")

    # groups
    g_leaf = AG("LEAF", ["HR_NET", "ENG_NET"])
    g_mid  = AG("MID", ["LEAF"])
    g_top  = AG("TOP", ["MID"])

    monkeypatch.setattr("ruleGenerator.src.panoramaData.AddressObject.refreshall",
                        lambda *_: [a1, a2])
    monkeypatch.setattr("ruleGenerator.src.panoramaData.AddressGroup.refreshall",
                        lambda *_: [g_leaf, g_mid, g_top])

    pdata = PanoramaData(pano_stub)

    assert pdata.expandAddressGroups("TOP") == ["ENG_NET", "HR_NET"] 
    # cache hit path
    assert pdata._expandedAppGroupCache == {}  # untouched by address flow


def test_expandAddressGroups_circular(monkeypatch, pano_stub):
    g1 = AG("G1", ["G2"])
    g2 = AG("G2", ["G1"])   # circular
    monkeypatch.setattr("ruleGenerator.src.panoramaData.AddressObject.refreshall", lambda *_: [])
    monkeypatch.setattr("ruleGenerator.src.panoramaData.AddressGroup.refreshall",  lambda *_: [g1, g2])

    pdata = PanoramaData(pano_stub)
    # Should terminate without RecursionError and return no leaves
    assert pdata.expandAddressGroups("G1") == []

# ------------------------------------------------------------------
# Application group expansion (leaf + subgroup + container)
def test_expandAppGroup_mixed(monkeypatch, pano_stub):
    # leaf apps
    leaf_a = SimpleNamespace(name="ssl")
    leaf_b = SimpleNamespace(name="dns")

    # predefined container stub (will be expanded to ['ssl'])
    container = SimpleNamespace(name="web-browsing")

    app_grp  = SimpleNamespace(name="APP_GRP", value=["dns", "APP_SUB"])
    app_sub  = SimpleNamespace(name="APP_SUB", value=["web-browsing"])

    monkeypatch.setattr("ruleGenerator.src.panoramaData.ApplicationObject.refreshall",
                        lambda *_: [leaf_a, leaf_b])
    monkeypatch.setattr("ruleGenerator.src.panoramaData.ApplicationGroup.refreshall",
                        lambda *_: [app_grp, app_sub])
    monkeypatch.setattr("ruleGenerator.src.panoramaData.ApplicationContainer.refreshall", lambda *_: [])
    # predefined container mapping
    monkeypatch.setattr("ruleGenerator.src.panoramaData.Predefined", lambda pano: SimpleNamespace(
        application_objects     = {},
        application_container_objects = {"web-browsing": container},
        service_objects         = {},
        refreshall_applications = lambda self=None: None,
        refreshall_services     = lambda self=None: None))

    # container leaf map
    # -- make sure refreshPredefContainerLeaves doesn't wipe our stub ------
    monkeypatch.setattr(
        "ruleGenerator.src.panoramaData.PanoramaData._refreshPredefContainerLeaves",
        lambda self: setattr(self, "_predefinedContainerLeaves",
                             {"web-browsing": ["ssl"]})
    )

    pdata = PanoramaData(pano_stub)

    expanded = pdata._expandAppGroup("APP_GRP")
    assert expanded == ["dns", "ssl"]

    # cache should now store result
    assert pdata._expandedAppGroupCache["APP_GRP"] == ["dns", "ssl"]

# ------------------------------------------------------------------
# Service group expansion order-insensitive
def test_expandServiceGroup_set_semantics(monkeypatch, pano_stub):
    svc_tcp = SimpleNamespace(name="HTTP_TCP", protocol="tcp", destination_port="80")
    svc_udp = SimpleNamespace(name="DNS_UDP", protocol="udp", destination_port="53")
    g_leaf  = SimpleNamespace(name="SVC_LEAF", value=["HTTP_TCP"])
    g_root  = SimpleNamespace(name="SVC_ROOT", value=["SVC_LEAF", "DNS_UDP"])

    monkeypatch.setattr("ruleGenerator.src.panoramaData.ServiceObject.refreshall", lambda *_: [svc_tcp, svc_udp])
    monkeypatch.setattr("ruleGenerator.src.panoramaData.ServiceGroup.refreshall",  lambda *_: [g_leaf, g_root])

    pdata = PanoramaData(pano_stub)
    assert set(pdata._expandServiceGroup("SVC_ROOT")) == {"HTTP_TCP", "DNS_UDP"}
