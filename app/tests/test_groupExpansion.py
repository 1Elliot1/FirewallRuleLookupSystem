# tests/test_group_expansion.py
from types import SimpleNamespace

from ruleGenerator.core.inventory import PanoramaInventory          # <─ no facade
from tests.conftest import AO, AG

BASE = "ruleGenerator.core.inventory"          # convenience for monkey-patches


# ──────────────────────────────────────────────────────────────────────────────
# Address-group expansion
# ──────────────────────────────────────────────────────────────────────────────
def test_expand_address_groups_nested(monkeypatch, pano_stub):
    a1 = AO("HR_NET",  "10.1.0.0/24")
    a2 = AO("ENG_NET", "10.2.0.0/24")

    g_leaf = AG("LEAF", ["HR_NET", "ENG_NET"])
    g_mid  = AG("MID",  ["LEAF"])
    g_top  = AG("TOP",  ["MID"])

    monkeypatch.setattr(f"{BASE}.AddressObject.refreshall", lambda *_: [a1, a2])
    monkeypatch.setattr(f"{BASE}.AddressGroup.refreshall",
                        lambda *_: [g_leaf, g_mid, g_top])

    inv = PanoramaInventory(pano_stub)

    assert set(inv.expand_address_groups("TOP")) == {"HR_NET", "ENG_NET"}


def test_expand_address_groups_circular(monkeypatch, pano_stub):
    g1 = AG("G1", ["G2"])
    g2 = AG("G2", ["G1"])          # circular reference

    monkeypatch.setattr(f"{BASE}.AddressObject.refreshall", lambda *_: [])
    monkeypatch.setattr(f"{BASE}.AddressGroup.refreshall",  lambda *_: [g1, g2])

    inv = PanoramaInventory(pano_stub)
    assert inv.expand_address_groups("G1") == []


# ──────────────────────────────────────────────────────────────────────────────
# Application-group expansion (incl. predefined container)
# ──────────────────────────────────────────────────────────────────────────────
def test_expand_app_group_mixed(monkeypatch, pano_stub):
    leaf_ssl = SimpleNamespace(name="ssl")
    leaf_dns = SimpleNamespace(name="dns")
    container = SimpleNamespace(name="web-browsing")

    app_grp = SimpleNamespace(name="APP_GRP", value=["dns", "APP_SUB"])
    app_sub = SimpleNamespace(name="APP_SUB", value=["web-browsing"])

    monkeypatch.setattr(f"{BASE}.ApplicationObject.refreshall",
                        lambda *_: [leaf_ssl, leaf_dns])
    monkeypatch.setattr(f"{BASE}.ApplicationGroup.refreshall",
                        lambda *_: [app_grp, app_sub])
    monkeypatch.setattr(f"{BASE}.ApplicationContainer.refreshall", lambda *_: [])

    # stub predefined container & its leaf expansion
    monkeypatch.setattr(
        f"{BASE}.Predefined",
        lambda pano: SimpleNamespace(
            application_objects={},
            application_container_objects={"web-browsing": container},
            service_objects={},
            refreshall_applications=lambda self=None: None,
            refreshall_services=lambda self=None: None,
        ),
    )
    monkeypatch.setattr(
        f"{BASE}.PanoramaInventory._refresh_predef_container_leaves",
        lambda self: setattr(
            self, "_predefinedContainerLeaves", {"web-browsing": ["ssl"]}
        ),
    )

    inv = PanoramaInventory(pano_stub)

    apps, _ = inv.resolve_app_and_service_groups(["APP_GRP"], None)
    assert apps == ["dns", "ssl"]


# ──────────────────────────────────────────────────────────────────────────────
# Service-group expansion
# ──────────────────────────────────────────────────────────────────────────────
def test_expand_service_group_set_semantics(monkeypatch, pano_stub):
    svc_tcp = SimpleNamespace(name="HTTP_TCP", protocol="tcp", destination_port="80")
    svc_udp = SimpleNamespace(name="DNS_UDP",  protocol="udp", destination_port="53")
    g_leaf  = SimpleNamespace(name="SVC_LEAF", value=["HTTP_TCP"])
    g_root  = SimpleNamespace(name="SVC_ROOT", value=["SVC_LEAF", "DNS_UDP"])

    monkeypatch.setattr(f"{BASE}.ServiceObject.refreshall",
                        lambda *_: [svc_tcp, svc_udp])
    monkeypatch.setattr(f"{BASE}.ServiceGroup.refreshall",
                        lambda *_: [g_leaf, g_root])

    inv = PanoramaInventory(pano_stub)

    _, svcs = inv.resolve_app_and_service_groups(None, ["SVC_ROOT"])
    assert set(svcs) == {"HTTP_TCP", "DNS_UDP"}
