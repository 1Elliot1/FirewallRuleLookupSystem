# tests/test_port_resolution.py
"""
Covers
    • core.ports.build_port_maps               (indirectly, via introspection)
    • PortResolver.enrich_rule_with_ports      (all four main branches)

Scenarios:
    1. Plain application-default               → ports from app map
    2. Explicit service objects                → ports from service map
    3. Mixed app-default + service objects     → merged results
    4. Service "any"                           → tcp/* + udp/*
"""

from types import SimpleNamespace

from ruleGenerator.core.inventory import PanoramaInventory
from ruleGenerator.core.ports import build_port_maps

# ---------------------------------------------------------------------------
# Tiny app / service helpers
APP = lambda name, ports: SimpleNamespace(name=name, default_port=ports)
SVC = lambda name, proto, port: SimpleNamespace(
    name=name, protocol=proto, destination_port=port
)

BASE = "ruleGenerator.core.inventory"          # convenience for monkey-patches

# ---------------------------------------------------------------------------
# Local stub inventory builder
def _stub_inventory(monkeypatch):
    """
    Creates two applications + two services and monkey-patches all relevant
    *.refreshall()* calls so that PanoramaInventory sees only this data.
    """
    # ---- Applications --------------------------------------------------
    app_http = APP("web-http", ["tcp/80-82"])    # range expands to 80,81,82
    app_dns  = APP("dns-udp",  ["udp/53"])

    # ---- Services ------------------------------------------------------
    svc_www   = SVC("svc_www",   "tcp", "8080")
    svc_batch = SVC("svc_batch", "tcp", "2000-2002")  # range 2000,2001,2002

    monkeypatch.setattr(f"{BASE}.ApplicationObject.refreshall",
                        lambda *_: [app_http, app_dns])
    monkeypatch.setattr(f"{BASE}.ApplicationGroup.refreshall",    lambda *_: [])
    monkeypatch.setattr(f"{BASE}.ApplicationContainer.refreshall",lambda *_: [])

    monkeypatch.setattr(f"{BASE}.ServiceObject.refreshall",
                        lambda *_: [svc_www, svc_batch])
    monkeypatch.setattr(f"{BASE}.ServiceGroup.refreshall",        lambda *_: [])

    # keep everything else empty (address objects, templates, …)
    empty = lambda *_: []
    monkeypatch.setattr(f"{BASE}.AddressObject.refreshall", empty)
    monkeypatch.setattr(f"{BASE}.AddressGroup.refreshall", empty)
    monkeypatch.setattr(f"{BASE}.DeviceGroup.refreshall",  empty)
    monkeypatch.setattr(f"{BASE}.Template.refreshall",     empty)

# ---------------------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------------------

def test_application_default(monkeypatch, pano_stub):
    _stub_inventory(monkeypatch)

    inv = PanoramaInventory(pano_stub)
    resolver = build_port_maps(inv)

    # sanity: port map contains expanded range
    assert inv.applicationToPorts["web-http"]["tcp"] == ["80", "81", "82"]

    res = resolver.enrich_rule_with_ports(
        apps=["web-http"],
        services=[],
        service_field_raw=["application-default"],
    )

    assert set(res["resolvedPorts"]) == {"tcp/80", "tcp/81", "tcp/82"}
    assert res["portReasoning"]["tcp/80"] == ["web-http (application-default)"]


def test_explicit_service_objects(monkeypatch, pano_stub):
    _stub_inventory(monkeypatch)

    inv = PanoramaInventory(pano_stub)
    resolver = build_port_maps(inv)

    res = resolver.enrich_rule_with_ports(
        apps=[],
        services=["svc_www", "svc_batch"],
        service_field_raw=["svc_www", "svc_batch"],
    )

    assert set(res["resolvedPorts"]) == {
        "tcp/8080", "tcp/2000", "tcp/2001", "tcp/2002"
    }
    assert "svc_www (service object)" in res["portReasoning"]["tcp/8080"]


def test_mixed_app_default_and_service(monkeypatch, pano_stub):
    _stub_inventory(monkeypatch)

    inv = PanoramaInventory(pano_stub)
    resolver = build_port_maps(inv)

    res = resolver.enrich_rule_with_ports(
        apps=["dns-udp"],
        services=["svc_www"],
        service_field_raw=["application-default", "svc_www"],
    )

    assert set(res["resolvedPorts"]) == {"udp/53", "tcp/8080"}


def test_service_any_expands_wildcards(monkeypatch, pano_stub):
    _stub_inventory(monkeypatch)

    inv = PanoramaInventory(pano_stub)
    resolver = build_port_maps(inv)

    res = resolver.enrich_rule_with_ports(
        apps=[],
        services=["any"],
        service_field_raw=["any"],
    )

    assert set(res["resolvedPorts"]) == {"tcp/*", "udp/*"}
    assert res["portReasoning"]["tcp/*"] == ["Service Any"]
