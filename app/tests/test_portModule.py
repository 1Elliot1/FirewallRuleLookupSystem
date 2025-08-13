# tests/test_port_module.py
"""
Unit-tests for ruleGenerator.core.ports

Covers:
    • build_port_maps()  – application / service → port dictionaries
    • PortResolver.enrich_rule_with_ports()
"""

from types import SimpleNamespace

import pytest

# Core code under test -------------------------------------------------------
from ruleGenerator.core.inventory import PanoramaInventory
from ruleGenerator.core.ports import build_port_maps

BASE = "ruleGenerator.core.inventory"      # monkey-patch shortcut


# ---------------------------------------------------------------------------
# Shared application / service stubs
# ---------------------------------------------------------------------------
def _app(name: str, default_port: list[str]):
    return SimpleNamespace(name=name, default_port=default_port)

def _svc(name: str, proto: str, port: str):
    return SimpleNamespace(name=name, protocol=proto, destination_port=port)


# ---------------------------------------------------------------------------
# 1) Port map construction
# ---------------------------------------------------------------------------
def test_port_maps_roundtrip(monkeypatch, pano_stub):
    """
    Checks that applications / services and the reverse port-to-entity map
    are all populated correctly by *build_port_maps()*.
    """
    # Two apps: one with single port, one with a range
    app_web  = _app("web-app", ["tcp/443"])
    app_ftp  = _app("ftp-app", ["tcp/20-21"])

    # Two service objects mirroring the apps
    svc_dns  = _svc("DNS-UDP",  "udp", "53")
    svc_icmp = _svc("PING",     "icmp", "0")

    # Patch refreshall() so the inventory sees our stubs
    monkeypatch.setattr(f"{BASE}.ApplicationObject.refreshall",
                        lambda *_: [app_web, app_ftp])
    monkeypatch.setattr(f"{BASE}.ServiceObject.refreshall",
                        lambda *_: [svc_dns, svc_icmp])
    # empty for everything else we don’t need here
    monkeypatch.setattr(f"{BASE}.ApplicationGroup.refreshall",    lambda *_: [])
    monkeypatch.setattr(f"{BASE}.ApplicationContainer.refreshall",lambda *_: [])
    monkeypatch.setattr(f"{BASE}.AddressObject.refreshall",       lambda *_: [])
    monkeypatch.setattr(f"{BASE}.AddressGroup.refreshall",        lambda *_: [])
    monkeypatch.setattr(f"{BASE}.ServiceGroup.refreshall",        lambda *_: [])
    monkeypatch.setattr(f"{BASE}.DeviceGroup.refreshall",         lambda *_: [])
    monkeypatch.setattr(f"{BASE}.Template.refreshall",            lambda *_: [])

    inv = PanoramaInventory(pano_stub)
    resolver = build_port_maps(inv)        # mutates *inv* in-place

    # ---- applicationToPorts ---------------------------------------
    assert inv.applicationToPorts["web-app"] == {"tcp": ["443"]}
    assert inv.applicationToPorts["ftp-app"]["tcp"] == ["20", "21"]

    # ---- serviceToPorts -------------------------------------------
    assert inv.serviceToPorts["DNS-UDP"]  == {"udp": ["53"]}
    assert inv.serviceToPorts["PING"]     == {"icmp": ["0"]}

    # ---- portToEntities reverse map -------------------------------
    assert set(inv.portToEntities["tcp/21"]["applications"]) == {"ftp-app"}
    assert set(inv.portToEntities["udp/53"]["services"])     == {"DNS-UDP"}


# ---------------------------------------------------------------------------
# 2) Port-resolution logic
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "apps, services, raw_field, expected",
    [
        # application-default -> pick ports from each app
        (["web-app"], [], ["application-default"], {"tcp/443"}),
        # service any -> wildcard proto/port
        ([], [], ["any"], {"tcp/*", "udp/*"}),
        # explicit service object(s)
        ([], ["DNS-UDP"], ["DNS-UDP"], {"udp/53"}),
        # mix of app-default + service object
        (["web-app"], ["DNS-UDP"], ["DNS-UDP", "application-default"],
         {"tcp/443", "udp/53"}),
    ],
)
def test_enrich_rule_with_ports(monkeypatch, pano_stub,
                                apps, services, raw_field, expected):
    """Exercise the resolver end-to-end for common rule combinations."""
    # minimal single app / svc definitions
    app_web = _app("web-app", ["tcp/443"])
    svc_dns = _svc("DNS-UDP", "udp", "53")

    monkeypatch.setattr(f"{BASE}.ApplicationObject.refreshall",
                        lambda *_: [app_web])
    monkeypatch.setattr(f"{BASE}.ServiceObject.refreshall",
                        lambda *_: [svc_dns])
    monkeypatch.setattr(f"{BASE}.ApplicationGroup.refreshall",    lambda *_: [])
    monkeypatch.setattr(f"{BASE}.ApplicationContainer.refreshall",lambda *_: [])
    monkeypatch.setattr(f"{BASE}.AddressObject.refreshall",       lambda *_: [])
    monkeypatch.setattr(f"{BASE}.AddressGroup.refreshall",        lambda *_: [])
    monkeypatch.setattr(f"{BASE}.ServiceGroup.refreshall",        lambda *_: [])
    monkeypatch.setattr(f"{BASE}.DeviceGroup.refreshall",         lambda *_: [])
    monkeypatch.setattr(f"{BASE}.Template.refreshall",            lambda *_: [])

    inv = PanoramaInventory(pano_stub)
    resolver = build_port_maps(inv)

    result = resolver.enrich_rule_with_ports(apps, services, raw_field)
    assert set(result["resolvedPorts"]) == expected
