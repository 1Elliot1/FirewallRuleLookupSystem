#enrichRuleWithPorts
# tests/test_port_resolution.py
"""
Covers
    • _buildApplicationServicePortMaps  (indirectly, by introspection)
    • enrichRuleWithPorts

Scenarios:
    1. Plain application-default                     → ports from app map
    2. Explicit service objects                      → ports from service map
    3. Mixed app-default + explicit services         → merged results
    4. Service "any"                                 → tcp/* + udp/*
    5. Port-range parsing (80-82) expands per port
"""

from types import SimpleNamespace
from ruleGenerator.src.panoramaData import PanoramaData


# ---------------------------------------------------------------------------
# Tiny app / service constructors

APP = lambda name, ports: SimpleNamespace(name=name, default_port=ports)
SVC = lambda name, proto, port: SimpleNamespace(
        name=name, protocol=proto, destination_port=port)


# ---------------------------------------------------------------------------
# Test inventory fixture local to this module
def _stub_inventory(monkeypatch):
    """Create two apps + two services and patch refreshall()."""
    # Applications --------------------------------------------------
    # web-http -> tcp/80,81,82  (range)
    # dns-udp  -> udp/53
    app_http = APP("web-http", ["tcp/80-82"])
    app_dns  = APP("dns-udp",  ["udp/53"])

    # Services ------------------------------------------------------
    # svc_www   -> tcp/8080
    # svc_batch -> tcp/2000-2002 (range)
    svc_www   = SVC("svc_www",   "tcp", "8080")
    svc_batch = SVC("svc_batch", "tcp", "2000-2002")

    monkeypatch.setattr("ruleGenerator.src.panoramaData.ApplicationObject.refreshall",
                        lambda *_: [app_http, app_dns])
    monkeypatch.setattr("ruleGenerator.src.panoramaData.ApplicationGroup.refreshall",    lambda *_: [])
    monkeypatch.setattr("ruleGenerator.src.panoramaData.ApplicationContainer.refreshall", lambda *_: [])
    monkeypatch.setattr("ruleGenerator.src.panoramaData.ServiceObject.refreshall",
                        lambda *_: [svc_www, svc_batch])
    monkeypatch.setattr("ruleGenerator.src.panoramaData.ServiceGroup.refreshall",        lambda *_: [])
    # keep others empty
    empty = lambda *_: []
    monkeypatch.setattr("ruleGenerator.src.panoramaData.AddressObject.refreshall", empty)
    monkeypatch.setattr("ruleGenerator.src.panoramaData.AddressGroup.refreshall", empty)
    monkeypatch.setattr("ruleGenerator.src.panoramaData.DeviceGroup.refreshall",  empty)
    monkeypatch.setattr("ruleGenerator.src.panoramaData.Template.refreshall",     empty)


# ---------------------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------------------

def test_application_default(monkeypatch, pano_stub):
    _stub_inventory(monkeypatch)
    pdata = PanoramaData(pano_stub)

    # sanity: port map contains expanded range
    assert pdata.applicationToPorts["web-http"]["tcp"] == ["80", "81", "82"]

    res = pdata.enrichRuleWithPorts(
        apps=["web-http"],
        services=[],
        serviceFieldRaw=["application-default"],
    )

    assert set(res["resolvedPorts"]) == {"tcp/80", "tcp/81", "tcp/82"}
    assert res["portReasoning"]["tcp/80"] == ["web-http (application-default)"]


def test_explicit_service_objects(monkeypatch, pano_stub):
    _stub_inventory(monkeypatch)
    pdata = PanoramaData(pano_stub)

    res = pdata.enrichRuleWithPorts(
        apps=[],
        services=["svc_www", "svc_batch"],
        serviceFieldRaw=["svc_www", "svc_batch"],
    )
    assert set(res["resolvedPorts"]) == {
        "tcp/8080", "tcp/2000", "tcp/2001", "tcp/2002"
    }
    assert "svc_www (service object)" in res["portReasoning"]["tcp/8080"]


def test_mixed_app_default_and_service(monkeypatch, pano_stub):
    _stub_inventory(monkeypatch)
    pdata = PanoramaData(pano_stub)

    res = pdata.enrichRuleWithPorts(
        apps=["dns-udp"],
        services=["svc_www"],
        serviceFieldRaw=["application-default", "svc_www"],
    )
    assert set(res["resolvedPorts"]) == {"udp/53", "tcp/8080"}


def test_service_any_expands_wildcards(monkeypatch, pano_stub):
    _stub_inventory(monkeypatch)
    pdata = PanoramaData(pano_stub)

    res = pdata.enrichRuleWithPorts(
        apps=[],
        services=["any"],
        serviceFieldRaw=["any"],
    )
    assert set(res["resolvedPorts"]) == {"tcp/*", "udp/*"}
    assert res["portReasoning"]["tcp/*"] == ["Service Any"]

#! What happens if apps and services == any? Is that possible?
#! What happens if apps == any and services == application-default? is that possible?
#! What happens if apps == any and services == None? Is that possible?
#! What happens if apps == None and services == None? Is that possible?