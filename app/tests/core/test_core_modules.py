"""Unit‑level smoke tests for the new *ruleGenerator.core* split.

These tests don’t aim for exhaustive coverage (your existing suite already
covers the heavy logic) – they simply prove that the three extracted modules
*Inventory*, *Ports*, *Overrides* and *Metrics* plug together without breaking
the public contracts relied on by ruleDocumentBuilder.
"""

from __future__ import annotations

from types import SimpleNamespace
import textwrap
import xml.etree.ElementTree as ET
import ipaddress

import pytest

# ---------------------------------------------------------------------------
# Shared helpers / tiny object factories
# ---------------------------------------------------------------------------
AO = lambda n, v: SimpleNamespace(name=n, value=v)
AG = lambda n, members: SimpleNamespace(name=n, static_value=list(members))
APP = lambda n, ports: SimpleNamespace(name=n, default_port=ports)
SVC = lambda n, proto, port: SimpleNamespace(name=n, protocol=proto, destination_port=port)


def _make_xml(hit=1):
    return ET.fromstring(
        f"""
        <response status='success'>
          <result>
            <device-vsys>
              <entry>
                <hit-count>{hit}</hit-count>
              </entry>
            </device-vsys>
          </result>
        </response>
        """
    )

# ---------------------------------------------------------------------------
# Inventory basics
# ---------------------------------------------------------------------------

def test_inventory_maps(monkeypatch, pano_stub):
    from ruleGenerator.core.inventory import PanoramaInventory

    ao1, ao2 = AO("NET1", "10.0.0.0/24"), AO("NET2", "10.0.1.0/24")
    ag = AG("GRP", ["NET1", "NET2"])

    # patch refreshall() paths inside *core.inventory*
    monkeypatch.setattr("ruleGenerator.core.inventory.AddressObject.refreshall", lambda *_: [ao1, ao2])
    monkeypatch.setattr("ruleGenerator.core.inventory.AddressGroup.refreshall", lambda *_: [ag])
    # keep other refreshall() empty to speed up
    empty = lambda *_: []
    monkeypatch.setattr("ruleGenerator.core.inventory.ServiceObject.refreshall", empty)
    monkeypatch.setattr("ruleGenerator.core.inventory.ServiceGroup.refreshall", empty)
    monkeypatch.setattr("ruleGenerator.core.inventory.ApplicationObject.refreshall", empty)
    monkeypatch.setattr("ruleGenerator.core.inventory.ApplicationGroup.refreshall", empty)
    monkeypatch.setattr("ruleGenerator.core.inventory.ApplicationContainer.refreshall", empty)
    monkeypatch.setattr("ruleGenerator.core.inventory.DeviceGroup.refreshall", empty)
    monkeypatch.setattr("ruleGenerator.core.inventory.Template.refreshall", empty)

    inv = PanoramaInventory(pano_stub)

    assert inv.addressObjectByName["NET1"] is ao1
    assert set(inv.address_groups_for_object(ao1)) == {"GRP"}
    nested = inv.nested_objects_in_network("10.0.0.0/16")
    assert set(nested) == {"NET1", "NET2"}

# ---------------------------------------------------------------------------
# Ports builder & resolver
# ---------------------------------------------------------------------------

def test_port_resolver(monkeypatch, pano_stub):
    from ruleGenerator.core.inventory import PanoramaInventory
    from ruleGenerator.core.ports import build_port_maps

    # minimal inventory with one app + one svc
    app = APP("web-http", ["tcp/80"])
    svc = SVC("svc_www", "tcp", "8080")

    monkeypatch.setattr("ruleGenerator.core.inventory.ApplicationObject.refreshall", lambda *_: [app])
    monkeypatch.setattr("ruleGenerator.core.inventory.ServiceObject.refreshall", lambda *_: [svc])
    # empty rest
    for sym in [
        "ApplicationGroup", "ApplicationContainer", "ServiceGroup",
        "AddressObject", "AddressGroup", "DeviceGroup", "Template"
    ]:
        monkeypatch.setattr(f"ruleGenerator.core.inventory.{sym}.refreshall", lambda *_: [])

    inv = PanoramaInventory(pano_stub)
    resolver = build_port_maps(inv)

    res = resolver.enrich_rule_with_ports(
        apps=["web-http"], services=["svc_www"], service_field_raw=["application-default", "svc_www"]
    )
    assert set(res["resolvedPorts"]) == {"tcp/80", "tcp/8080"}

# ---------------------------------------------------------------------------
# Static overrides
# ---------------------------------------------------------------------------

def test_static_overrides(monkeypatch, pano_stub, tmp_path):
    from ruleGenerator.core.inventory import PanoramaInventory
    from ruleGenerator.core.ports import build_port_maps
    from ruleGenerator.core.overrides import apply_static_overrides

    # base inventory with empty lists
    empty = lambda *_: []
    for sym in [
        "AddressObject", "AddressGroup", "ServiceObject", "ServiceGroup",
        "ApplicationObject", "ApplicationGroup", "ApplicationContainer",
        "DeviceGroup", "Template"
    ]:
        monkeypatch.setattr(f"ruleGenerator.core.inventory.{sym}.refreshall", empty)

    inv = PanoramaInventory(pano_stub)
    build_port_maps(inv)  # creates application/service maps so overrides can merge

    overrides_yaml = tmp_path / "overrides.yml"
    overrides_yaml.write_text(
        textwrap.dedent(
            """
            addressObjects:
              NEW_NET: 203.0.113.0/24
            """
        )
    )

    apply_static_overrides(inv, overrides_yaml)
    assert inv.addressObjectByName["NEW_NET"].value == "203.0.113.0/24"
    # _nets updated too
    assert any(name == "NEW_NET" for _, name in inv._nets)

# ---------------------------------------------------------------------------
# Metrics collector + utils
# ---------------------------------------------------------------------------

def test_metrics_weight_and_shadow(monkeypatch, pano_stub):
    from ruleGenerator.core.inventory import PanoramaInventory
    from ruleGenerator.core.metrics import (
        RuleMetricsCollector,
        calc_rule_weight,
        is_shadowed,
    )

    # stub minimal inventory w/out API calls
    for sym in [
        "AddressObject", "AddressGroup", "ServiceObject", "ServiceGroup",
        "ApplicationObject", "ApplicationGroup", "ApplicationContainer",
        "DeviceGroup", "Template"
    ]:
        monkeypatch.setattr(f"ruleGenerator.core.inventory.{sym}.refreshall", lambda *_: [])

    inv = PanoramaInventory(pano_stub)

    # --- hit count collector wiring ----------------------------------
    monkeypatch.setattr(
        pano_stub,
        "op",
        lambda *a, **kw: _make_xml(hit=5),
    )
    # stitch a fake rule bucket so collector finds one rule
    rule_obj = SimpleNamespace(name="ALLOW_WEB")
    inv.deviceGroupRules = {"DG1": {"SecurityRule": [rule_obj]}}

    collector = RuleMetricsCollector(inv)
    collector.collect_hit_counts()
    assert inv.ruleMetrics["DG1:ALLOW_WEB"]["hitCount"] == 5

    # --- weight & shadow helpers ------------------------------------
    doc_a = {
        "source": {"address": {"objects": ["A"]}},
        "destination": {"address": {"objects": ["B"]}},
        "applications": ["http"],
        "services": ["svc_web"],
    }
    weight = calc_rule_weight(doc_a)
    assert isinstance(weight, int) and weight > 0

    earlier = [
        {
            "action": "allow",
            "source": {"zones": [], "address": {"cidr": ["0.0.0.0/0"], "objects": [], "groups": []}},
            "destination": {"zones": [], "address": {"cidr": ["0.0.0.0/0"], "objects": [], "groups": []}},
            "applications": ["any"],
            "services": ["any"],
        }
    ]
    candidate = {
        "action": "allow",
        "source": {"zones": [], "address": {"cidr": ["10.0.0.0/24"], "objects": [], "groups": []}},
        "destination": {"zones": [], "address": {"cidr": ["1.1.1.1/32"], "objects": [], "groups": []}},
        "applications": ["http"],
        "services": ["svc_web"],
    }
    assert is_shadowed(candidate, earlier) is True
