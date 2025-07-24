# tests/test_rule_metrics.py
"""
Covers the hit-count helpers that live in **ruleGenerator.core.metrics**

    • RuleMetricsCollector._get_rule_metrics
    • RuleMetricsCollector.collect_hit_counts
"""

from types import SimpleNamespace
import xml.etree.ElementTree as ET
import pytest

# ––––– project imports –––––––––––––––––––––––––––––––––––––––––––––––
from ruleGenerator.core.inventory import PanoramaInventory
from ruleGenerator.core.metrics   import RuleMetricsCollector

# --------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------
def _xml(hit, last=None, first=None, created=None, modified=None):
    """<response> with a single <device-vsys><entry> …</entry></device-vsys>."""
    tag = lambda k, v: f"<{k}>{v}</{k}>" if v is not None else ""
    return ET.fromstring(
        f"""
        <response status="success">
          <result>
            <device-vsys><entry>
              <hit-count>{hit}</hit-count>
              {tag('last-hit-timestamp', last)}
              {tag('first-hit-timestamp', first)}
              {tag('rule-creation-timestamp', created)}
              {tag('rule-modification-timestamp', modified)}
            </entry></device-vsys>
          </result>
        </response>
        """
    )

@pytest.fixture
def inv(monkeypatch, pano_stub):
    """
    Lightweight PanoramaInventory with *no* rules pulled from Panorama
    (it’s enough for the metrics helper).
    """
    # skip network / rulebase queries for speed
    monkeypatch.setattr(
        PanoramaInventory,
        "_collect_device_group_rules",
        lambda self: setattr(self, "deviceGroupRules", {}),
    )
    return PanoramaInventory(pano_stub)

# --------------------------------------------------------------------
# _get_rule_metrics
# --------------------------------------------------------------------
def test_single_vsys(monkeypatch, inv, pano_stub):
    coll = RuleMetricsCollector(inv)
    monkeypatch.setattr(pano_stub, "op", lambda *_, **__: _xml(5, 1700, 1600, 1500, 1750))

    m = coll._get_rule_metrics("DG", "security", "ALLOW_WEB")          # pylint: disable=protected-access
    assert m == {
        "hitCount": 5,
        "lastHit": 1700,
        "firstHit": 1600,
        "created": 1500,
        "modified": 1750,
    }

def test_multi_vsys(monkeypatch, inv, pano_stub):
    xml = ET.fromstring(
        """
        <response status="success"><result><device-vsys>
          <entry>
            <hit-count>3</hit-count>
            <last-hit-timestamp>2000</last-hit-timestamp>
            <first-hit-timestamp>1500</first-hit-timestamp>
            <rule-creation-timestamp>1400</rule-creation-timestamp>
            <rule-modification-timestamp>1990</rule-modification-timestamp>
          </entry>
          <entry>
            <hit-count>7</hit-count>
            <last-hit-timestamp>2100</last-hit-timestamp>
            <first-hit-timestamp>1600</first-hit-timestamp>
            <rule-creation-timestamp>1300</rule-creation-timestamp>
            <rule-modification-timestamp>2200</rule-modification-timestamp>
          </entry>
        </device-vsys></result></response>
        """
    )
    monkeypatch.setattr(pano_stub, "op", lambda *_, **__: xml)

    coll = RuleMetricsCollector(inv)
    m = coll._get_rule_metrics("DG", "security", "ALLOW_WEB")          # pylint: disable=protected-access
    assert m["hitCount"] == 10
    assert m["firstHit"] == 1500          # min
    assert m["lastHit"]  == 2100          # max
    assert m["created"]  == 1300          # min
    assert m["modified"] == 2200          # max

def test_non_digit_timestamps(monkeypatch, inv, pano_stub):
    monkeypatch.setattr(pano_stub, "op", lambda *_, **__: _xml(1, "n/a", "n/a"))

    coll = RuleMetricsCollector(inv)
    m = coll._get_rule_metrics("DG", "security", "ALLOW_WEB")          # pylint: disable=protected-access
    assert m["lastHit"] is None
    assert m["firstHit"] is None

# --------------------------------------------------------------------
# collect_hit_counts (integration)
# --------------------------------------------------------------------
def test_collect_hit_counts(monkeypatch, inv, pano_stub):
    """
    Inject a tiny fake rule bucket and ensure *collect_hit_counts()* stores
    the metrics under the correct composite key.
    """
    inv.deviceGroupRules = {
        "DG1": {"SecurityRule": [SimpleNamespace(name="ALLOW_WEB")]}
    }
    monkeypatch.setattr(pano_stub, "op", lambda *_, **__: _xml(42))

    coll = RuleMetricsCollector(inv)
    coll.collect_hit_counts()

    key = "DG1:ALLOW_WEB"
    assert inv.ruleMetrics[key]["hitCount"] == 42