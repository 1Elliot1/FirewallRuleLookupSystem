# _get_rule_metrics (uses heavy mocking)
# tests/test_rule_metrics.py
"""
Covers
    • PanoramaData._get_rule_metrics
    • PanoramaData._collectHitCountsPerRule

We monkey-patch pano_stub.op to return canned XML responses.
"""

import xml.etree.ElementTree as ET
from types import SimpleNamespace
import pytest
from ruleGenerator.src.panoramaData import PanoramaData


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def make_xml(hit, last=None, first=None, created=None, modified=None):
    """Return <response> element with a single device-vsys entry."""
    stamp = lambda tag, val: f"<{tag}>{val}</{tag}>" if val is not None else ""
    return ET.fromstring(
        f"""
        <response status="success">
          <result>
            <device-vsys>
              <entry>
                <hit-count>{hit}</hit-count>
                {stamp('last-hit-timestamp', last)}
                {stamp('first-hit-timestamp', first)}
                {stamp('rule-creation-timestamp', created)}
                {stamp('rule-modification-timestamp', modified)}
              </entry>
            </device-vsys>
          </result>
        </response>
    """
    )

@pytest.fixture
def pdata(monkeypatch, pano_stub):
    """PanoramaData with _collectDeviceGroupRules disabled for faster init."""
    monkeypatch.setattr(
        "ruleGenerator.src.panoramaData.PanoramaData._collectDeviceGroupRules",
        lambda *_: None
    )
    return PanoramaData(pano_stub)


# ---------------------------------------------------------------------------
# _get_rule_metrics
# ---------------------------------------------------------------------------

def test_single_vsys_parsing(monkeypatch, pdata, pano_stub):
    xml = make_xml(hit=5, last=1700, first=1600, created=1500, modified=1750)
    monkeypatch.setattr(pano_stub, "op", lambda *a, **kw: xml)

    m = pdata._get_rule_metrics("DG", "security", "ALLOW_WEB")
    assert m == {
        "hitCount": 5,
        "lastHit": 1700,
        "firstHit": 1600,
        "created": 1500,
        "modified": 1750,
    }


def test_multi_vsys_sums_and_extremes(monkeypatch, pdata, pano_stub):
    """Two device-vsys entries → sum hits, min(first), max(last/modified)."""
    xml = ET.fromstring(
        """
        <response status="success">
          <result>
            <device-vsys>
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
            </device-vsys>
          </result>
        </response>
        """
    )
    monkeypatch.setattr(pano_stub, "op", lambda *a, **kw: xml)

    m = pdata._get_rule_metrics("DG", "security", "ALLOW_WEB")
    assert m["hitCount"] == 10
    assert m["firstHit"] == 1500          # min
    assert m["lastHit"] == 2100           # max
    assert m["created"] == 1300           # min
    assert m["modified"] == 2200          # max


def test_non_digit_timestamps_ignored(monkeypatch, pdata, pano_stub):
    xml = make_xml(hit=1, last="n/a", first="n/a")
    monkeypatch.setattr(pano_stub, "op", lambda *a, **kw: xml)

    m = pdata._get_rule_metrics("DG", "security", "ALLOW_WEB")
    assert m["lastHit"] is None
    assert m["firstHit"] is None


# ---------------------------------------------------------------------------
# _collectHitCountsPerRule (integration)
# ---------------------------------------------------------------------------

def test_collectHitCounts(monkeypatch, pano_stub):
    """
    Build a fake deviceGroupRules structure with one SecurityRule
    and patch pano.op so the helper picks up our canned metrics.
    """
    # --- fake rule bucket ---------------------------------------------------
    rule_obj = SimpleNamespace(name="ALLOW_WEB")
    device_group_rules = {
        "DG1": {"SecurityRule": [rule_obj]},
    }

    # stub out collectDeviceGroupRules so we can inject our bucket
    monkeypatch.setattr(
        "ruleGenerator.src.panoramaData.PanoramaData._collectDeviceGroupRules",
        lambda self: setattr(self, "deviceGroupRules", device_group_rules),
    )

    # canned XML for the op() call inside _get_rule_metrics
    xml = make_xml(hit=42)
    monkeypatch.setattr(pano_stub, "op", lambda *a, **kw: xml)

    pd = PanoramaData(pano_stub)
    pd._collectHitCountsPerRule()

    key = "DG1:ALLOW_WEB"
    assert pd.ruleMetrics[key]["hitCount"] == 42
