# tests/integration/test_build_rule_documents.py
"""
Golden-path integration test for `buildRuleDocuments`.

We spin up the real PanoramaData façade (via the shared `pdata` fixture)
and feed it a single SecurityRule.  All helpers – inventory, port–maps,
static-overrides (skipped in the stub), rule-metrics – execute exactly
as in production *except* for external-CIDR detection, which we stub with
a 3-line helper to keep the test self-contained.
"""

from types import SimpleNamespace
from functools import partial, wraps
from ruleGenerator.src.ruleDocumentBuilder import buildRuleDocuments


# ---------------------------------------------------------------------------
# A minimal stand-in SecurityRule
# ---------------------------------------------------------------------------
def _rule(name: str, **overrides) -> SimpleNamespace:
    base = dict(
        action="allow",
        fromzone=["internal"],
        tozone=["external"],
        source=["any"],
        destination=["any"],
        application=["any"],
        service=["any"],
        description=None,
    )
    base.update(overrides)
    return SimpleNamespace(name=name, **base)


# ---------------------------------------------------------------------------
# Tiny “always-internal” stub so buildRuleDocuments doesn’t explode
# ---------------------------------------------------------------------------
def _always_internal(self, cidrs, groups, zones=None):   # noqa: D401
    """Pretend everything is internal – good enough for this test."""
    return False


# ---------------------------------------------------------------------------
# The golden test
# ---------------------------------------------------------------------------
def test_build_rule_documents_golden(pdata, monkeypatch):
    """
    End-to-end contract check: critical fields survive the full pipeline.
    """

    # -- 1) Arrange ----------------------------------------------------
    pdata.deviceGroupRules = {
        "DG1": {"SecurityRule": [_rule("Allow-Internet-Out", source=["HR_NET"])]}
    }
    pdata.ruleMetrics = {}                 # not checked here

    #   Patch *once* at the class level for all PanoramaData instances
    monkeypatch.setattr(
        type(pdata),                       # PanoramaData class
        "isExternal",
        _always_internal,
        raising=False,                     # attribute doesn’t exist in refactor
    )

    # -- 2) Act --------------------------------------------------------
    docs = buildRuleDocuments(pdata)

    # -- 3) Assert: minimal but schema-critical -----------------------
    assert len(docs) == 1
    d = docs[0]

    # identity / routing
    assert d["ruleId"]     == "DG1:Allow-Internet-Out"
    assert d["deviceGroup"] == "DG1"
    assert d["ruleType"]   == "SecurityRule"
    assert d["action"]     == "allow"

    # address expansion
    assert d["source"]["address"]["objects"] == ["HR_NET"]
    assert d["destination"]["address"]["groups"] == ["any"]

    # service *any* → wildcard ports / protocol bytes
    assert set(d["resolved"]["ports"])      == {"tcp/*", "udp/*"}
    assert set(d["resolved"]["protocols"])  == {6, 17}          # TCP / UDP
