"""Integration test for `buildRuleDocuments` using a *tiny* fake inventory.

This golden‑sample test wires the real `PanoramaData` helpers together with a
one‑rule, one‑device‑group scenario.  It relies solely on the lightweight
fixtures in *tests/conftest.py* (no live API needed).
"""

from types import SimpleNamespace

import pytest

# Project imports -----------------------------------------------------------
from ruleGenerator.src.ruleDocumentBuilder import buildRuleDocuments


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rule(name: str, **overrides):
    """Create a stand‑in SecurityRule as SimpleNamespace."""
    # defaults minimise the amount of PanoramaData state we have to mock
    data = {
        "action": "allow",
        "fromzone": ["internal"],
        "tozone": ["external"],
        "source": ["any"],
        "destination": ["any"],
        "application": ["any"],
        "service": ["any"],
        "description": None,
    }
    data.update(overrides)
    return SimpleNamespace(name=name, **data)


# ---------------------------------------------------------------------------
# Golden‑sample test
# ---------------------------------------------------------------------------

def test_build_rule_documents_golden(pdata):
    """End‑to‑end check that schema‑critical fields survive refactors."""
    # 1) Arrange – tiny fake rule set --------------------------------------
    pdata.deviceGroupRules = {
        "DG1": {
            "SecurityRule": [
                _rule(
                    "Allow-Internet-Out",
                    source=["HR_NET"],        # AddressObject the stub already provides
                    destination=["any"],
                )
            ]
        }
    }
    pdata.ruleMetrics = {}   # hit‑count optional for this test

    # 2) Act ---------------------------------------------------------------
    docs = buildRuleDocuments(pdata)

    # 3) Assert – minimal contract guarantees -----------------------------
    assert len(docs) == 1
    doc = docs[0]

    # identity & routing ---------------------------------------------------
    assert doc["ruleId"] == "DG1:Allow-Internet-Out"
    assert doc["ruleName"] == "Allow-Internet-Out"
    assert doc["deviceGroup"] == "DG1"
    assert doc["ruleType"] == "SecurityRule"
    assert doc["action"] == "allow"

    # address expansion ----------------------------------------------------
    assert doc["source"]["address"]["objects"] == ["HR_NET"]
    assert doc["destination"]["address"]["groups"] == ["any"]

    # service *any* → wildcard ports --------------------------------------
    assert set(doc["resolved"]["ports"]) == {"tcp/*", "udp/*"}
    assert set(doc["resolved"]["protocols"]) == {6, 17}   # TCP / UDP
