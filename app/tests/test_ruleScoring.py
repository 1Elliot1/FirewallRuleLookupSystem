# tests/test_rule_scoring.py
"""
Unit-tests for ``ruleGenerator.core.metrics.calc_rule_weight``.

Formula under test
------------------
    S = len(src.objects)          D = len(dst.objects)
    serv = len(services)          apps = len(applications)

    metric_logged = log10(S*D)  if S*D != 0 else 1
    weight        = int(metric_logged*10 + serv*3 + apps*3)

    if "any" in applications and "any" in services:
        weight += 24
"""

from ruleGenerator.core.metrics import calc_rule_weight
import math

# ---------------------------------------------------------------------------
# Helper – build the minimal rule-doc skeleton the function expects
# ---------------------------------------------------------------------------
def _make_doc(S=0, D=0, serv=0, apps=0, apps_any=False, serv_any=False):
    src_objs = [f"S{i}"   for i in range(S)]
    dst_objs = [f"D{i}"   for i in range(D)]
    applications = ["any"] if apps_any else [f"A{i}"  for i in range(apps)]
    services     = ["any"] if serv_any else [f"SV{i}" for i in range(serv)]

    return {
        "source":      {"address": {"objects": src_objs}},
        "destination": {"address": {"objects": dst_objs}},
        "applications": applications,
        "services":     services,
    }

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_non_zero_matrix():
    """
    S = 2, D = 5  → log10(10) = 1
    serv = 3, apps = 4
    weight = int(1*10 + 3*3 + 4*3) = 31
    """
    doc = _make_doc(S=2, D=5, serv=3, apps=4)
    assert calc_rule_weight(doc) == 31


def test_zero_matrix_uses_baseline():
    """
    S * D == 0 so metric_logged = 1
    (Here S=0, D=4.)
    serv = 0, apps = 1
    weight = int(1*10 + 0 + 3) = 13
    """
    doc = _make_doc(S=0, D=4, serv=0, apps=1)
    assert calc_rule_weight(doc) == 13


def test_any_any_bonus():
    """
    Baseline:
        S = 1, D = 1 → log10(1)=0  → 0*10 = 0
        serv = 1 ('any'), apps = 1 ('any') → still counted as 1 each
        raw weight = 0 + 3 + 3 = 6
        bonus +24  → 30
    """
    doc = _make_doc(S=1, D=1, serv_any=True, apps_any=True)
    assert calc_rule_weight(doc) == 30
