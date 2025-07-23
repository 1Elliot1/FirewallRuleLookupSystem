# calcRuleWeight
# tests/test_rule_scoring.py
"""
Covers PanoramaData.calcRuleWeight()

Formula (from source code):

    S = len(source.address.objects)
    D = len(destination.address.objects)
    serv = len(services)
    apps = len(applications)

    if S * D != 0:
        metricLogged = log10(S * D)
    else:
        metricLogged = 1

    weight = int(metricLogged * 10 + serv * 3 + apps * 3)

    if "any" in applications and "any" in services:
        weight += 24
"""

from ruleGenerator.src.panoramaData import PanoramaData
import pytest


# ---------------------------------------------------------------------------
# Fixtures
@pytest.fixture
def pdata(pano_stub):
    """No special inventory needed; calcRuleWeight is self-contained."""
    return PanoramaData(pano_stub)


def make_doc(S=0, D=0, serv=0, apps=0, apps_any=False, serv_any=False):
    """Utility to generate the minimal rule-doc skeleton."""
    src_objs = [f"S{i}" for i in range(S)]
    dst_objs = [f"D{i}" for i in range(D)]

    applications = ["any"] if apps_any else [f"A{i}" for i in range(apps)]
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

def test_non_zero_matrix(pdata):
    """
    S = 2, D = 5  → log10(10) = 1
    serv = 3, apps = 4
    weight = int(1*10 + 3*3 + 4*3) = 10 + 9 + 12 = 31
    """
    doc = make_doc(S=2, D=5, serv=3, apps=4)
    assert pdata.calcRuleWeight(doc) == 31


def test_zero_matrix_uses_baseline(pdata):
    """
    S * D == 0 → metricLogged = 1
    serv = 0, apps = 1
    weight = int(1*10 + 0 + 3) = 13
    """
    doc = make_doc(S=0, D=4, serv=0, apps=1)   # S=0 makes product 0
    assert pdata.calcRuleWeight(doc) == 13


def test_any_any_bonus(pdata):
    """
    Baseline: S=1, D=1 → log10(1) = 0 → 0*10 = 0
    serv=1 (but 'any'), apps=1 (but 'any') → still counted as 1 each
    Raw weight: 0 + 3 + 3 = 6  +24 bonus = 30
    """
    doc = make_doc(S=1, D=1, serv_any=True, apps_any=True)
    assert pdata.calcRuleWeight(doc) == 30
