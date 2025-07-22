# isShadowed + _cidrs_cover + _subset
# tests/test_shadowing.py
"""
Covers PanoramaData.isShadowed() plus the underlying helpers
    • _subset
    • _cidrs_cover

We craft minimal rule-document dicts (same shape ruleDocumentBuilder
emits) to hit the key branches:

    1. Candidate completely shadowed by earlier allow rule
    2. Action mismatch ⇒ not shadowed
    3. One field (applications) not a subset ⇒ not shadowed
    4. Earlier rule uses 'any' joker ⇒ shadows
"""

from types import SimpleNamespace
import pytest
from ruleGenerator.src.panoramaData import PanoramaData


# ---------------------------------------------------------------------------
# Helpers
def make_rule(
    *,
    action="allow",
    src_zones=None,
    dst_zones=None,
    src_cidrs=None,
    dst_cidrs=None,
    apps=None,
    services=None,
):
    """Return a minimal rule-doc dict for isShadowed()."""
    return {
        "action": action,
        "source": {
            "zones": src_zones or [],
            "address": {"cidr": src_cidrs or [], "objects": [], "groups": []},
        },
        "destination": {
            "zones": dst_zones or [],
            "address": {"cidr": dst_cidrs or [], "objects": [], "groups": []},
        },
        "applications": apps or [],
        "services": services or [],
    }


# ---------------------------------------------------------------------------
# The tests
# ---------------------------------------------------------------------------

@pytest.fixture
def pdata(pano_stub):
    """Fresh PanoramaData instance—no special inventory needed."""
    return PanoramaData(pano_stub)


def test_fully_shadowed(pdata):
    earlier = [
        make_rule(
            action="allow",
            src_zones=["trust"],
            dst_zones=["untrust"],
            src_cidrs=["10.0.0.0/24"],
            dst_cidrs=["0.0.0.0/0"],          # supernet
            apps=["http", "dns"],
            services=["svc_web", "svc_dns"],
        )
    ]

    candidate = make_rule(
        action="allow",
        src_zones=["trust"],
        dst_zones=["untrust"],
        src_cidrs=["10.0.0.5/32"],
        dst_cidrs=["1.2.3.4/32"],
        apps=["dns"],
        services=["svc_dns"],
    )

    assert pdata.isShadowed(candidate, earlier) is True


def test_action_mismatch_not_shadowed(pdata):
    earlier = [make_rule(action="deny", apps=["any"], services=["any"])]
    candidate = make_rule(action="allow", apps=["any"], services=["any"])
    assert pdata.isShadowed(candidate, earlier) is False


def test_applications_not_subset(pdata):
    earlier = [make_rule(apps=["http"], services=["svc_web"])]
    candidate = make_rule(apps=["http", "dns"], services=["svc_web"])
    assert pdata.isShadowed(candidate, earlier) is False


def test_any_joker_shadows(pdata):
    earlier = [
        make_rule(
            apps=["any"],
            services=["any"],
            src_zones=["trust"],
            dst_zones=["untrust"],
        )
    ]
    candidate = make_rule(
        apps=["ssl"],
        services=["svc_ssl"],
        src_zones=["trust"],
        dst_zones=["untrust"],
    )
    assert pdata.isShadowed(candidate, earlier) is True
