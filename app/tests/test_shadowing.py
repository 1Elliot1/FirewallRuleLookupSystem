# tests/test_shadowing.py
"""
Covers
    • is_shadowed()
    • _subset
    • _cidrs_cover

We create minimal rule-document dicts (mirroring ruleDocumentBuilder’s output)
to exercise the main branches:

    1. Candidate completely shadowed by an earlier allow rule
    2. Action mismatch → not shadowed
    3. One field (applications) is not a subset → not shadowed
    4. Earlier rule uses 'any' joker → shadows
"""

from ruleGenerator.core.metrics import is_shadowed


# ---------------------------------------------------------------------------
# Helper ­– rule-doc factory
# ---------------------------------------------------------------------------
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
    """Return the minimal rule-document dict expected by *is_shadowed()*."""
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
# Tests
# ---------------------------------------------------------------------------
def test_fully_shadowed():
    earlier = [
        make_rule(
            action="allow",
            src_zones=["trust"],
            dst_zones=["untrust"],
            src_cidrs=["10.0.0.0/24"],
            dst_cidrs=["0.0.0.0/0"],        # supernet
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
    assert is_shadowed(candidate, earlier) is True


def test_action_mismatch_not_shadowed():
    earlier = [make_rule(action="deny", apps=["any"], services=["any"])]
    candidate = make_rule(action="allow", apps=["any"], services=["any"])
    assert is_shadowed(candidate, earlier) is False


def test_applications_not_subset():
    earlier = [make_rule(apps=["http"], services=["svc_web"])]
    candidate = make_rule(apps=["http", "dns"], services=["svc_web"])
    assert is_shadowed(candidate, earlier) is False


def test_any_joker_shadows():
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
    assert is_shadowed(candidate, earlier) is True
