# isExternal / _cidrIsExternal logic
# tests/test_zone_external.py
from types import SimpleNamespace
import pytest
from ruleGenerator.src.panoramaData import PanoramaData


# ---------------------------------------------------------------------------
# Tiny stubs & helpers
AO = lambda n, v: SimpleNamespace(name=n, value=v)
AG = lambda n, mem: SimpleNamespace(name=n, static_value=list(mem))

INTERNALS = ["10.0.0.0/8", "2001:db8:abcd::/48"]


def _bootstrap(monkeypatch, pano_stub):
    """Return PanoramaData with staticOverrides that define internal prefixes."""
    # Empty inventory – we only care about _applyStaticOverrides
    empty = lambda *_: []
    monkeypatch.setattr("ruleGenerator.src.panoramaData.AddressObject.refreshall", empty)
    monkeypatch.setattr("ruleGenerator.src.panoramaData.AddressGroup.refreshall", empty)
    monkeypatch.setattr("ruleGenerator.src.panoramaData.DeviceGroup.refreshall", empty)
    monkeypatch.setattr("ruleGenerator.src.panoramaData.Template.refreshall", empty)
    monkeypatch.setattr("ruleGenerator.src.panoramaData.ApplicationObject.refreshall", empty)
    monkeypatch.setattr("ruleGenerator.src.panoramaData.ApplicationGroup.refreshall", empty)
    monkeypatch.setattr("ruleGenerator.src.panoramaData.ApplicationContainer.refreshall", empty)
    monkeypatch.setattr("ruleGenerator.src.panoramaData.ServiceObject.refreshall", empty)
    monkeypatch.setattr("ruleGenerator.src.panoramaData.ServiceGroup.refreshall", empty)

    # Short-circuit YAML loading; feed our own internalPrefixes list
    def fake_apply(self, *a, **kw):
        self._internalNets = [  # what _applyStaticOverrides normally sets
            __import__("ipaddress").ip_network(c) for c in INTERNALS
        ]
        self._externalZones = {"dmz"}  # mark “dmz” as external

    monkeypatch.setattr(
        "ruleGenerator.src.panoramaData.PanoramaData._applyStaticOverrides", fake_apply
    )

    return PanoramaData(pano_stub)


# ---------------------------------------------------------------------------
# _cidrIsExternal
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "cidr, expected",
    [
        ("10.1.1.0/24", False),                   # inside internal /8
        ("192.168.0.0/16", True),                # outside
        ("2001:db8:abcd::1/128", False),         # inside IPv6 internal
        ("2001:db8:beef::/48", True),            # outside IPv6 range
        ({"gte": "10.0.0.5", "lte": "10.0.0.10"}, False),
        ({"gte": "10.0.0.5", "lte": "11.0.0.10"}, True),
        ("any", True),
    ],
)
def test_cidrIsExternal(monkeypatch, pano_stub, cidr, expected):
    pdata = _bootstrap(monkeypatch, pano_stub)
    assert pdata._cidrIsExternal(cidr) is expected


# ---------------------------------------------------------------------------
# isExternal (rule-level)
# ---------------------------------------------------------------------------
def test_zone_based_external(monkeypatch, pano_stub):
    pdata = _bootstrap(monkeypatch, pano_stub)
    # Zone list with specific external zone overrides CIDR logic
    assert pdata.isExternal(
        cidrList=["10.1.1.1/32"], groupList=[], zoneList=["dmz"]
    )


def test_group_and_object_internal(monkeypatch, pano_stub):
    # Address object inside internal; group references it
    ao = AO("HR_NET", "10.2.0.0/24")
    ag = AG("HR_GROUP", ["HR_NET"])

    monkeypatch.setattr(
        "ruleGenerator.src.panoramaData.AddressObject.refreshall", lambda *_: [ao]
    )
    monkeypatch.setattr(
        "ruleGenerator.src.panoramaData.AddressGroup.refreshall", lambda *_: [ag]
    )

    pdata = _bootstrap(monkeypatch, pano_stub)

    assert pdata.isExternal(
        cidrList=[],
        groupList=["HR_NET", "HR_GROUP"],
        zoneList=None,
    ) is False


def test_any_group_trumps_internal(monkeypatch, pano_stub):
    pdata = _bootstrap(monkeypatch, pano_stub)
    assert pdata.isExternal(
        cidrList=["10.0.0.1/32"], groupList=["any"], zoneList=None
    )


def test_cidr_outside_internal(monkeypatch, pano_stub):
    pdata = _bootstrap(monkeypatch, pano_stub)
    assert pdata.isExternal(
        cidrList=["172.16.0.0/16"], groupList=[], zoneList=None
    )
