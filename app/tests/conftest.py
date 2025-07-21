# tests/conftest.py
import pytest
from types import SimpleNamespace
import ruleGenerator.src.panoramaData as pano_mod
from ruleGenerator.src.panoramaData import PanoramaData

# Helpers to create tiny stand-in objects
AO = lambda n, v: SimpleNamespace(name=n, value=v)         # AddressObject
AG = lambda n, members: SimpleNamespace(name=n, static_value=list(members))
SV = lambda n, proto, port: SimpleNamespace(
        name=n, protocol=proto, destination_port=port)

class StubPredefined:
    """Stand-in for panos.predefined.Predefined used by PanoramaData."""
    def __init__(self, pano):
        self.pano = pano
        self.application_objects = {}
        self.application_container_objects = {}
        self.service_objects = {}

    def refreshall_applications(self):
        return None        # no-op

    def refreshall_services(self):
        return None        # no-op


# Panorama stub
@pytest.fixture
def pano_stub(monkeypatch):
    """
    Fake `panos.panorama.Panorama` that satisfies everything PanoramaData
    touches.  Individual tests can monkey-patch refreshall() again to return
    different data without re-creating the fixture.
    """
    pano = SimpleNamespace(
        # pano.xapi.get(...) --> must return an Element-like obj
        xapi=SimpleNamespace(get=lambda *_, **__: SimpleNamespace(findall=lambda *_: [])),
        # pano.op(...) -> hit-count XML; we’ll override per-test when needed
        op=lambda *_, **__: SimpleNamespace(findall=lambda *_: []),
    )
    
    # ---- Predefined stub ----------------------------------------
    monkeypatch.setattr("ruleGenerator.src.panoramaData.Predefined", StubPredefined)

    # ---- default refreshall() returns ---------------------------
    monkeypatch.setattr("ruleGenerator.src.panoramaData.AddressObject.refreshall",
                        lambda *_: [AO("HR_NET", "10.5.0.0/24")])
    
    # -- generic default refreshall() returns ----------------------
    monkeypatch.setattr("ruleGenerator.src.panoramaData.AddressObject.refreshall",
                        lambda *_: [AO("HR_NET", "10.5.0.0/24")])
    monkeypatch.setattr("ruleGenerator.src.panoramaData.AddressGroup.refreshall",        lambda *_: [])
    monkeypatch.setattr("ruleGenerator.src.panoramaData.DeviceGroup.refreshall",         lambda *_: [])
    monkeypatch.setattr("ruleGenerator.src.panoramaData.Template.refreshall",            lambda *_: [])
    monkeypatch.setattr("ruleGenerator.src.panoramaData.ApplicationObject.refreshall",   lambda *_: [])
    monkeypatch.setattr("ruleGenerator.src.panoramaData.ApplicationGroup.refreshall",    lambda *_: [])
    monkeypatch.setattr("ruleGenerator.src.panoramaData.ApplicationContainer.refreshall", lambda *_: [])
    monkeypatch.setattr("ruleGenerator.src.panoramaData.ServiceObject.refreshall",       lambda *_: [])
    monkeypatch.setattr("ruleGenerator.src.panoramaData.ServiceGroup.refreshall",        lambda *_: [])

    return pano

# Ready-to-use PanoramaData instance
@pytest.fixture
def pdata(pano_stub):
    """Fresh PanoramaData with default stub inventory."""
    return PanoramaData(pano_stub)
