# tests/conftest.py
import pytest
from types import SimpleNamespace
from ruleGenerator.src.panoramaData import PanoramaData

# Helpers to create tiny stand-in objects
AO = lambda n, v: SimpleNamespace(name=n, value=v)         # AddressObject
AG = lambda n, members: SimpleNamespace(name=n, static_value=list(members))
SV = lambda n, proto, port: SimpleNamespace(
        name=n, protocol=proto, destination_port=port)


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

    # -- generic default refreshall() returns ----------------------
    monkeypatch.setattr("panoramaData.AddressObject.refreshall",
                        lambda *_: [AO("HR_NET", "10.5.0.0/24")])
    monkeypatch.setattr("panoramaData.AddressGroup.refreshall",        lambda *_: [])
    monkeypatch.setattr("panoramaData.DeviceGroup.refreshall",         lambda *_: [])
    monkeypatch.setattr("panoramaData.Template.refreshall",            lambda *_: [])
    monkeypatch.setattr("panoramaData.ApplicationObject.refreshall",   lambda *_: [])
    monkeypatch.setattr("panoramaData.ApplicationGroup.refreshall",    lambda *_: [])
    monkeypatch.setattr("panoramaData.ApplicationContainer.refreshall",lambda *_: [])
    monkeypatch.setattr("panoramaData.ServiceObject.refreshall",       lambda *_: [])
    monkeypatch.setattr("panoramaData.ServiceGroup.refreshall",        lambda *_: [])

    return pano

# Ready-to-use PanoramaData instance
@pytest.fixture
def pdata(pano_stub):
    """Fresh PanoramaData with default stub inventory."""
    return PanoramaData(pano_stub)
