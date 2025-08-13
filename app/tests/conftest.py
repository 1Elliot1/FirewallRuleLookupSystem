# tests/conftest.py
import pytest
from types import SimpleNamespace
from ruleGenerator.src.panoramaData import PanoramaData

# Tiny helpers ------------------------------------------------------
AO = lambda n, v: SimpleNamespace(name=n, value=v)
AG = lambda n, members: SimpleNamespace(name=n, static_value=list(members))
SV = lambda n, proto, port: SimpleNamespace(
    name=n, protocol=proto, destination_port=port
)

# Stub for the content-DB wrapper ----------------------------------
class StubPredefined:
    def __init__(self, pano):
        self.pano = pano
        self.application_objects = {}
        self.application_container_objects = {}
        self.service_objects = {}

    def refreshall_applications(self):  # no-ops
        return None

    def refreshall_services(self):
        return None

# ------------------------------------------------------------------ 
# Panorama stub + default monkey-patches
# ------------------------------------------------------------------
@pytest.fixture
def pano_stub(monkeypatch):
    """Bare-bones fake `panos.panorama.Panorama` connection."""
    pano = SimpleNamespace(
        xapi=SimpleNamespace(          # .xapi.get()
            get=lambda *_, **__: SimpleNamespace(findall=lambda *_: [])
        ),
        op=lambda *_, **__: SimpleNamespace(findall=lambda *_: []),  # .op()
    )

    # ---- redirect all refreshall() calls to simple lists ----------
    tgt = "ruleGenerator.core.inventory"
    monkeypatch.setattr(f"{tgt}.AddressObject.refreshall",
                        lambda *_: [AO("HR_NET", "10.5.0.0/24")])
    monkeypatch.setattr(f"{tgt}.AddressGroup.refreshall",        lambda *_: [])
    monkeypatch.setattr(f"{tgt}.DeviceGroup.refreshall",         lambda *_: [])
    monkeypatch.setattr(f"{tgt}.Template.refreshall",            lambda *_: [])
    monkeypatch.setattr(f"{tgt}.ApplicationObject.refreshall",   lambda *_: [])
    monkeypatch.setattr(f"{tgt}.ApplicationGroup.refreshall",    lambda *_: [])
    monkeypatch.setattr(f"{tgt}.ApplicationContainer.refreshall",lambda *_: [])
    monkeypatch.setattr(f"{tgt}.ServiceObject.refreshall",       lambda *_: [])
    monkeypatch.setattr(f"{tgt}.ServiceGroup.refreshall",        lambda *_: [])

    # ---- stub out Predefined --------------------------------------
    monkeypatch.setattr(f"{tgt}.Predefined", StubPredefined)

    return pano

# Ready-to-use inventory instance ----------------------------------
@pytest.fixture
def pdata(pano_stub):
    return PanoramaData(pano_stub)
