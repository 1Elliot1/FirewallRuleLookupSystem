import pytest
from unittest.mock import MagicMock, patch
from panoramaData import PanoramaData

class StubPanorama(MagicMock):
    """Mimics the pan-os-python Panorama object.
       Every API call returns controllable fake data.
    """

@pytest.fixture
def pano():
    """A panorama stub already loaded with empty lists for refreshall calls."""
    p = StubPanorama()
    # Generic refreshall mocks
    p.side_effect = None                    # just in case
    for cls in (
        "AddressObject", "AddressGroup", "DeviceGroup", "Template",
        "ApplicationObject", "ApplicationGroup", "ApplicationContainer",
        "ServiceObject", "ServiceGroup"
    ):
        patcher = patch(f"panoramaData.{cls}.refreshall", return_value=[])
        patcher.start()
        # let pytest clean up
        p.addCleanup(patcher.stop)
    return p

@pytest.fixture
def pdata(pano):
    """PanoramaData instance built from a stubbed Panorama."""
    return PanoramaData(pano)

#! Add extra helper fixtures later (e.g. internal_prefixes_yaml, sample_rule_docs) to keep individual test files tiny.