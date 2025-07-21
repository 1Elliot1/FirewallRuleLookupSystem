import panoramaData as pd

PD = pd.PanoramaData()
PD._internalNets   = []
PD._externalZones  = {"untrust", "dmz"}

def param(is_ext, zones, cidrs, groups):
    return is_ext, zones, cidrs, groups

CASES = [
    param(True,  ["untrust"], [], []),
    param(False, ["inside"],  ["10.1.1.0/24"], []),
    param(True,  ["any"],     [], ["any"]),
]

import pytest
@pytest.mark.parametrize("expected,zones,cidrs,groups", CASES)
def test_is_external(expected, zones, cidrs, groups):
    assert PD.isExternal(cidrList=cidrs, groupList=groups, zoneList=zones) == expected
