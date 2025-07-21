import ipaddress
from app.ruleGenerator.src import panoramaData as pd

PD = pd.PanoramaData()          # construct with minimal kwargs if needed
PD._internalNets = [ipaddress.ip_network("10.0.0.0/8")]

def test_cidr_is_external():
    assert PD._cidrIsExternal("8.8.8.0/24") is True
    assert PD._cidrIsExternal("10.1.1.0/24") is False

def test_cidr_compliment():
    result = pd.PanoramaData._cidrCompliment(PD, ["10.0.0.0/8"])
    assert "0.0.0.0/1" in result and "128.0.0.0/1" in result
