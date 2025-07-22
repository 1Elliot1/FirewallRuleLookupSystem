# tests/test_static_overrides.py
"""
Covers PanoramaData._applyStaticOverrides:
    • default / if_nonexistent      → creates when missing
    • merge                         → extends but does not duplicate
    • overwrite                     → replaces value

We exercise two object families because the helper funnels them through the
same _applyByMode dispatcher:
    1. addressObjects      (simple scalar payload)
    2. applications        (dict payload with proto→port list)
"""

from types import SimpleNamespace
import textwrap
import yaml
import pytest
import ipaddress
from ruleGenerator.src.panoramaData import PanoramaData


# ---------------------------------------------------------------------------
# Helpers and fixtures
AO = lambda n, v: SimpleNamespace(name=n, value=v)


@pytest.fixture
def pdata_no_overrides(monkeypatch, pano_stub):
    """
    Instantiate PanoramaData **without** running the built-in static-override
    logic, so the tests start from a clean baseline and invoke it manually.
    """
    # capture original function so we can call it later
    orig_apply = PanoramaData._applyStaticOverrides
    monkeypatch.setattr("ruleGenerator.src.panoramaData.PanoramaData._applyStaticOverrides",
                        lambda self, *a, **kw: None)

    pd = PanoramaData(pano_stub)

    # restore original method on the class
    monkeypatch.setattr("ruleGenerator.src.panoramaData.PanoramaData._applyStaticOverrides",
                        orig_apply)
    return pd


def write_yaml(tmp_path, content: str):
    f = tmp_path / "overrides.yml"
    f.write_text(textwrap.dedent(content))
    return f


# ---------------------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------------------

def test_if_nonexistent_and_overwrite_address_objects(pdata_no_overrides, tmp_path):
    """
    • NEW_OBJ should be created (default mode == if_nonexistent)
    • EXISTING should be overwritten from 192.168.0.0/24 → 10.0.0.0/24
    """
    pd = pdata_no_overrides

    # seed EXISTING object so overwrite can change it
    pd.addressObjectByName["EXISTING"] = AO("EXISTING", "192.168.0.0/24")

    yaml_path = write_yaml(
        tmp_path,
        """
        addressObjects:
          NEW_OBJ: 203.0.113.0/24

          EXISTING:
            _mode: overwrite
            value: 10.0.0.0/24
        """
    )

    pd._applyStaticOverrides(yaml_path)

    # NEW_OBJ created
    assert pd.addressObjectByName["NEW_OBJ"].value == "203.0.113.0/24"
    # EXISTING updated
    assert pd.addressObjectByName["EXISTING"].value == "10.0.0.0/24"

    # _nets cache got updated for both objects
    nets = {name for _, name in pd._nets}
    assert {"NEW_OBJ", "EXISTING"}.issubset(nets)


def test_merge_applications_adds_ports_without_dup(pdata_no_overrides, tmp_path):
    """
    Start with web-app {tcp: [80]}, merge in ports 81 and 82, ensure
    final list is [80, 81, 82] (order preserved, no duplicates).
    """
    pd = pdata_no_overrides

    # pre-seed applicationToPorts
    pd.applicationToPorts["web-app"] = {"tcp": ["80"]}

    yaml_path = write_yaml(
        tmp_path,
        """
        applications:
          web-app:
            _mode: merge
            tcp: [81, 82]
        """
    )

    pd._applyStaticOverrides(yaml_path)

    assert pd.applicationToPorts["web-app"]["tcp"] == ["80", "81", "82"]


def test_new_application_created_if_absent(pdata_no_overrides, tmp_path):
    """
    If the application doesn't exist, default _mode ('merge' → if_nonexistent)
    should create it with given ports.
    """
    pd = pdata_no_overrides

    yaml_path = write_yaml(
        tmp_path,
        """
        applications:
          new-app:
            tcp: [1234]
        """
    )
    pd._applyStaticOverrides(yaml_path)

    assert pd.applicationToPorts["new-app"]["tcp"] == ["1234"]
