# tests/test_static_overrides.py
"""
Covers the YAML-driven static-override helper:

    • if-nonexistent / overwrite for AddressObjects
    • merge for application-to-port maps
"""

from types import SimpleNamespace
import textwrap
from pathlib import Path

import pytest

from ruleGenerator.core.inventory import PanoramaInventory          # inventory only
from ruleGenerator.core.overrides import apply_static_overrides
from ruleGenerator.core.ports import build_port_maps


# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

AO = lambda n, v: SimpleNamespace(name=n, value=v)          # tiny AddressObject stub


def _stub_empty_inventory(monkeypatch, pano_stub) -> PanoramaInventory:
    """
    Return a *blank* PanoramaInventory whose refreshall() calls are patched to
    produce no objects – the tests populate only the bits they need.
    """
    base = "ruleGenerator.core.inventory"
    empty = lambda *_: []

    monkeypatch.setattr(f"{base}.AddressObject.refreshall",        empty)
    monkeypatch.setattr(f"{base}.AddressGroup.refreshall",         empty)
    monkeypatch.setattr(f"{base}.ServiceObject.refreshall",        empty)
    monkeypatch.setattr(f"{base}.ServiceGroup.refreshall",         empty)
    monkeypatch.setattr(f"{base}.ApplicationObject.refreshall",    empty)
    monkeypatch.setattr(f"{base}.ApplicationGroup.refreshall",     empty)
    monkeypatch.setattr(f"{base}.ApplicationContainer.refreshall", empty)
    monkeypatch.setattr(f"{base}.DeviceGroup.refreshall",          empty)
    monkeypatch.setattr(f"{base}.Template.refreshall",             empty)

    inv = PanoramaInventory(pano_stub)

    # Build empty port-maps so overrides has the structures it expects
    build_port_maps(inv)
    return inv


def _write_yaml(tmp_path: Path, content: str) -> Path:
    f = tmp_path / "overrides.yml"
    f.write_text(textwrap.dedent(content))
    return f


# ---------------------------------------------------------------------------
#  Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def inv(monkeypatch, pano_stub):
    """
    A *clean* inventory instance whose AddressObject / Group classes are stubbed
    so we don't pull in the heavy pan-os-python objects.
    """
    # -- stub classes referenced inside core.overrides ---------------------
    monkeypatch.setattr(
        "ruleGenerator.core.overrides.AddressGroup",
        lambda name, static_value=None: SimpleNamespace(
            name=name, static_value=list(static_value or [])
        ),
    )
    #  _apply_address_objects() & _ensure_address_object() import this *locally*
    #  → patch the real import path.
    monkeypatch.setattr(
        "panos.objects.AddressObject",
        lambda name, value: SimpleNamespace(name=name, value=value),
        raising=False,            # path may not exist in test env
    )

    return _stub_empty_inventory(monkeypatch, pano_stub)


# ---------------------------------------------------------------------------
#  TESTS
# ---------------------------------------------------------------------------

def test_if_nonexistent_and_overwrite_address_objects(inv, tmp_path):
    """
    NEW_OBJ should be created (default mode == if_nonexistent)
    EXISTING should be overwritten 192.168.0.0/24 → 10.0.0.0/24
    """
    # seed EXISTING object
    inv.addressObjectByName["EXISTING"] = AO("EXISTING", "192.168.0.0/24")

    yaml_path = _write_yaml(
        tmp_path,
        """
        addressObjects:
          NEW_OBJ: 203.0.113.0/24

          EXISTING:
            _mode: overwrite
            value: 10.0.0.0/24
        """
    )

    apply_static_overrides(inv, yaml_path)

    assert inv.addressObjectByName["NEW_OBJ"].value == "203.0.113.0/24"
    assert inv.addressObjectByName["EXISTING"].value == "10.0.0.0/24"

    # _nets updated for both objects
    names_in_nets = {n for _, n in inv._nets}
    assert {"NEW_OBJ", "EXISTING"}.issubset(names_in_nets)


def test_merge_applications_adds_ports_without_dup(inv, tmp_path):
    """
    Start with web-app {tcp:[80]}, merge ports 81 & 82 and ensure final list
    keeps order and has no dups.
    """
    inv.applicationToPorts["web-app"] = {"tcp": ["80"]}

    yaml_path = _write_yaml(
        tmp_path,
        """
        applications:
          web-app:
            _mode: merge
            tcp: [81, 82]
        """
    )

    apply_static_overrides(inv, yaml_path)

    assert inv.applicationToPorts["web-app"]["tcp"] == ["80", "81", "82"]


def test_new_application_created_if_absent(inv, tmp_path):
    """
    Absence + default mode should *create* the application entry.
    """
    yaml_path = _write_yaml(
        tmp_path,
        """
        applications:
          new-app:
            tcp: [1234]
        """
    )
    apply_static_overrides(inv, yaml_path)

    assert inv.applicationToPorts["new-app"]["tcp"] == ["1234"]
