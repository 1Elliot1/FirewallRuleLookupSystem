"""ruleGenerator.core.overrides
================================
Static YAML‑driven mutations for a :class:`~ruleGenerator.core.inventory.PanoramaInventory`.

The old *monolith* folded a 400‑line `_applyStaticOverrides()` method into
PanoramaData.  We move that logic here so that the core inventory stays a
pure data snapshot while overrides are an **optional post‑processing step**.

Public API
----------

``apply_static_overrides(inv: PanoramaInventory, path: Path | str | None = None)``
    Merge the directives found in *staticOverrides.yml* (or a custom path)
    into *inv* – creating / modifying AddressObjects, groups, apps, service
    → port maps, VLANs, zones, etc.

Design notes
~~~~~~~~~~~~
* The helper mutates the passed ``PanoramaInventory`` *in‑place*.
* It expects that the caller already ran the **port‑map builder** from
  ``ruleGenerator.core.ports`` (so that ``inv.applicationToPorts`` & friends
  exist).  In the legacy flow this was the order as well.
* Most private helper functions are copied verbatim from the original code
  but turned into *module‑private* (leading underscore) stateless helpers so
  we can unit‑test them directly.
"""

from __future__ import annotations

import ipaddress
import logging
from pathlib import Path
from typing import List, Tuple

import yaml

from panos.objects import AddressGroup

from .inventory import PanoramaInventory

_LOG = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
#  Public entrypoint
# ---------------------------------------------------------------------------

def apply_static_overrides(inv: PanoramaInventory, path: str | Path | None = None) -> None:  # noqa: N802 – keep legacy name
    """Merge static‑override YAML into *inv* (in‑place)."""
    path = Path(path or inv.__class__.__module__).resolve().parent / "staticOverrides.yml" if path is None else Path(path)

    if not path.is_file():
        _LOG.warning("Static overrides file '%s' not found, skipping", path)
        return

    try:
        data = yaml.safe_load(path.read_text()) or {}
    except Exception as exc:  # pylint: disable=broad-except
        _LOG.error("Failed to load static overrides from '%s': %s", path, exc)
        return

    _LOG.info("Applying static overrides from %s", path)

    # ------------------------------------------------------------------
    #  Internal prefixes & EXT‑INTERNET synth
    # ------------------------------------------------------------------
    _apply_internal_external(inv, data)

    # ------------------------------------------------------------------
    #  Applications / services / address objects / groups / VLANs / zones
    # ------------------------------------------------------------------
    _apply_applications(inv, data.get("applications", {}))
    _apply_application_groups(inv, data.get("applicationGroups", {}))
    _apply_services(inv, data.get("services", {}))
    _apply_address_objects(inv, data.get("addressObjects", {}))
    _apply_address_groups(inv, data.get("addressGroups", {}))
    _apply_vlans(inv, data.get("vlans", {}))
    _apply_zones(inv, data.get("zones", {}))


# ===========================================================================
#  Helper sections – split by object family
# ===========================================================================

def _apply_internal_external(inv: PanoramaInventory, blob: dict) -> None:
    inside = blob.get("internalPrefixes", [])
    external_cidrs = _cidr_complement(inside)
    inv._externalZones = {z.lower() for z in blob.get("externalZones", [])}  # pylint: disable=protected-access

    inv._internalNets = [ipaddress.ip_network(c, strict=False) for c in inside]  # pylint: disable=protected-access

    # Ensure EXT‑INTERNET catch‑all
    _ensure_address_object(inv, "EXT-INTERNET", "0.0.0.0/0")

    # Create one AddressObject per external CIDR (EXT-1, EXT-2, …)
    member_names: List[str] = []
    for idx, cidr in enumerate(external_cidrs, 1):
        obj_name = f"EXT-{idx}"
        _ensure_address_object(inv, obj_name, cidr)
        member_names.append(obj_name)

    # Group EXT-INTERNET = [EXT-1, EXT-2, …]
    grp = inv.addressGroupByName.setdefault(
        "EXT-INTERNET",
        AddressGroup(name="EXT-INTERNET", static_value=[]),
    )
    grp.static_value = member_names

    for mem in member_names:
        inv._addrToGroup.setdefault(mem, []).append("EXT-INTERNET")  # pylint: disable=protected-access


def _apply_applications(inv: PanoramaInventory, blob: dict) -> None:
    for app, entry in blob.items():
        mode, payload = _extract_mode(entry)
        ports_map = {proto.lower(): [str(p) for p in ports] for proto, ports in (payload or {}).items()}

        exists = app in getattr(inv, "applicationToPorts", {})

        def create():
            inv.applicationToPorts.setdefault(app, {}).update(ports_map)  # type: ignore[attr-defined]

        def overwrite():
            inv.applicationToPorts[app] = ports_map  # type: ignore[attr-defined]

        def merge():
            target = inv.applicationToPorts.setdefault(app, {})  # type: ignore[attr-defined]
            for proto, plist in ports_map.items():
                target.setdefault(proto, [])
                target[proto].extend(p for p in plist if p not in target[proto])

        _apply_by_mode(mode, exists, merge, overwrite, create)


def _apply_application_groups(inv: PanoramaInventory, blob: dict) -> None:
    from panos.objects import ApplicationGroup  # local import to avoid heavy dep at module load

    for group, entry in blob.items():
        mode, payload = _extract_mode(entry)
        members = list(payload.get("members", []))
        exists = group in inv.appGroupByName

        def create():
            inv.appGroupByName[group] = ApplicationGroup(name=group, value=members)

        def overwrite():
            inv.appGroupByName[group].value = members

        def merge():
            g = inv.appGroupByName[group]
            g.value = list(set(g.value or []).union(members))

        _apply_by_mode(mode, exists, merge, overwrite, create)


def _apply_services(inv: PanoramaInventory, blob: dict) -> None:
    for svc, entry in blob.items():
        mode, payload = _extract_mode(entry)
        ports_map = {proto.lower(): list(ports) for proto, ports in (payload or {}).items()}
        exists = svc in getattr(inv, "serviceToPorts", {})

        def create():
            inv.serviceToPorts.setdefault(svc, {}).update(ports_map)  # type: ignore[attr-defined]

        def overwrite():
            inv.serviceToPorts[svc] = ports_map  # type: ignore[attr-defined]

        def merge():
            target = inv.serviceToPorts.setdefault(svc, {})  # type: ignore[attr-defined]
            for proto, plist in ports_map.items():
                target.setdefault(proto, [])
                target[proto].extend(p for p in plist if p not in target[proto])

        _apply_by_mode(mode, exists, merge, overwrite, create)


def _apply_address_objects(inv: PanoramaInventory, blob: dict) -> None:
    from panos.objects import AddressObject

    for name, entry in blob.items():
        mode, payload = _extract_mode(entry)
        cidr = payload.get("value") if isinstance(payload, dict) else payload
        exists = name in inv.addressObjectByName

        def create():
            inv.addressObjectByName[name] = AddressObject(name=name, value=cidr)
            _add_to_nets(inv, name, cidr)

        def overwrite():
            inv.addressObjectByName[name].value = cidr
            _add_to_nets(inv, name, cidr, replace=True)

        _apply_by_mode(mode, exists, lambda: None, overwrite, create)


def _apply_address_groups(inv: PanoramaInventory, blob: dict) -> None:
    from panos.objects import AddressGroup

    for group, entry in blob.items():
        mode, payload = _extract_mode(entry)
        members = list(payload.get("members", [])) if isinstance(payload, dict) else list(payload)
        exists = group in inv.addressGroupByName

        def create():
            inv.addressGroupByName[group] = AddressGroup(name=group, static_value=members)
            for m in members:
                inv._addrToGroup.setdefault(m, []).append(group)  # pylint: disable=protected-access

        def overwrite():
            inv.addressGroupByName[group].static_value = members
            for m in members:
                inv._addrToGroup.setdefault(m, []).append(group)  # pylint: disable=protected-access

        def merge():
            ag = inv.addressGroupByName[group]
            ag.static_value = list(set(ag.static_value or []).union(members))
            for m in members:
                inv._addrToGroup.setdefault(m, []).append(group)  # pylint: disable=protected-access

        _apply_by_mode(mode, exists, merge, overwrite, create)


def _apply_vlans(inv: PanoramaInventory, blob: dict) -> None:
    for tmpl_key, vlan_map in blob.items():
        inv.vlanData.setdefault(tmpl_key, {"vlanMap": {}, "zones": []})
        for vlan_id, entry in vlan_map.items():
            mode, payload = _extract_mode(entry)
            cidr = payload if isinstance(payload, str) else payload.get("value")
            exists = vlan_id in inv.vlanData[tmpl_key]["vlanMap"]

            def create():
                inv.vlanData[tmpl_key]["vlanMap"][vlan_id] = cidr

            def overwrite():
                inv.vlanData[tmpl_key]["vlanMap"][vlan_id] = cidr

            _apply_by_mode(mode, exists, lambda: None, overwrite, create)


def _apply_zones(inv: PanoramaInventory, blob: dict) -> None:
    for tmpl_key, entry in blob.items():
        mode, payload = _extract_mode(entry)
        new_zones = list(payload.get("members", [])) if isinstance(payload, dict) else list(entry)
        inv.vlanData.setdefault(tmpl_key, {"vlanMap": {}, "zones": []})
        exists = bool(inv.vlanData[tmpl_key]["zones"])

        def create():
            inv.vlanData[tmpl_key]["zones"].extend(new_zones)

        def overwrite():
            inv.vlanData[tmpl_key]["zones"] = new_zones

        def merge():
            prev = inv.vlanData[tmpl_key]["zones"]
            prev.extend(z for z in new_zones if z not in prev)

        _apply_by_mode(mode, exists, merge, overwrite, create)


# ---------------------------------------------------------------------------
#  Shared helper functions (stateless)
# ---------------------------------------------------------------------------

def _extract_mode(blob, default: str = "merge") -> Tuple[str, dict | list | str]:
    if isinstance(blob, dict) and "_mode" in blob:
        mode = str(blob.pop("_mode")).lower()
    else:
        mode = default
    return mode, blob


def _apply_by_mode(mode: str, exists: bool, merge_fn, overwrite_fn, create_fn) -> None:  # noqa: D401
    """Dispatch helper implementing the small *merge/overwrite/if_nonexistent* DSL."""
    if exists:
        if mode == "overwrite":
            overwrite_fn()
        elif mode == "merge":
            merge_fn()
    else:
        create_fn()


def _cidr_complement(cidrs: List[str]) -> List[str]:
    v4_everything = [ipaddress.ip_network("0.0.0.0/0")]
    v6_everything = [ipaddress.ip_network("::/0")]

    for raw in cidrs:
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        everything = v4_everything if net.version == 4 else v6_everything
        new_everything = []
        for block in everything:
            if net.subnet_of(block):
                new_everything.extend(block.address_exclude(net))
            else:
                new_everything.append(block)
        if net.version == 4:
            v4_everything = new_everything
        else:
            v6_everything = new_everything

    return [n.with_prefixlen for n in v4_everything + v6_everything if n.prefixlen != 0]


def _ensure_address_object(inv: PanoramaInventory, name: str, value: str) -> None:
    from panos.objects import AddressObject

    if name in inv.addressObjectByName:
        return
    inv.addressObjectByName[name] = AddressObject(name=name, value=value)
    _add_to_nets(inv, name, value)


def _add_to_nets(inv: PanoramaInventory, name: str, cidr: str, *, replace: bool = False) -> None:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return

    if replace:
        inv._nets[:] = [t for t in inv._nets if t[1] != name]  # pylint: disable=protected-access

    inv._nets.append((net, name))  # pylint: disable=protected-access


# ---------------------------------------------------------------------------
#  __all__
# ---------------------------------------------------------------------------
__all__ = ["apply_static_overrides"]
