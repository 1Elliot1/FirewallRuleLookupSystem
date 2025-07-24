"""ruleGenerator.core.inventory
================================
Low‑level *data pull* and fast‑lookup helpers extracted from the former
`panoramaData.PanoramaData` monolith.  The class defined here –
:class:`PanoramaInventory` – **does nothing except fetch & structure raw
Pan‑OS objects**:

* refreshes Panorama → local lists (`addressObjects`, `serviceObjects`, …)
* builds O(1) lookup dictionaries (``addressObjectByName`` …)
* provides a few convenience expansion helpers used by higher‑level code
  (group recursion, nested‑CIDR lookup, etc.)

Everything related to **static overrides**, **port‑resolution**, or
**metrics / hit‑counts** now lives in their own modules – see
``ruleGenerator.core.overrides``, ``ruleGenerator.core.ports`` and
``ruleGenerator.core.metrics``.

The public surface purposely mirrors the old PanoramaData attributes so
existing callers can transition gradually.
"""

from __future__ import annotations

import ipaddress
import logging
from collections import defaultdict
from functools import lru_cache
from typing import Dict, List, Set, Tuple

# pan‑os‑python ------------------------------------------------------------
from panos.panorama import Panorama, DeviceGroup, Template
from panos.policies import (
    PreRulebase,
    SecurityRule,
    NatRule,
    ApplicationOverride,
    PolicyBasedForwarding,
    DecryptionRule,
    AuthenticationRule,
)
from panos.network import AggregateInterface, Layer3Subinterface, Zone
from panos.device import Vsys
from panos.objects import (
    AddressObject,
    AddressGroup,
    ServiceObject,
    ServiceGroup,
    ApplicationObject,
    ApplicationGroup,
    ApplicationContainer,
)
from panos.predefined import Predefined

_LOG = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
#  Helpers & constants
# ---------------------------------------------------------------------------

RULE_TYPES = (
    SecurityRule,
    NatRule,
    ApplicationOverride,
    PolicyBasedForwarding,
    DecryptionRule,
    AuthenticationRule,
)

# Small utility shared by several modules -----------------------------------
@lru_cache(maxsize=None)
def ip_in_cidr(ip: str, cidr: str) -> bool:  # noqa: N802 – keep snake_case
    """Return *True* if *ip* (address or network) lies inside *cidr*.

    Used by higher‑level correlation helpers; kept here to avoid a tiny helper
    import round‑trip.
    """
    try:
        network = ipaddress.ip_network(cidr.strip("'[]"), strict=False)
    except ValueError as exc:
        _LOG.warning("Invalid CIDR '%s' for IP check: %s", cidr, exc)
        return False

    # Catch‑all 0.0.0.0/0 or ::/0 should *never* shadow more specific nets in
    # containment queries.
    if network.prefixlen == 0:
        return False

    try:
        if "/" in ip:
            subject = ipaddress.ip_network(ip, strict=False)
            return subject.version == network.version and subject.subnet_of(network)
        return ipaddress.ip_address(ip) in network
    except ValueError as exc:
        _LOG.warning("Invalid IP '%s' for CIDR check '%s': %s", ip, cidr, exc)
        return False


# ---------------------------------------------------------------------------
#  Main class – PanoramaInventory
# ---------------------------------------------------------------------------

class PanoramaInventory:  # pylint: disable=too-many-instance-attributes
    """Download & cache raw Panorama objects, plus fast look‑ups.

    Parameters
    ----------
    pano : :class:`panos.panorama.Panorama`
        **Already‑authenticated** Panorama connection.
    """

    # Public lists (typed for MyPy) -----------------------------------
    addressObjects: List[AddressObject]
    addressGroups: List[AddressGroup]
    serviceObjects: List[ServiceObject]
    serviceGroups: List[ServiceGroup]
    applicationObjects: List[ApplicationObject]
    applicationGroups: List[ApplicationGroup]
    applicationContainers: List[ApplicationContainer]

    # Fast look‑up maps ----------------------------------------------
    addressObjectByName: Dict[str, AddressObject]
    addressGroupByName: Dict[str, AddressGroup]
    serviceGroupByName: Dict[str, ServiceGroup]
    appGroupByName: Dict[str, ApplicationGroup]
    appContainerByName: Dict[str, ApplicationContainer]
    predefContainerByName: Dict[str, ApplicationContainer]
    leafAppNames: Set[str]

    # Big caches ------------------------------------------------------
    deviceGroupRules: Dict[str, Dict[str, List]]
    vlanData: Dict[str, Dict]

    # internal helpers ------------------------------------------------
    _addrToGroup: Dict[str, List[str]]
    _nets: List[Tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]]
    _expandedAppGroupCache: Dict[str, List[str]]

    # ----------------------------------------------------------------
    def __init__(self, pano: Panorama):
        self.pano = pano
        self.refresh()

    # ----------------------------------------------------------------
    #  Refresh entrypoint
    # ----------------------------------------------------------------
    def refresh(self) -> None:
        """Pull a fresh snapshot from Panorama into memory."""
        self._refresh_inventory()
        self._build_fast_maps()

        self.deviceGroupRules = {}
        self.vlanData = {}

        self._collect_device_group_rules()
        self._collect_vlan_data()

        # Pre‑defined container leaf expansion -----------------------
        self._refresh_predef_container_leaves()

    # ----------------------------------------------------------------
    #  Raw inventory pull
    # ----------------------------------------------------------------
    def _refresh_inventory(self) -> None:
        _LOG.info("Refreshing Panorama inventory …")

        self.addressObjects = AddressObject.refreshall(self.pano)
        self.addressGroups = AddressGroup.refreshall(self.pano)
        self.deviceGroups = DeviceGroup.refreshall(self.pano)
        self.templates = Template.refreshall(self.pano)
        self.applicationObjects = ApplicationObject.refreshall(self.pano)
        self.applicationGroups = ApplicationGroup.refreshall(self.pano)
        self.applicationContainers = ApplicationContainer.refreshall(self.pano)
        self.serviceObjects = ServiceObject.refreshall(self.pano)
        self.serviceGroups = ServiceGroup.refreshall(self.pano)

        # ---- predefined content DB ---------------------------------
        predef = Predefined(self.pano)
        predef.refreshall_applications()
        predef.refreshall_services()

        self._predefAppObjects = predef.application_objects
        self.predefContainerByName = predef.application_container_objects
        self._predefServiceObjects = predef.service_objects

    # ----------------------------------------------------------------
    #  Fast maps & helper caches
    # ----------------------------------------------------------------
    def _build_fast_maps(self) -> None:
        """O(1) look‑ups for names → objects; plus auxiliary caches."""
        self.addressObjectByName = {o.name: o for o in self.addressObjects}
        self.addressGroupByName = {g.name: g for g in self.addressGroups}
        self.serviceGroupByName = {g.name: g for g in self.serviceGroups}
        self.appGroupByName = {g.name: g for g in self.applicationGroups}
        self.appContainerByName = {c.name: c for c in self.applicationContainers}
        self.leafAppNames = {a.name for a in self.applicationObjects}

        # AddressObject → parent groups --------------------------------
        addr2grp: Dict[str, Set[str]] = defaultdict(set)
        for grp in self.addressGroups:
            for member in getattr(grp, "static_value", []):
                addr2grp[member].add(grp.name)
        self._addrToGroup = {k: sorted(v) for k, v in addr2grp.items()}

        # Net list for nested‑object queries ---------------------------
        self._nets = []
        for obj in self.addressObjects:
            try:
                net = ipaddress.ip_network(obj.value, strict=False)
                self._nets.append((net, obj.name))
            except ValueError:
                continue  # ignore bogus CIDRs silently – already logged upstream

        self._expandedAppGroupCache = {}

    # ----------------------------------------------------------------
    #  Predefined application containers
    # ----------------------------------------------------------------
    def _refresh_predef_container_leaves(self) -> None:
        leaves: Dict[str, List[str]] = {}
        for name in self.predefContainerByName:
            xpath = (
                "/config/predefined/application-container"
                f"/entry[@name='{name}']"
            )
            try:
                xml = self.pano.xapi.get(xpath=xpath)
                members = [m.text for m in xml.findall(".//functions/member")]
                leaves[name] = members or []
            except Exception as exc:  # pylint: disable=broad-except
                _LOG.warning("Predef container '%s' failed: %s", name, exc)
                leaves[name] = []
        self._predefinedContainerLeaves = leaves

    def expand_predef_container(self, name: str) -> List[str]:
        """Return leaves for a predefined application container."""
        return self._predefinedContainerLeaves.get(name, [])

    # ----------------------------------------------------------------
    #  Device‑group rule snapshot
    # ----------------------------------------------------------------
    def _collect_device_group_rules(self) -> None:
        total = 0
        for dg in self.deviceGroups:
            pre_rb = dg.find(PreRulebase) or PreRulebase()
            if pre_rb.parent is None:
                dg.add(pre_rb)

            bucket: Dict[str, List] = defaultdict(list)
            for rt in RULE_TYPES:
                rules = rt.refreshall(pre_rb)
                bucket[rt.__name__] = rules
                total += len(rules)
            self.deviceGroupRules[dg.name] = bucket

        _LOG.info("Collected %d pre‑rules across %d device groups", total, len(self.deviceGroupRules))

    # ----------------------------------------------------------------
    #  VLAN / Zone snapshot
    # ----------------------------------------------------------------
    def _collect_vlan_data(self) -> None:
        """Build *template‑vsys → vlanID → cidr* mapping."""
        for tmpl in self.templates:
            for vsys in tmpl.findall(Vsys):
                zones = vsys.findall(Zone)
                agg_ifaces = tmpl.findall(AggregateInterface)

                vlan_map: Dict[str, str] = {}
                for agg in agg_ifaces:
                    for subif in agg.findall(Layer3Subinterface):
                        try:
                            vlan, ip_cidr = subif.name.split(".")[1], subif.ip
                            vlan_map[vlan] = ip_cidr
                        except (IndexError, AttributeError):
                            _LOG.warning("Cannot parse VLAN from %s", subif.name)

                if vlan_map:
                    key = f"{tmpl.name}-{vsys.name}"
                    self.vlanData[key] = {"vlanMap": vlan_map, "zones": zones}

        _LOG.info("Collected VLAN data for %d template/vsys combos", len(self.vlanData))

    # ----------------------------------------------------------------
    #  Public helper methods (used by ruleDocumentBuilder & tests)
    # ----------------------------------------------------------------
    def address_groups_for_object(self, obj: AddressObject) -> List[str]:
        """Return direct / ancestor AddressGroups containing *obj*."""
        return self._addrToGroup.get(obj.name, [])

    # ----------------------------------------------------------------
    def expand_address_groups(self, group_name: str) -> List[str]:
        """Flatten *all* nested leaf members of an AddressGroup."""
        stack = [group_name]
        leaves: Set[str] = set()
        seen: Set[str] = set()
        while stack:
            g = stack.pop()
            if g in seen:
                continue
            seen.add(g)
            grp = self.addressGroupByName.get(g)
            if not grp:
                continue
            for member in getattr(grp, "static_value", []):
                if member in self.addressGroupByName:
                    stack.append(member)
                else:
                    leaves.add(member)
        return list(leaves)

    # ----------------------------------------------------------------
    def all_nested_group_names(self, group_name: str) -> List[str]:
        """Return *group_name* **plus** all nested child group names."""
        out: Set[str] = set()
        stack = [group_name]
        while stack:
            g = stack.pop()
            if g in out:
                continue
            out.add(g)
            grp = self.addressGroupByName.get(g)
            if not grp:
                continue
            for member in getattr(grp, "static_value", []):
                if member in self.addressGroupByName:
                    stack.append(member)
        return list(out)

    # ----------------------------------------------------------------
    @lru_cache(maxsize=None)
    def nested_objects_in_network(self, parent_cidr: str) -> Tuple[str, ...]:
        """Return names of AddressObjects fully contained within *parent_cidr*."""
        try:
            parent = ipaddress.ip_network(parent_cidr, strict=False)
        except ValueError:
            return ()

        if parent.prefixlen == 0:
            return ()

        return tuple(
            name
            for net, name in self._nets
            if net.version == parent.version and net != parent and net.subnet_of(parent)
        )
    # ----------------------------------------------------------------
    #  Application / service group helpers
    # ----------------------------------------------------------------

    def expand_applications(self, candidates: List[str]) -> List[str]:
        """Return the list of *leaf* applications after group/container
        expansion (keeps 'application-default' untouched)."""
        resolved: List[str] = []
        for app in candidates:
            if app == "application-default":
                resolved.append(app)
            elif app in self.leafAppNames:
                resolved.append(app)
            elif app in self.appGroupByName:
                resolved.extend(self._expand_app_group(app))
            elif app in self.predefContainerByName:
                resolved.extend(self.expand_predef_container(app))
            else:
                resolved.append(app)
        # preserve order, deduplicate
        return list(dict.fromkeys(resolved))

    def expand_services(self, svcs: List[str]) -> List[str]:
        resolved: Set[str] = set()
        for svc in svcs:
            if svc in self.serviceGroupByName:
                resolved.update(self._expand_service_group(svc))
            else:
                resolved.add(svc)
        return list(resolved)

    # ---- private, cached recursion helpers ------------------------

    def _expand_app_group(self, name: str) -> List[str]:
        cache = self._expandedAppGroupCache
        if name in cache:
            return cache[name]

        grp = self.appGroupByName.get(name)
        if not grp:
            return [name]

        leaves: List[str] = []
        for member in getattr(grp, "value", []):
            if member in self.appGroupByName:
                leaves.extend(self._expand_app_group(member))
            elif member in self.predefContainerByName:
                leaves.extend(self.expand_predef_container(member))
            else:
                leaves.append(member)

        deduped = list(dict.fromkeys(leaves))
        cache[name] = deduped
        return deduped

    from functools import lru_cache as _lru  # local alias

    @_lru(maxsize=None)
    def _expand_service_group(self, name: str) -> Tuple[str, ...]:
        grp = self.serviceGroupByName.get(name)
        if not grp:
            return (name,)

        leaves: Set[str] = set()
        for member in getattr(grp, "value", []):
            if member in self.serviceGroupByName:
                leaves.update(self._expand_service_group(member))
            else:
                leaves.add(member)
        return tuple(leaves)

    # ----------------------------------------------------------------
    #  Convenience combo helper used by rule builders
    # ----------------------------------------------------------------
    def resolve_app_and_service_groups(
        self, apps: List[str] | None, services: List[str] | None
    ) -> Tuple[List[str], List[str]]:
        return (
            self.expand_applications(apps or []),
            self.expand_services(services or []),
        )


# ---------------------------------------------------------------------------
#  __all__
# ---------------------------------------------------------------------------
__all__ = [
    "PanoramaInventory",
    "ip_in_cidr",
]
