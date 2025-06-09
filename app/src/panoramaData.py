"""Panorama inventory & correlation layer

Wraps the pan‑os‑python calls, builds fast look‑up maps, expands groups /
containers and flattens data to be structured elswhere 

Usage
~~~~~
```python
from panos.panorama import Panorama
from panoramaData import PanoramaData
from ruleDocumentBuilder import buildRuleDocuments

pano = Panorama(hostname, api_key=key)
inventory  = PanoramaData(pano)

ruleDocs = buildRuleDocs(inventory)
```
"""

from __future__ import annotations

import ipaddress
import logging
from collections import defaultdict
from functools import lru_cache
from typing import Dict, List, Set, Tuple
import yaml
from pathlib import Path

from panos.panorama import Panorama, DeviceGroup, Template
from panos.policies import (
    PreRulebase,
    #PostRulebase,
    #Rulebase,
    SecurityRule,
    NatRule,
    ApplicationOverride,
    PolicyBasedForwarding,
    DecryptionRule,
    AuthenticationRule,
)
from panos.network import (
    AggregateInterface,
    Layer3Subinterface,
    #Vlan,
    Zone,
)
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

_LOG = logging.getLogger("panoramaData")

# ---------------------------------------------------------------------------
#  Setup/Helpers
# ---------------------------------------------------------------------------


RULE_TYPES = (
    SecurityRule,
    NatRule,
    ApplicationOverride,
    PolicyBasedForwarding,
    DecryptionRule,
    AuthenticationRule,
)

#RULEBASE_CLASSES = (PreRulebase, Rulebase, PostRulebase)

#lru_cache to speed up repeated lookups
#TODO: Look into the lru_cache decorator to see how it works/what it exactly does
@lru_cache(maxsize=None)
def _ip_in_cidr(ip: str, cidr: str) -> bool:
    """Fast *utility* used by higher‑level correlation helpers."""
    try:
        network = ipaddress.ip_network(cidr.strip("'[]"), strict=False)
    except ValueError:
        return False

    if network.prefixlen == 0:  # 0.0.0.0/0 catch‑all. Ignore
        return False

    try:
        if "/" in ip:
            subject = ipaddress.ip_network(ip, strict=False)
            return (
                subject.version == network.version and subject.subnet_of(network)
            )
        return ipaddress.ip_address(ip) in network
    except ValueError:
        return False


# ---------------------------------------------------------------------------
#  PanoramaData Class (Collect and Correlate PanOS Objects)
# ---------------------------------------------------------------------------

class PanoramaData:
    """
    Collects desired objects from Panorama and prepares fast lookup maps
    (can plug in whatever builder script you want onto this output)
    """

    # Public attrs that callers may read ---------------------------
    addressObjects: List[AddressObject]
    addressGroups:  List[AddressGroup]
    serviceObjects: List[ServiceObject]
    serviceGroups:  List[ServiceGroup]
    applicationObjects: List[ApplicationObject]
    applicationGroups: List[ApplicationGroup]
    applicationContainers: List[ApplicationContainer]

    # Fast lookup dicts -------------------------------------------
    addressObjectByName: Dict[str, AddressObject]
    addressGroupByName: Dict[str, AddressGroup]
    serviceGroupByName: Dict[str, ServiceGroup]
    appGroupByName: Dict[str, ApplicationGroup]
    appContainerByName: Dict[str, ApplicationContainer]
    predefContainerByName: Dict[str, ApplicationContainer]
    leafAppNames: Set[str]

    # Big caches --------------------------------------------------
    deviceGroupRules: Dict[str, Dict[str, List]]
    vlanData: Dict[str, Dict]
    applicationToPorts: Dict[str, Dict[str, List[str]]]
    serviceToPorts: Dict[str, Dict[str, List[str]]]
    portToEntities: Dict[str, Dict[str, List[str]]]

    #predefined application containers -> Member leaves
    _predefinedContainerLeaves: Dict[str, List[str]] = {}  

    #ruleHitCounts: {ruleType: ruleName: hitCount}
    ruleHitCounts: Dict[str, Dict[str, int]]

    def __init__(self, pano: Panorama) -> None:
        self.pano = pano
        self._refreshPanoramaInventory()
        self._buildFastMaps()

        self._refreshPredefContainerLeaves()

        self.deviceGroupRules = {}
        self.vlanData = {}

        self._collectDeviceGroupRules()
        self._collectHitCounts()
        self._collectVlanData()
        self._buildApplicationServicePortMaps()

        self._applyStaticOverrides()

    # ------------------------------------------------------------------
    #  Inventory Private Methods
    # ------------------------------------------------------------------

    def _refreshPanoramaInventory(self) -> None:
        """Grab **everything** from Panorama into lists."""
        _LOG.info("Refreshing Panorama inventory …")

        self.addressObjects       = AddressObject.refreshall(self.pano)
        self.addressGroups        = AddressGroup.refreshall(self.pano)
        self.deviceGroups         = DeviceGroup.refreshall(self.pano)
        self.templates             = Template.refreshall(self.pano)
        self.applicationObjects   = ApplicationObject.refreshall(self.pano)
        self.applicationGroups    = ApplicationGroup.refreshall(self.pano)
        self.applicationContainers = ApplicationContainer.refreshall(self.pano)
        self.serviceObjects       = ServiceObject.refreshall(self.pano)
        self.serviceGroups        = ServiceGroup.refreshall(self.pano)

        # Pre‑defined apps & services (content DB)
        predef = Predefined(self.pano)
        predef.refreshall_applications()
        predef.refreshall_services()

        self._predefAppObjects       = predef.application_objects
        self.predefContainerByName  = predef.application_container_objects
        self._predefServiceObjects   = predef.service_objects

    def _buildFastMaps(self) -> None:
        """Prepare O(1) look‑up maps used later in correlations."""
        #TODO: Determine how to handle predefined objects. Don't seem to be added to the main maps, although much of the applications in pano are predefined
        self.addressObjectByName   = {o.name: o for o in self.addressObjects}
        self.addressGroupByName = {g.name: g for g in self.addressGroups}
        self.serviceGroupByName = {g.name: g for g in self.serviceGroups}
        self.appGroupByName     = {g.name: g for g in self.applicationGroups}
        self.appContainerByName = {c.name: c for c in self.applicationContainers}
        self.leafAppNames        = {a.name for a in self.applicationObjects}

        # Address to group mapping
        # This is a map of address object names to the groups they belong to (key is the address object name, value is a list of group names)
        addr2grp: Dict[str, Set[str]] = defaultdict(set)
        for grp in self.addressGroups:
            for member in getattr(grp, "static_value", []):
                addr2grp[member].add(grp.name)
        self._addrToGroup = {k: sorted(v) for k, v in addr2grp.items()}

        #Set up a list of tuples containing the networks and their object names to use for adding sub addr objects' names to rules
        self._nets: list[tuple[ipaddress.IPv4Network, str]] = [] #list of tuples: (network, objectName)
        for object in self.addressObjects:
            try:
                net = ipaddress.ip_network(object.value, strict=False)
                self._nets.append((net, object.name))
            except ValueError:
                continue
        
        # Cache to avoid re‑expanding the same app group 1000× --------
        self._expandedAppGroupCache: Dict[str, List[str]] = {}

    # ---------------Predefined Containers ----------------------------
    def _refreshPredefContainerLeaves(self) -> None:
        leaves: Dict[str, List[str]] = {}
        for name in self.predefContainerByName:
            xpath = ("/config/predefined/application-container"
                     f"/entry[@name='{name}']")
            try:
                xml = self.pano.xapi.get(xpath=xpath)
                members = [m.text for m in xml.findall(".//functions/member")]
                leaves[name] = members or []
            except Exception as exc:
                _LOG.warning("Predef container '%s' failed: %s", name, exc)
                leaves[name] = []
        self._predefinedContainerLeaves = leaves
    
    def _expandPredefContainer(self, name: str) -> list[str]:
        #Check XML API Cache for pre-defined container members
        #!This returns the name of the members of a container, not the actual application objects
        return self._predefinedContainerLeaves.get(name, [])

    @lru_cache(maxsize=None)
    def nestedObjectsInNetwork(self, parentCidr: str) -> tuple[str, ...]:
        """
        Return names of all AddressObjects whos CIDR/host network is fully contained in parentCidr (excluding identical object)
        """
        try:
            parent = ipaddress.ip_network(parentCidr, strict=False)
        except ValueError:
            return ()
        
        out: list[str] = [
            name
            for net, name in self._nets
            if net.version == parent.version
            and net != parent
            and net.subnet_of(parent)
        ]
        return tuple(out)   

        
    # -----------Rule Fetching ---------------------------------------

    def _collectDeviceGroupRules(self) -> None:
        """Fetch ONLY the pre-rulebase slice, creating the wrapper if absent."""
        total = 0
        for dg in self.deviceGroups:
            #get or create the pre-rulebase node
            pre_rb = dg.find(PreRulebase)
            if pre_rb is None:
                pre_rb = PreRulebase()
                dg.add(pre_rb)

            #pull every rule type
            bucket: Dict[str, List] = defaultdict(list)
            for rt in RULE_TYPES:
                rules = rt.refreshall(pre_rb)
                bucket[rt.__name__] = rules
                total += len(rules)

            self.deviceGroupRules[dg.name] = bucket
        _LOG.info("Collected %d pre‑rules across %d device groups", total, len(self.deviceGroupRules))

    # ----------VLAN and Zone Handling----------------------------------------

    def _collectVlanData(self) -> None:
        """
        Populate self.vlanData with VLAN -> CIDR + Zone list per template
        """
        for tmpl in self.templates:
            for vsys in tmpl.findall(Vsys):
                zones = vsys.findall(Zone)
                aggIfaces = tmpl.findall(AggregateInterface)

                vlanMap: Dict[str, str] = {}
                for agg in aggIfaces:
                    #TODO: Figure out if you need to handle any othercases of subinterfaces (Not layer3-- Unsure if these exist in our env)
                    for subif in agg.findall(Layer3Subinterface):
                        try:
                            #Create a mapping of VLAN numbers to their associated IP ranges
                            #!Assumes that subinterface name format is <name>.<vlanNumber>
                            #TODO: Figure out if there is a way to handle naming conventions that do not follow this, even though it works for this env for now 
                            vlan, ipCidr = subif.name.split(".")[1], subif.ip
                            vlanMap[vlan] = ipCidr
                        except (IndexError, AttributeError):
                            _LOG.warning("Cannot parse VLAN from %s", subif.name)
                if vlanMap:
                    key = f"{tmpl.name}-{vsys.name}"
                    self.vlanData[key] = {"vlanMap": vlanMap, "zones": zones}

        _LOG.info("Collected VLAN data for %d template/vsys combos", len(self.vlanData))


    # --------- App and Service -> Ports ---------------------------

    def _buildApplicationServicePortMaps(self) -> None:
        self.applicationToPorts: Dict[str, Dict[str, List[str]]] = {}
        self.serviceToPorts: Dict[str, Dict[str, List[str]]] = {}
        portToEntities: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: {
            "applications": [],
            "services": [],
        })

        # ---- Applications -----------------------------------------

        for app in self.applicationObjects + list(self._predefAppObjects.values()):
            ports: Dict[str, List[str]] = defaultdict(list)

            for entry in getattr(app, "default_port", []) or []:
                try:
                    proto, blob = entry.split("/")
                    proto = proto.lower()
                    if proto not in {"tcp", "udp", "icmp"}:
                        continue

                    for part in blob.split(","):
                        part = part.strip()
                        ports[proto].append(part)
                        portToEntities[f"{proto}/{part}"]["applications"].append(app.name)
                except ValueError:
                    _LOG.debug("Cannot parse app port entry: %s", entry)
            self.applicationToPorts[app.name] = ports

        # ---- Services ---------------------------------------------
        for svc in self.serviceObjects + list(self._predefServiceObjects.values()):
            if not (svc.protocol and svc.destination_port):
                continue
            proto = svc.protocol.lower()
            if proto not in {"tcp", "udp", "icmp"}:
                continue 
            self.serviceToPorts[svc.name] = {proto: [svc.destination_port]}
            portToEntities[f"{proto}/{svc.destination_port}"]["services"].append(svc.name)

        self.portToEntities = dict(portToEntities)
        _LOG.info("Port maps built: %d apps, %d services", len(self.applicationToPorts), len(self.serviceToPorts))


    #  Public helpers reused by ruleDocumentBuiilder (or whatever other script you decide to plug into this)
    # ------------------------------------------------------------------

    def addressGroupsForObject(self, object: AddressObject) -> List[str]:
        """
        All direct or ancestor Address Groups containing supplied AddressObject
        """
        return self._addrToGroup.get(object.name, [])

    def expandAddressGroups(self, groupName: str) -> List[str]:
        """
        Return all nested members (recursively) of an Address Group (Leaf objects only)
        """
        #TODO: Determine if this still maintains the groups that are impacted by a rule, or strictly all of the leaf objects they resolve to
        #!If it only resolves to leave objects, figure out if that is the desired behavior
        stack = [groupName]
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
                # If the member is another group, add it to the stack for further expansion
                if member in self.addressGroupByName:
                    stack.append(member)
                else:
                    # Otherwise, it's a leaf address object
                    leaves.add(member)
        
        return list(leaves)
    
    def allNestedGroupNames(self, groupName: str) -> List[str]:
        """
        Return {groupName} and all nested child group names recursively
        """
        out: set[str] = set()
        stack = [groupName]
        while stack:
            #grab a group from stack
            g  = stack.pop()
            #if groups already been seen, skip
            if g in out:
                continue
            #add group to seenlist
            out.add(g)
            #get the group object from the map by its name
            grp = self.addressGroupByName.get(g)
            if not grp:
                continue
            #get all members of group
            for member in getattr(grp, "static_value", []):
                #if a member is a group, add to stack to expand it as well
                if member in self.addressGroupByName:
                    stack.append(member)
        return list(out)

    # ---- Application and Service Expansion -------------------------

    def resolveAppAndServiceGroups(
        self,
        apps: List[str] | None,
        services: List[str] | None,
    ) -> Tuple[List[str], List[str]]:
        
        """
        Entry point used by ruleDocumentBuilder
        """
        
        return (
            self._expandApplications(apps or []),
            self._expandServices(services or []),
        )

    # Private Methods for resolving applications and services..........

    def _expandApplications(self, candidates: List[str]) -> List[str]:
        """
        Expand application names, groups and containers into a flat list of leaf app names.
        """
        resolved: List[str] = []
        for app in candidates:
            if app == "application-default":
                resolved.append(app)
            elif app in self.leafAppNames:
                resolved.append(app)
            elif app in self.appGroupByName:
                resolved.extend(self._expandAppGroup(app))
            # elif app in self.appContainerByName:
            #     resolved.extend(self._expandAppContainer(app))
            elif app in self.predefContainerByName:
                resolved.extend(self._expandPredefContainer(app))
            else:
                resolved.append(app)
        # preserve order but dedupe
        return list(dict.fromkeys(resolved))

    def _expandServices(self, svcs: List[str]) -> List[str]:
        resolved: Set[str] = set()
        for svc in svcs:
            if svc in self.serviceGroupByName:
                resolved.update(self._expandServiceGroup(svc))
            else:
                resolved.add(svc)
        return list(resolved)

    # ---- recursive helpers with caching --------------------------

    def _expandAppGroup(self, name: str) -> List[str]:
        if name in self._expandedAppGroupCache:
            return self._expandedAppGroupCache[name]

        grp = self.appGroupByName.get(name)
        if not grp:
            return [name]

        leaves: List[str] = []
        for member in getattr(grp, "value", []):
            if member in self.appGroupByName:
                leaves.extend(self._expandAppGroup(member))
            # elif member in self.appContainerByName:
            #     leaves.extend(self._expandAppContainer(member))
            elif member in self.predefContainerByName:
                leaves.extend(self._expandPredefContainer(member))
            else:
                leaves.append(member)
        deduped = list(dict.fromkeys(leaves))
        self._expandedAppGroupCache[name] = deduped
        return deduped

#TODO: _ExpandAppContaier function for non-predefined containers?

    @lru_cache(maxsize=None)
    def _expandServiceGroup(self, name: str) -> Tuple[str, ...]:
        grp = self.serviceGroupByName.get(name)
        if not grp:
            return (name,)
        leaves: Set[str] = set()
        for member in getattr(grp, "value", []):
            if member in self.serviceGroupByName:
                leaves.update(self._expandServiceGroup(member))
            else:
                leaves.add(member)
        return tuple(leaves)


    #  Port resolution helper (used by ruleDocumentBuilder)
    # ------------------------------------------------------------------

    def enrichRuleWithPorts(
        self,
        apps: List[str],
        services: List[str],
        serviceFieldRaw: List[str],
    ) -> Dict[str, List | Dict]:
        """
        Resolve all <protocol>/<port> pairs a rule allows and return
        {"resolvedPorts": [...], "portReasoning": {...}}.

        * `apps` / `services` must be fully expanded (no groups).
        * Keeps application-default semantics intact.
        """
        resolvedPorts: Set[str] = set()
        reasoning: Dict[str, List[str]] = {}

        # --- application-default -------------------------------------
        if serviceFieldRaw == ["application-default"]:
            for app in apps:
                portMap = self.applicationToPorts.get(app, {})
                for proto, portList in portMap.items():
                    for port in portList:
                        key = f"{proto}/{port}"
                        resolvedPorts.add(key)
                        reasoning.setdefault(key, []).append(
                            f"{app} (application-default)"
                        )

        # --- explicit service objects --------------------------------
        for svc in services:
            if svc == "application-default":
                continue
            portMap = self.serviceToPorts.get(svc, {})
            for proto, portList in portMap.items():
                for port in portList:
                    key = f"{proto}/{port}"
                    resolvedPorts.add(key)
                    reasoning.setdefault(key, []).append(
                        f"{svc} (service object)"
                    )

        return {
            "resolvedPorts": sorted(resolvedPorts),
            "portReasoning": reasoning,
        }
    
    # ------Static Override YAML Loader----------------------------------
    def _applyStaticOverrides(self, path: str | Path = "app/src/staticOverrides.yml") -> None:
        """
        Load static overrides from a YAML file and apply them to the inventory
        for overriding or adding specific rules or objects not captured by the API
        """
        if not Path(path).is_file():
            _LOG.warning("Static overrides file '%s' not found, skipping", path)
            return
        
        try:
            data = yaml.safe_load(Path(path).read_text()) or {}
        except Exception as exc:
            _LOG.error("Failed to load static overrides from '%s': %s", path, exc)
            return
        
        # ----- Applications to Ports
        for app, protoMap in data.get("applications", {}).items():
            self.applicationToPorts.setdefault(app, {})
            for proto, ports in (protoMap or {}).items():
                proto = proto.lower()
                self.applicationToPorts[app].setdefault(proto, [])
                self.applicationToPorts[app][proto].extend(ports)
        
        # ----- Application Groups
        for group, members in (data.get("applicationGroups") or {}).items():
            self.appGroupByName.setdefault(group, ApplicationGroup(name=group, value = []))
            existing = set(getattr(self.appGroupByName[group], "value", []))
            self.appGroupByName[group].value = list(existing.union(members))
        
        # ----- Services to Ports
        for svc, protoMap in data.get("services", {}).items():
            self.serviceToPorts.setdefault(svc, {})
            for proto, ports in (protoMap or {}).items():
                proto = proto.lower()
                self.serviceToPorts[svc].setdefault(proto, [])
                self.serviceToPorts[svc][proto].extend(ports)
        
        # ----- Address Objects
        for name, cidr in (data.get("addressObjects") or {}).items():
            if name not in self.addressObjectByName:
                self.addressObjectByName[name] = AddressObject(name=name, value=cidr)
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    self._nets.append((net, name))
                except ValueError:
                    _LOG.warning("Invalid CIDR '%s' for address object '%s'", cidr, name)
                    pass

        # ----- Address Groups
        for group, members in (data.get("addressGroups") or {}).items():
            ag = self.addressGroupByName.setdefault(group, AddressGroup(name=group, static_value=[]))
            ag.static_value = list(set(ag.static_value or []).union(members))
            for m in members:
                self._addrToGroup.setdefault(m, []).append(group)

        # ----- VLAN / Zone 
        for key, vlanMap in (data.get("vlans") or {}).items():
            self.vlanData.setdefault(key, {"vlanMap": {}, "zones": []})
            self.vlanData[key]["vlanMap"].update(vlanMap)

        for key, zones in (data.get("zones") or {}).items():
            self.vlanData.setdefault(key, {"vlanMap": {}, "zones": []})
            self.vlanData[key]["zones"].extend(z for z in zones if z not in self.vlanData[key]["zones"])

        _LOG.info("Static overrides from %s merged", path)

    # -------------- Additional Metrics for Elasticsearch ----------
    def calcRuleWeight(self, doc: dict) -> int:
        weight = (
            len(doc["source"]["address"]["objects"]) 
            + len(doc["destination"]["address"]["objects"])
            + len(doc["services"]) * 5
            + len(doc["applications"]) * 5
        )
        return weight

    def isShadowed(self, candidate: dict, earlier: list[dict]) -> bool:
        """
        Check if the canidate rule is shadowed by any of the earlier rules
        """
        for sup in earlier:                                     # iterate top-down
            if sup["action"] != candidate["action"]:
                continue

            if not self._subset(candidate["source"]["zones"], sup["source"]["zones"]):
                continue
            if not self._subset(candidate["destination"]["zones"], sup["destination"]["zones"]):
                continue
            if not self._subset(candidate["applications"], sup["applications"]):
                continue
            if not self._subset(candidate["services"], sup["services"]):
                continue
            if not self._cidrs_cover(                         # src CIDRs
                    candidate["source"]["address"]["cidr"],
                    sup["source"]["address"]["cidr"]
                ):
                continue
            if not self._cidrs_cover(                         # dst CIDRs
                    candidate["destination"]["address"]["cidr"],
                    sup["destination"]["address"]["cidr"]
                ):
                continue
            return True                                       # first match wins
        return False
    
    @staticmethod
    def _subset(needle: list[str], haystack: list[str]) -> bool:
        """`needle` is fully contained in `haystack` (handles `"any"` joker)."""
        if not needle:               # empty == wildcard
            return True
        if "any" in haystack:
            return True
        return set(needle).issubset(haystack)
    
    @staticmethod
    def _cidrs_cover(child: list[str | dict], parent: list[str | dict]) -> bool:
        """
        Returns True if every element in *child* is fully contained in at least one
        element in *parent*.  Elements can be:
            • CIDR string  "10.1.0.0/16"
            • range dict   {"gte":"10.1.0.5","lte":"10.1.0.20"}
        """
        #TODO: Look back at this catch all logic, does it make sense for shadows?
        if not child:
            return True
        if "any" in parent:
            return True

        # –– normalise parent list into list of ipaddress.IPv[4|6]Network or tuples
        parent_norm = []
        for p in parent:
            if isinstance(p, dict):
                parent_norm.append((
                    ipaddress.ip_address(p["gte"]),
                    ipaddress.ip_address(p["lte"]),
                ))
            else:
                parent_norm.append(ipaddress.ip_network(p, strict=False))

        # –– for every element in child, find a covering parent ––––––––––––––––
        for c in child:
            if isinstance(c, dict):
                c_lo = ipaddress.ip_address(c["gte"])
                c_hi = ipaddress.ip_address(c["lte"])
                ok = any(
                    # parent is range
                    (isinstance(p, tuple) and p[0] <= c_lo <= c_hi <= p[1]) or
                    # parent is CIDR
                    (not isinstance(p, tuple) and
                    c_lo in p and c_hi in p)
                    for p in parent_norm
                )
            else:
                c_net = ipaddress.ip_network(c, strict=False)
                ok = any(
                    # parent is range
                    (isinstance(p, tuple) and
                    p[0] <= c_net.network_address and
                    c_net.broadcast_address <= p[1]) or
                    # parent is CIDR
                    (not isinstance(p, tuple) and c_net.subnet_of(p))
                    for p in parent_norm
                )
            if not ok:
                return False
        return True

    
    def _collectHitCounts(self) -> None:
        """
        Collect hit counts for all rules in all device groups.
        """
        self.ruleHitCounts = defaultdict(lambda: defaultdict(int))
        ruleStyles = [
            ""
        ]