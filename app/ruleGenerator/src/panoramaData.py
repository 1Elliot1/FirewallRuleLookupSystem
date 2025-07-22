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
import math
from typing import Dict, List, Set, Tuple
import yaml
from pathlib import Path

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
from panos.network import (
    AggregateInterface,
    Layer3Subinterface,
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

_LOG = logging.getLogger(__name__)

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

#lru_cache to speed up repeated lookups
@lru_cache(maxsize=None)
def _ip_in_cidr(ip: str, cidr: str) -> bool:
    """Fast *utility* used by higher‑level correlation helpers."""
    try:
        network = ipaddress.ip_network(cidr.strip("'[]"), strict=False)
    except ValueError as exc:
        _LOG.warning("Invalid CIDR '%s' for IP check: %s", cidr, exc)
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
    except ValueError as exc:
        _LOG.warning("Invalid IP '%s' for CIDR check '%s': %s", ip, cidr, exc)
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

    #{ruleID: {hit, lastHit, created, modified}}
    ruleMetrics: Dict[str, dict]

    def __init__(self, pano: Panorama) -> None:
        self.pano = pano
        self._refreshPanoramaInventory()
        self._buildFastMaps()

        self._refreshPredefContainerLeaves()

        self.deviceGroupRules = {}
        self.vlanData = {}

        self._collectDeviceGroupRules()
        self._collectHitCountsPerRule()
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
        
        #Catch for when theres an object with /0 (as to not add all objects to its list)
        if parent.prefixlen == 0:
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
                    for subif in agg.findall(Layer3Subinterface):
                        try:
                            #Create a mapping of VLAN numbers to their associated IP ranges
                            #!Assumes that subinterface name format is <name>.<vlanNumber>
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
                        #Support for port ranges (e.g. "80-90")
                        if "-" in part:
                            low, high = map(int, part.split("-", 1))
                            for p in range (low, high + 1):
                                ports[proto].append(str(p))
                                portToEntities[f"{proto}/{p}"]["applications"].append(app.name)
                            continue
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

            self.serviceToPorts.setdefault(svc.name, {}).setdefault(proto, [])

            #Support for port ranges (e.g. "80-90")
            if "-" in svc.destination_port:
                low, high = map(int, svc.destination_port.split("-", 1))
                for p in range(low, high + 1):
                    port = str(p)
                    self.serviceToPorts[svc.name][proto].append(port)
                    portToEntities[f"{proto}/{port}"]["services"].append(svc.name)
            else:
                port = svc.destination_port.strip()
                self.serviceToPorts[svc.name][proto].append(port)
                portToEntities[f"{proto}/{port}"]["services"].append(svc.name)

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
            elif member in self.predefContainerByName:
                leaves.extend(self._expandPredefContainer(member))
            else:
                leaves.append(member)
        deduped = list(dict.fromkeys(leaves))
        self._expandedAppGroupCache[name] = deduped
        return deduped

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
        if "application-default" in serviceFieldRaw:
            for app in apps:
                portMap = self.applicationToPorts.get(app, {})
                for proto, portList in portMap.items():
                    for port in portList:
                        key = f"{proto}/{port}"
                        resolvedPorts.add(key)
                        reasoning.setdefault(key, []).append(
                            f"{app} (application-default)"
                        )

        if serviceFieldRaw == ["any"]:
            resolvedPorts.update({"tcp/*", "udp/*"})
            reasoning.setdefault("tcp/*", []).append("Service Any")
            reasoning.setdefault("udp/*", []).append("Service Any")

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

#Constant to get the absoulte path of yaml file:
    DEFAULT_STATIC_OVERRIDES = Path(__file__).resolve().parent / "staticOverrides.yml"
    # ------Static Override YAML Loader----------------------------------
    def _applyStaticOverrides(self, path: str | Path | None = None) -> None:
        path = Path(path or self.DEFAULT_STATIC_OVERRIDES)
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
        
        # ----- Ext/Int Internet Synth -----------------------------
        inside = data.get("internalPrefixes", [])
        externalCidrs = self._cidrCompliment(inside)
        self._externalZones = {z.lower() for z in data.get("externalZones", [])}


        self._internalNets = [
            ipaddress.ip_network(c, strict=False)
            for c in inside
        ]
        #Catch all object
        self._ensureAddressObject("EXT-INTERNET", "0.0.0.0/0")

        # On object per external CIDR (EXT-v4-<n>)
        memberNames = []
        for idx, cidr in enumerate(externalCidrs, 1):
            objectName = f"EXT-{idx}"
            self._ensureAddressObject(objectName, cidr)
            memberNames.append(objectName)

        # Create a group for EXT-Internet (adding all of the created address objects)
        addressGroup = self.addressGroupByName.setdefault("EXT-INTERNET", AddressGroup(name="EXT-INTERNET", static_value=[]))
        addressGroup.static_value = memberNames
        
        # Add the EXT-INTERNET group to the _addrToGroup mapping so searches by object show the group
        for mem in memberNames:
            self._addrToGroup.setdefault(mem, []).append("EXT-INTERNET")

        # ----- Applications to Ports
        for app, entry in (data.get("applications") or {}).items():
            mode, payload = self._extractMode(entry)
            # payload should be {proto: [ports]}
            portsMap = {proto.lower(): list(ports)
                        for proto, ports in (payload or {}).items()}

            exists = app in self.applicationToPorts

            def create():
                self.applicationToPorts[app] = portsMap

            def overwrite():
                self.applicationToPorts[app] = portsMap

            def merge():
                target = self.applicationToPorts.setdefault(app, {})
                for proto, portList in portsMap.items():
                    target.setdefault(proto, [])
                    #If a port list per protocol is already defined, extend it. If not add the new protocol + ports
                    target[proto].extend(
                        p for p in portList if p not in target[proto]
                    )

            self._applyByMode(mode, exists, merge, overwrite, create)
        
        # ----- Application Groups
        for group, entry in (data.get("applicationGroups") or {}).items():
            mode, payload = self._extractMode(entry)
            members = list(payload.get("members", []))

            exists = group in self.appGroupByName

            def create():
                self.appGroupByName[group] = ApplicationGroup(
                    name=group, value=list(members)
                )

            def overwrite():
                self.appGroupByName[group].value = list(members)

            def merge():
                g = self.appGroupByName[group]
                g.value = list(set(g.value or []).union(members))
            
            self._applyByMode(mode, exists, merge, overwrite, create)
        
        # ----- Services to Ports
        for svc, entry in (data.get("services") or {}).items():
            mode, payload = self._extractMode(entry)
            portsMap = {proto.lower(): list(ports)
                        for proto, ports in (payload or {}).items()}
        
            exists = svc in self.serviceToPorts
            
            def create():
                self.serviceToPorts[svc] = portsMap
            
            def overwrite():
                self.serviceToPorts[svc] = portsMap

            def merge():
                target = self.serviceToPorts.setdefault(svc, {})
                for proto, portList in portsMap.items():
                    target.setdefault(proto, [])
                    target[proto].extend(p for p in portList if p not in target[proto])

            self._applyByMode(mode, exists, merge, overwrite, create)
        
        # ----- Address Objects
        for name, entry in (data.get("addressObjects") or {}).items():
            mode, payload = self._extractMode(entry)
            
            #payload -> cidr string
            if isinstance(payload, dict):
                cidr = payload.get("value")
            else:
                cidr = payload
            
            #check if address object already exists
            exists = name in self.addressObjectByName

            def create():
                self.addressObjectByName[name] = AddressObject(name=name, value=cidr)
                self._addToNets(name, cidr)
            
            def overwrite():
                self.addressObjectByName[name].value = cidr
                self._addToNets(name, cidr, replace=True)
            
            def merge():
                #address objects have a single value, so merging = no operation
                pass
        
            self._applyByMode(mode, exists, merge, overwrite, create)

        # ----- Address Groups
        for group, entry in (data.get("addressGroups") or {}).items():
            mode, payload = self._extractMode(entry)
            members = list(payload.get("members", [])) if isinstance(payload, dict) else payload
            
            exists = group in self.addressGroupByName

            def create():
                self.addressGroupByName[group] = AddressGroup(
                    name=group, static_value=list(members)
                )
                for m in members:
                    self._addrToGroup.setdefault(m, []).append(group)

            def overwrite():
                self.addressGroupByName[group].static_value = list(members)
                for m in members:
                    self._addrToGroup.setdefault(m, []).append(group)

            def merge():
                ag = self.addressGroupByName[group]
                ag.static_value = list(set(ag.static_value or []).union(members))
                for m in members:
                    self._addrToGroup.setdefault(m, []).append(group)

            self._applyByMode(mode, exists, merge, overwrite, create)

        # ----- VLANs  
        for templateKey, vlanMap in data.get("vlans", {}).items():
            self.vlanData.setdefault(templateKey, {"vlanMap": {}, "zones": []})

            for vlanID, entry in vlanMap.items():
                mode, payload = self._extractMode(entry)
                cidr = payload if isinstance(payload, str) else payload.get("value")

                exists = vlanID in self.vlanData[templateKey]["vlanMap"]

                def create():
                    self.vlanData[templateKey]["vlanMap"][vlanID] = cidr

                def overwrite():
                    self.vlanData[templateKey]["vlanMap"][vlanID] = cidr

                def merge():
                    #Vlans have a single value, so merging = no operation
                    pass

                self._applyByMode(
                    mode, exists, merge, overwrite, create
                )

        # ----- Zones
        for templateKey, entry in data.get("zones", {}).items():
            mode, payload = self._extractMode(entry)
            newZones = list(payload.get("members", [])) if isinstance(payload, dict) else list(entry)

            self.vlanData.setdefault(templateKey, {"vlanMap": {}, "zones":[]})
            exists = bool(self.vlanData[templateKey]["zones"])

            def create():
                self.vlanData[templateKey]["zones"].extend(newZones)

            def overwrite():
                self.vlanData[templateKey]["zones"] = list(newZones)

            def merge():
                prevZones = self.vlanData[templateKey]["zones"]
                prevZones.extend(z for z in newZones if z not in prevZones)

            self._applyByMode(
                mode, exists, merge, overwrite, create
            )

        _LOG.info("Static overrides from %s merged", path)

    def _addToNets(self, name: str, cidr: str, *, replace: bool = False) -> None:
        """
        Keep self._nets [(ip_network, objName), …] in sync with addressObjects.

        • replace=True → delete any old tuple for `name` before appending new one
        • silently ignores invalid CIDRs (already logged upstream)
        """
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return

        if replace:
            self._nets[:] = [t for t in self._nets if t[1] != name]

        self._nets.append((net, name))

    def _extractMode(self, blob, default="merge"):
        """
        Returns (mode, payload_dict)
        Extracts the '_mode' from a single staticOverrides object entry and returns it with the rest of the payload.
        • blob can be a scalar, list, or mapping.
        • If it's a mapping and contains '_mode', pop it.
        • Everything else is returned as payload.
        """
        if isinstance(blob, dict) and "_mode" in blob:
            mode = str(blob.pop("_mode")).lower()
        else:
            mode = default
        return mode, blob

    def _applyByMode(
            self,
            mode: str, 
            exists: bool,
            mergeFn: callable,
            overwriteFn: callable,
            createFn: callable,
    ):
        """
        Dispatch convenience for static overrides.

        • mode       - 'merge' | 'overwrite' | 'if_nonexistent'
        • exists     - does an object of that name already exist?
        • mergeFn    - called when mode=='merge'  and exists
        • overwriteFn- called when mode=='overwrite' and exists
        • createFn   - called when object needs to be created
        """
        if exists:
            if mode == "overwrite":
                overwriteFn()
            elif mode == "merge":
                mergeFn()
        else:
            createFn()

    # -------------- Helpers for EXT/INT Internet Synth   -----------
    def _cidrCompliment(self, cidrs: list[str]) -> list[str]:
        """
        Given a list of CIDRs, return a set of CIDRs that cover everything except the input
        """
        v4Everything = [ipaddress.ip_network("0.0.0.0/0")]
        v6Everything = [ipaddress.ip_network("::/0")]

        for raw in cidrs: 
            try:
                net = ipaddress.ip_network(raw, strict=False)
            except ValueError:
                continue
            everything = v4Everything if net.version == 4 else v6Everything
            newEverything = []
            for block in everything:
                if net.subnet_of(block):
                    # If the input CIDR is a subnet of the block, remove it
                    newEverything.extend(block.address_exclude(net))
                else: 
                    newEverything.append(block)
            if net.version == 4:
                v4Everything = newEverything
            else:
                v6Everything = newEverything
        
        return [n.with_prefixlen for n in v4Everything + v6Everything if n.prefixlen != 0]
    
    def _ensureAddressObject(self, name: str, value: str) -> None:
        """
        Create an address object if absent and sync self._nets
        """
        if name in self.addressObjectByName:
            return
        self.addressObjectByName[name] = AddressObject(name=name, value=value)
        self._addToNets(name, value)

    def _zoneIsExternal(self, z: str) -> bool:
        return z.lower() in self._externalZones

    def isExternal(self, cidrList: list[str], groupList: list[str], zoneList: list[str] | None = None) -> bool:
        """
        Return True if any CIDR or address object/group on that rule side lies outside of internalPrefixes
        """
        if zoneList and "any" not in {z.lower() for z in zoneList}:
            return any(self._zoneIsExternal(z) for z in zoneList)

        if "any" in groupList or "EXT-INTERNET" in groupList:
            return True

        for c in cidrList:
            if self._cidrIsExternal(c):
                return True

        for obj in groupList:
            if obj.lower() == "any":
                continue
            ao = self.addressObjectByName.get(obj)
            if ao and self._cidrIsExternal(ao.value):
                return True

        return False
    
    def _cidrIsExternal(self, cidr: str | dict) -> bool:
        """
        Return true of CidrStr is outside all internal prefixes
        Accepts 0.0.0.0/24 or {'gte': '0.0.0.0', 'lte':'0.0.0.10'}
        """
        if cidr == "any":
            return True
        if isinstance(cidr, dict):
            lo = ipaddress.ip_address(cidr["gte"])
            hi = ipaddress.ip_address(cidr["lte"])
            return not any(lo in net and hi in net for net in self._internalNets)
        net = ipaddress.ip_network(cidr, strict=False)
        return not any(net.subnet_of(internal) for internal in self._internalNets)

    # -------------- Additional Metrics for Elasticsearch ----------
    def calcRuleWeight(self, doc: dict) -> int:
        S = len(doc["source"]["address"]["objects"])
        D = len(doc["destination"]["address"]["objects"])
        serv = len(doc["services"])
        apps = len(doc["applications"])
        if S * D != 0:
            metricLogged = math.log(S*D, 10)
        else: 
            metricLogged = 1
        weight = int((
            #Weight = numImpactedDevices + [(numServices * 5) + (numApplications * 5) || 100 if applications AND services == "Any"]  
            metricLogged * 10
            + (serv * 3)
            + (apps * 3)
        ))
        if "any" in doc["applications"] and "any" in doc["services"]:
            #adding 90 to account for fact that the ANY entry in both adds 5 each
            weight += 24
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

    def _collectHitCountsPerRule(self) -> None:
        """
        Call the *exact* XML you validated:

        <show><rule-hit-count>
          <device-group><entry name='DG'><pre-rulebase>
            <entry name='RULETYPE'><rules>
              <rule-name><entry name='RULENAME'/></rule-name>
            </rules></entry></pre-rulebase>
          </entry></device-group>
        </rule-hit-count></show>

        We loop every device-group / rule-type / rule to populate
        hitCount, lastHit, created, modified.
        """

        rule_types = {
            "SecurityRule": "security",
            "NatRule": "nat",
            "PolicyBasedForwarding": "pbf",
            "ApplicationOverride": "application-override",
            "DecryptionRule": "decryption",
            "AuthenticationRule": "authentication",
        }
        metrics: dict[str, dict] = {}

        for dg, bucket in self.deviceGroupRules.items():
            for rt, rules in bucket.items():
                apiName = rule_types.get(rt)
                if not apiName:
                    continue
                for rule in rules:
                    elem = self._get_rule_metrics(dg, apiName, rule.name)
                    if elem is None:
                        continue
                    rid = f"{dg}:{rule.name}"
                    metrics[rid] = elem

        self.ruleMetrics = metrics
        _LOG.info("Hit-count collected for %d rules", len(metrics))

    def _get_rule_metrics(self, dg: str, rt: str, rn: str) -> dict | None:

        import xml.etree.ElementTree as ET
        import xml.dom.minidom as minidom
        cmd = f"<show><rule-hit-count><device-group><entry name='{dg}'><pre-rulebase><entry name='{rt}'><rules><rule-name><entry name='{rn}'/></rule-name></rules></entry></pre-rulebase></entry></device-group></rule-hit-count></show>"
        try: 
            xmlAnswer = self.pano.op(cmd=cmd, cmd_xml=False)
        except Exception as e:
            _LOG.error("Hit Count Op Failed for %s/%s/%s: %s", dg, rt, rn, e)
            return None
        
        toStr = ET.tostring(xmlAnswer, encoding='utf-8')
        root = ET.fromstring(toStr)
        dvEntries = root.findall(".//device-vsys/entry")
        if not dvEntries:
            _LOG.warning("No device-vsys entries found for %s/%s/%s", dg, rt, rn)
            return None
        hitSum = 0
        lastHit = firstHit = created = modified = None
        
        for dv in dvEntries:
            rawHit = dv.findtext("hit-count") or "0"   # ← returns "0" if empty/None
            hitSum += int(rawHit)
            
            lh = dv.findtext("last-hit-timestamp")
            fh = dv.findtext("first-hit-timestamp")
            cr = dv.findtext("rule-creation-timestamp")
            mo = dv.findtext("rule-modification-timestamp")

            for tag, val in [("lh", lh), ("fh", fh), ("cr", cr), ("mo", mo)]:
                if val and not val.isdigit():
                    val = None
            
            if lh and(lastHit is None or int(lh) > lastHit):
                lastHit = int(lh)
            if fh and(firstHit is None or int(fh) < firstHit):
                firstHit = int(fh)
            if cr and(created is None or int(cr) < created):
                created = int(cr)
            if mo and(modified is None or int(mo) > modified):
                modified = int(mo)

        return { 
            "hitCount": hitSum,
            "lastHit": lastHit,
            "firstHit": firstHit,
            "created": created,
            "modified": modified,
        }

