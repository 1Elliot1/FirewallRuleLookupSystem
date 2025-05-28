"""
Convert the raw pan-os objects collected in firewallRuleLookup.py into **flat rule documents** that match a single-index Elasticsearch schema.

    ─ rule_id
    ─ rule_name
    ─ device_group
    ─ rule_type
    ─ action
    ─ src / dst zones
    ─ src / dst { objects, groups, cidr }
    ─ applications, services
    ─ resolved.ports  [ "tcp/443", "udp/53", … ]
    ─ resolved.protocols [ 6, 17 ]

Call it after buildApplicationPortMap() so that all of the helper mappings are defined
"""

from __future__ import annotations

import logging
from typing import List, Dict, Tuple, Set

from firewallRuleLookupSystem import PanoramaData

PROTOCOL_TO_BYTE = {
        "tcp": 6,
        "udp": 17,
        "icmp": 1,
}

# ---------------------------------------------------------------------------
#  Public API
# ---------------------------------------------------------------------------

def buildRuleDocuments(panData: "PanoramaData") -> List[Dict]:
    """
    Return a list of ElasticSearch ready rule documents
    
    Params:
    panData : PanoramaData
        Fully initialized PanaoramaData object with all caches populated    
    """

    docs: List[dict] = []

    #For each device group, iterate through the rule types for that group
    for deviceGroup, ruleTypeMap in panData.deviceGroupRules.items():
        # For each rule type, iterate through the rules for that type
        for ruleType, rules in ruleTypeMap.items():
            for rule in rules:

                # ------------------ Basic Rule Info -------------------------
                ruleName: str = getattr(rule, "name", "<unnamed>")
                ruleId: str = f"{deviceGroup}:{ruleName}"

                # ------------------ Zones & Address References --------------
                srcZones: List[str] = _normalizeToList(getattr(rule, "fromzone", []))
                destZones: List[str] = _normalizeToList(getattr(rule, "tozone", []))

                srcObjects, srcGroups, srcCidrs = _expandAddressReferences(
                    panData, _normalizeToList(getattr(rule, "source", []))
                )

                destObjects, destGroups, destCidrs = _expandAddressReferences(
                    panData, _normalizeToList(getattr(rule, "destination", []))
                )

                # ---------------- Applications / Services / Ports -----------
                rawApps: List[str] = _normalizeToList(getattr(rule, "application", []))
                rawServices: List[str] = _normalizeToList(getattr(rule, "service", []))

                allApps, allServices = panData.resolveAppAndServiceGroups(rawApps, rawServices)
                portdata = panData.enrichRuleWithPorts(allApps, allServices, rawServices)

                protocols: Set[int] = {
                    PROTOCOL_TO_BYTE[p.split("/")[0]]
                    for p in portdata["resolvedPorts"]
                    if p.split("/")[0] in PROTOCOL_TO_BYTE
                }

                # ------------------ Build Final Document --------------------
                doc: Dict = {
                    "ruleId": ruleId,
                    "ruleName": ruleName,
                    "deviceGroup": deviceGroup,
                    "ruleType": ruleType,
                    "action": getattr(rule, "action", None),

                    "source": {
                        "zones": srcZones,
                        "address": {
                            "objects": srcObjects,
                            "groups": srcGroups,
                            "cidr": srcCidrs
                        },
                    },
                    "destination": {
                        "zones": destZones,
                        "address": {
                            "objects": destObjects,
                            "groups": destGroups,
                            "cidr": destCidrs
                        },
                    },

                    "applications": allApps,
                    "services": allServices,

                    "resolved": {
                        "ports": portdata["resolvedPorts"],
                        "protocols": list(protocols),
                    },

                    "description": getattr(rule, "description", None),
                    #Add additional rule fields here as needed
                }
                docs.append(doc)
    
    return docs

# ---------------------------------------------------------------------------
# Internal Helper Functions
# ---------------------------------------------------------------------------

def _normalizeToList(value) -> List[str]:
    """
    Normalize input to a list of strings, handling None and scalars when they should be lists.
    """
    if value is None:
        return []
    return value if isinstance(value, (list, tuple)) else [value]

def _expandAddressReferences(
        panData: "PanoramaData", rawReferences: List[str]
) -> Tuple[List[str], List[str], List[str]]:
    
    """
    Return (objects, groups, cidrs, etc.) from a rule's source/destination field
    """

    objects: Set[str] = set()
    groups: Set[str] = set()
    cidrs: Set[str] = set()

    for reference in rawReferences: 
        if reference == "any":
            groups.add("any")
            continue

        addressObject = panData.addressObjectByName.get(reference)
        if addressObject:
            #Direct addr object reference (Single IPs are also added to cidr collection):
            objects.add(addressObject.name)
            cidrs.add(addressObject.value)
        
            #Additionaly, pull the objects parent groups, so that search by groups work 
            #TODO: Confirm that this logic is correct. If a rule contains a reference to an object-- should the rule also include the parent groups?
            parent = panData.addressGroupsForObject(addressObject)
            if parent:
                groups.update(parent)
            continue

        addressGroup = panData.addressGroupByName.get(reference)
        if addressGroup:
            groups.add(addressGroup.name)
            #Flatten the group's members into objects/cidrs
            for member in getattr(addressGroup, "static_value", []):
                memberObject = panData.addressObjectByName.get(member)
                if memberObject:
                    objects.add(memberObject.name)
                    cidrs.add(memberObject.value)
            continue 

        #If the reference is not a object or group, keep it as a group token.
        #This way, users can still filter on whatever literal value 

        groups.add(reference)
    return list(objects), list(groups), list(cidrs)


"""
Be sure to add the helper caches to the PanoramaData class:
    self.addressObjByName   = {o.name: o   for o in self.addressObjects}
    self.addressGroupByName = {g.name: g   for g in self.addressGroups}
    self.appGroupByName     = {g.name: g   for g in self.applicationGroup}
    self.appContainerByName = {c.name: c   for c in self.applicationContainers}
    self.predefContainerByName = self.predefinedObjectContainers
    self.serviceGroupByName = {g.name: g   for g in self.serviceGroups}
    self.leafAppNames       = {a.name for a in self.applicationObject}
    self.expandedAppGroupCache: dict[str, list[str]] = {}

"""