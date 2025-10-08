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

from typing import List, Dict, Tuple, Set
from datetime import datetime, timezone
import ipaddress
import re
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ruleGenerator.src.panoramaData import PanoramaData

PROTOCOL_TO_BYTE = {
        "tcp": 6,
        "udp": 17,
        "icmp": 1,
}

_RANGE_RE = re.compile(r"\s*([\dA-Fa-f.:]+)\s*-\s*([\dA-Fa-f.:]+)\s*")

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

                if srcZones and not _zones_are_any(srcZones) and _should_expand_from_zones(srcObjects, srcGroups, srcCidrs):
                    zcidrs = panData.cidrsForZones(srcZones)       # VLAN/subint CIDRs for zones
                    zvlans  = panData.vlansForZones(srcZones)      # keep using this in doc

                    # 1) Add the VLAN CIDRs themselves (dedup)
                    for c in zcidrs:
                        if c not in srcCidrs:
                            srcCidrs.append(c)

                    # 2) Add impacted AddressObjects: names + their own CIDRs
                    for c in zcidrs:
                        for name in panData.nestedObjectsInNetwork(c):
                            if name not in srcObjects:
                                srcObjects.append(name)

                            # If we can resolve the object’s value, add its exact CIDR/IP too
                            ao = panData.addressObjectByName.get(name)
                            if ao and getattr(ao, "value", None):
                                oc = _cidrOrRange(ao.value)  # same helper used in _expandAddressReferences
                                if oc and oc not in srcCidrs:
                                    srcCidrs.append(oc)

                    # stash VLANs for the doc payload you build later
                    srcZoneVlans = zvlans
                else:
                    srcZoneVlans = []

                if destZones and not _zones_are_any(destZones) and _should_expand_from_zones(destObjects, destGroups, destCidrs):
                    zcidrs = panData.cidrsForZones(destZones)       # VLAN/subint CIDRs for zones
                    zvlans  = panData.vlansForZones(destZones)      # keep using this in doc

                    # 1) Add the VLAN CIDRs themselves (dedup)
                    for c in zcidrs:
                        if c not in destCidrs:
                            destCidrs.append(c)

                    # 2) Add impacted AddressObjects: names + their own CIDRs
                    for c in zcidrs:
                        for name in panData.nestedObjectsInNetwork(c):
                            if name not in destObjects:
                                destObjects.append(name)

                            # If we can resolve the object’s value, add its exact CIDR/IP too
                            ao = panData.addressObjectByName.get(name)
                            if ao and getattr(ao, "value", None):
                                oc = _cidrOrRange(ao.value)  # same helper used in _expandAddressReferences
                                if oc and oc not in destCidrs:
                                    destCidrs.append(oc)

                    # stash VLANs for the doc payload you build later
                    destZoneVlans = zvlans
                else:
                    destZoneVlans = []


                # ---------------- EXT/INT Flags -----------------------------
                srcIsExternal = panData.isExternal(srcCidrs, srcGroups, srcZones)
                destIsExternal = panData.isExternal(destCidrs, destGroups, destZones)

                if srcIsExternal and "EXT-INTERNET" not in srcGroups:
                    srcGroups.append("EXT-INTERNET")
                if destIsExternal and "EXT-INTERNET" not in destGroups:
                    destGroups.append("EXT-INTERNET")

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
                        "zoneVlans": srcZoneVlans,
                        "address": {
                            "objects": srcObjects,
                            "groups": srcGroups,
                            "cidr": srcCidrs,
                            "isExternal": srcIsExternal
                        },
                    },
                    "destination": {
                        "zones": destZones,
                        "zoneVlans": destZoneVlans,
                        "address": {
                            "objects": destObjects,
                            "groups": destGroups,
                            "cidr": destCidrs,
                            "isExternal": destIsExternal
                        },
                    },

                    "applications": allApps,
                    "services": allServices,

                    "resolved": {
                        "ports": portdata["resolvedPorts"],
                        "protocols": list(protocols),
                    },

                    "description": getattr(rule, "description", None),

                    "snapshotTimestamp": (
                        datetime.now(timezone.utc)
                        .replace(microsecond=0)
                        .isoformat()
                    )
                }

                src_ip_ranges = [c for c in srcCidrs if c is not None]
                dst_ip_ranges = [c for c in destCidrs if c is not None]

                doc["srcCidrs"] = src_ip_ranges
                doc["dstCidrs"] = dst_ip_ranges
                doc["allCidrs"] = src_ip_ranges + dst_ip_ranges

                info = panData.ruleMetrics.get(ruleId, {})
                
                doc.update({
                    "hitCount": info.get("hitCount", 0),
                    "lastHit": info.get("lastHit", None),
                    "firstHit": info.get("firstHit", None),
                    "created": info.get("created", None),
                    "lastModified": info.get("lastModified", None)
                })

                doc["ruleWeight"] = panData.calcRuleWeight(doc)
                doc["isShadowed"] = panData.isShadowed(doc, docs)

                doc["uid"] = stable_rule_id(doc)
                doc["active"] = True

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

def _should_expand_from_zones(objects: list[str], groups: list[str], cidrs: list[str]) -> bool:
    has_any = any(g.lower() == "any" for g in groups)
    emptyish = (not objects and not cidrs)
    return has_any or emptyish

def _zones_are_any(zones: list[str]) -> bool:
    return any((z or "").lower() == "any" for z in zones)

def _cidrOrRange(token: str | dict | None) -> str | dict | None:
    """ 
    Return a value valid for IP_range or None if not parsable
    """
    if isinstance(token, dict):
        return token 
    if not token or token.lower() in {"any", "unknown", ""}:
        return None
    token = token.strip()
    #handling dash ranges
    m = _RANGE_RE.fullmatch(token)
    if m:
        start, end = m.group(1), m.group(2)
        try:
            ipaddress.ip_address(start)
            ipaddress.ip_address(end)
        except ValueError:
            return None
        return {"gte": start, "lte": end}
    
    if "/" in token:
        #already valid CIDR
        try: 
            return ipaddress.ip_network(token, strict=False).with_prefixlen
        except ValueError:
            return None
        
    #single host ip without suffix
    try:
        ipObj = ipaddress.ip_address(token)
        mask = 32 if ipObj.version == 4 else 128
        return f"{ipObj}/{mask}"
    except ValueError:
        # fall through → unparsable
        return None

def _expandAddressReferences(
        panData: "PanoramaData", rawReferences: List[str]
) -> Tuple[List[str], List[str], List[str]]:
    
    """
    Return (objects, groups, cidrs, etc.) from a rule's source/destination field
    """

    objects: Set[str] = set()
    groups: Set[str] = set()
    cidrs: List[str | dict] = []

    for reference in rawReferences: 
        if reference == "any":
            groups.add("any")
            continue

        # ── AddressObject referenced by name ───────────────────────
        addressObject = panData.addressObjectByName.get(reference)
        if addressObject:
            #Direct addr object reference (Single IPs are also added to cidr collection):
            objects.add(addressObject.name)
            cidrVal = _cidrOrRange(addressObject.value)
            if cidrVal is not None:
                cidrs.append(cidrVal)

            #If objects val is a network-- theres potentially child object groups that fall within it. 
            #Find all nested addressObjects fully contained within the object:
            if "/" in addressObject.value: 
                objects.update(
                    name for name in panData.nestedObjectsInNetwork(addressObject.value)
                    if name != addressObject.name  # Avoid adding itself    
                )
            #Additionaly, pull the objects parent groups, so that search by groups work 
            #TODO: Confirm that this logic is correct. If a rule contains a reference to an object-- should the rule also include the parent groups?
            parent = panData.addressGroupsForObject(addressObject)
            if parent:
                groups.update(parent)
            continue

        # ── AddressGroup referenced by name ────────────────────────
        addressGroup = panData.addressGroupByName.get(reference)
        if addressGroup:
            #add the curr group and every nested child group name
            groups.update(panData.allNestedGroupNames(addressGroup.name))

            #Flatten the group's members into objects/cidrs
            #Add every individual leaf AddressObject under the group heirarchy (including nested groups)
            for objectName in  panData.expandAddressGroups(addressGroup.name):
                object = panData.addressObjectByName.get(objectName)
                if object: 
                    objects.add(object.name)
                    cidrVal = _cidrOrRange(object.value)
                    if cidrVal is not None:
                        cidrs.append(cidrVal)
            continue
        
        # ── Literal IP/CIDR/Range ─────────────────────────────
        lit = _cidrOrRange(reference)
        if lit is not None:
            cidrs.append(lit)
            continue 

        # ── Fallback: literal token kept as a group
        groups.add(str(reference))
    seen = set()
    deduped = []
    for item in cidrs:
        key = item if isinstance(item, str) else (item["gte"], item["lte"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    cidrs = deduped

    return list(objects), list(groups), list(cidrs)

import hashlib
import json

def stable_rule_id(rule: dict) -> str:
    """
    Generate a stable unique ID for a firewall rule document.
    Handles lists (sorted, deduplicated) and nested structures.
    """

    def normalize_list(lst):
        # Ensure lists are sorted and unique strings
        if lst is None:
            return []
        return sorted(set(str(item).lower() for item in lst))
    
    def safe_lower(s):
        # Handle None or non-string input safely
        if s is None:
            return ""
        return str(s).lower()


    # Extract and normalize fields, fall back to empty if missing
    device_group = safe_lower(rule.get("deviceGroup", ""))

    # Source address fields normalized into JSON string
    src_addr = rule.get("source", {}).get("address", {})
    src_objects = normalize_list(src_addr.get("objects", []))
    src_groups = normalize_list(src_addr.get("groups", []))
    src_cidr = normalize_list(src_addr.get("cidr", []))

    # Destination address fields normalized
    dst_addr = rule.get("destination", {}).get("address", {})
    dst_objects = normalize_list(dst_addr.get("objects", []))
    dst_groups = normalize_list(dst_addr.get("groups", []))
    dst_cidr = normalize_list(dst_addr.get("cidr", []))

    # Other key fields
    rule_type = safe_lower(rule.get("ruleType", ""))
    action = safe_lower(rule.get("action", ""))
    applications = normalize_list(rule.get("applications", []))
    services = normalize_list(rule.get("services", []))

    # Compose a canonical dictionary of normalized contents
    id_data = {
        "deviceGroup": device_group,
        "source": {
            "objects": src_objects,
            "groups": src_groups,
            "cidr": src_cidr
        },
        "destination": {
            "objects": dst_objects,
            "groups": dst_groups,
            "cidr": dst_cidr
        },
        "ruleType": rule_type,
        "action": action,
        "applications": applications,
        "services": services
    }

    # Serialize with sorted keys for consistent hashing
    id_json = json.dumps(id_data, sort_keys=True, separators=(',', ':'))

    # Create SHA256 hash of the serialized string
    return hashlib.sha256(id_json.encode('utf-8')).hexdigest()

