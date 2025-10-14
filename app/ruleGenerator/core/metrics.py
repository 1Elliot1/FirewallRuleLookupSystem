"""ruleGenerator.core.metrics
================================
Hit‑count fetch, rule‑weight calculation, and shadowing detection split out
from the legacy `PanoramaData` class.

Public surface
--------------
* :class:`RuleMetricsCollector` – grabs device‑group *rule hit counts* via the
  same XML you already validated and stores them on the attached
  :class:`~ruleGenerator.core.inventory.PanoramaInventory` instance.
* :func:`calc_rule_weight(doc)` – pure function; identical math to the monolith.
* :func:`is_shadowed(candidate, earlier)` – top‑down shadowing check plus
  helpers ``_subset`` and ``_cidrs_cover``.

Nothing in here touches static overrides or port resolution – those live in
`core.overrides` and `core.ports` respectively.

Typical usage
-------------
```
inv     = PanoramaInventory(pano)
resolver = build_port_maps(inv)
apply_static_overrides(inv)
metrics  = RuleMetricsCollector(inv)
metrics.collect_hit_counts()

for doc in buildRuleDocuments(...):
    doc["ruleWeight"] = calc_rule_weight(doc)
    doc["isShadowed"] = is_shadowed(doc, docs_so_far)
```
All unit‑tested helper logic (subset, cidr cover, weight math) was moved
*verbatim* so existing tests stay green.
"""

from __future__ import annotations

import ipaddress
import logging
import math
import xml.etree.ElementTree as ET
from typing import Dict, List, Tuple, Iterable, Set

from .inventory import PanoramaInventory

_LOG = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
#  Hit‑count collection
# ---------------------------------------------------------------------------

_RULE_TYPE_API = {
    "SecurityRule": "security",
    "NatRule": "nat",
    "PolicyBasedForwarding": "pbf",
    "ApplicationOverride": "application-override",
    "DecryptionRule": "decryption",
    "AuthenticationRule": "authentication",
}


class RuleMetricsCollector:
    """Populate ``inventory.ruleMetrics`` with hit‑count data."""

    def __init__(self, inventory: PanoramaInventory):
        self.inv = inventory

    # ------------------------------------------------------------------
    def collect_hit_counts(self) -> None:
        metrics: Dict[str, dict] = {}
        for dg, bucket in self.inv.deviceGroupRules.items():
            for rt, rules in bucket.items():
                api_name = _RULE_TYPE_API.get(rt)
                if not api_name:
                    continue
                for rule in rules:
                    elem = self._get_rule_metrics(dg, api_name, rule.name)
                    if elem is None:
                        continue
                    rid = f"{dg}:{rule.name}"
                    metrics[rid] = elem
        self.inv.ruleMetrics = metrics
        _LOG.info("Hit‑count collected for %d rules", len(metrics))

    # ------------------------------------------------------------------
    def _get_rule_metrics(self, dg: str, rt: str, rn: str) -> dict | None:
        cmd = (
            "<show><rule-hit-count>"
            "<device-group><entry name='{dg}'><pre-rulebase>"
            "<entry name='{rt}'><rules>"
            "<rule-name><entry name='{rn}'/></rule-name>"
            "</rules></entry></pre-rulebase>"
            "</entry></device-group>"
            "</rule-hit-count></show>"
        ).format(dg=dg, rt=rt, rn=rn)

        try:
            xml_answer = self.inv.pano.op(cmd=cmd, cmd_xml=False)
        except Exception as exc:  # pylint: disable=broad-except
            _LOG.error("Hit‑count op failed for %s/%s/%s: %s", dg, rt, rn, exc)
            return None

        root = ET.fromstring(ET.tostring(xml_answer, encoding="utf-8"))
        dv_entries = root.findall(".//device-vsys/entry")
        if not dv_entries:
            _LOG.debug("No device‑vsys entries for %s/%s/%s", dg, rt, rn)
            return None

        hit_sum = 0
        last_hit = first_hit = created = modified = None

        def safe_int(s: str | None) -> int | None:
            return int(s) if s and s.isdigit() else None

        for dv in dv_entries:
            hit_sum += int(dv.findtext("hit-count") or "0")
            lh = safe_int(dv.findtext("last-hit-timestamp"))
            fh = safe_int(dv.findtext("first-hit-timestamp"))
            cr = safe_int(dv.findtext("rule-creation-timestamp"))
            mo = safe_int(dv.findtext("rule-modification-timestamp"))

            if lh is not None and (last_hit is None or lh > last_hit):
                last_hit = lh
            if fh is not None and (first_hit is None or fh < first_hit):
                first_hit = fh
            if cr is not None and (created is None or cr < created):
                created = cr
            if mo is not None and (modified is None or mo > modified):
                modified = mo

        return {
            "hitCount": hit_sum,
            "lastHit": last_hit,
            "firstHit": first_hit,
            "created": created,
            "lastModified": modified,
        }


# ---------------------------------------------------------------------------
#  Rule‑weight formula 
# ---------------------------------------------------------------------------
# normalize breadth to a 0..32 scale for both v4 and v6
def _cidr_breadth32(token) -> float:
    if isinstance(token, dict):  # {"gte": "...", "lte": "..."}
        # treat ranges as broad; assume IPv4 unless we can detect otherwise
        try:
            v = ipaddress.ip_address(token["gte"]).version
        except Exception:
            v = 4
        return 32.0 if v == 4 else 32.0  # normalized cap
    try:
        net = ipaddress.ip_network(token, strict=False)
        return (32.0 * ( (32 if net.version == 4 else 128) - net.prefixlen )
               / (32 if net.version == 4 else 128))
    except Exception:
        return 0.0

def _avg_breadth32(cidrs) -> float:
    if not cidrs:
        return 0.0
    vals = [_cidr_breadth32(c) for c in cidrs]
    return sum(vals) / max(1, len(vals))

def calc_rule_weight(doc: dict) -> int:
    src = doc["source"]["address"]
    dst = doc["destination"]["address"]

    n_objs = len(src["objects"]) + len(dst["objects"])
    n_groups = len(src["groups"]) + len(dst["groups"])
    n_apps = len(doc["applications"])
    n_svcs = len(doc["services"])
    n_ports = len(doc.get("resolved", {}).get("ports", []))

    # breadth in "IPv4-equivalent bits" (0..32) per side
    b_src = _avg_breadth32(src.get("cidr", []))
    b_dst = _avg_breadth32(dst.get("cidr", []))

    f_any_svc = any(s.lower() == "any" for s in doc["services"])
    f_app_def = any(s == "application-default" for s in doc["services"])
    f_any_app = any(a.lower() == "any" for a in doc["applications"])

    f_ext_src = bool(src.get("isExternal"))
    f_ext_dst = bool(dst.get("isExternal"))

    # Complexity / surface (log keeps large rules from exploding)
    w = 10
    w += 3 * math.log1p(n_objs + n_groups)        # address complexity
    w += 2 * math.log1p(n_apps) + 2 * math.log1p(n_svcs)
    w += 1 * math.log1p(n_ports)                   # effective surface

    # Breadth (wide CIDRs drive weight up)
    w += 1.5 * (b_src + b_dst)

    # Permissiveness
    if f_any_svc:         w += 20
    elif f_app_def:       w += 5
    if f_any_app:         w += 10

    # Externality
    if f_ext_dst:         w += 8
    if f_ext_src:         w += 4

    return int(round(w))

# ---------------------------------------------------------------------------
#  Shadowing detector (identical to old behaviour)
# ---------------------------------------------------------------------------
def _subset_anyaware(child: Iterable[str], parent: Iterable[str]) -> bool:
    c = {x.lower() for x in (child or [])}
    p = {x.lower() for x in (parent or [])}
    if not c:
        return True
    if not p or "any" in p:
        return True
    if "any" in c:
        # child==any can only be covered if parent==any
        return "any" in p and len(p) == 1
    return c.issubset(p)

def _range_in_net(lo, hi, net) -> bool:
    try:
        lo_ip = ipaddress.ip_address(lo)
        hi_ip = ipaddress.ip_address(hi)
    except Exception:
        return False
    if lo_ip.version != net.version or hi_ip.version != net.version:
        return False
    return (lo_ip in net) and (hi_ip in net)

def _token_covered_by_sup(token, sup_token) -> bool:
    # token/sup_token ∈ { "CIDR string" | {"gte": ip, "lte": ip} }
    try:
        if isinstance(sup_token, dict):
            # parent is a RANGE
            lo = ipaddress.ip_address(sup_token["gte"])
            hi = ipaddress.ip_address(sup_token["lte"])
            if lo.version != hi.version or lo > hi:
                return False
            if isinstance(token, dict):
                # child is RANGE: child range must lie fully within parent range
                clo = ipaddress.ip_address(token["gte"])
                chi = ipaddress.ip_address(token["lte"])
                return (clo.version == lo.version == hi.version) and (lo <= clo <= chi <= hi)
            else:
                # child is CIDR: net's first & last IP must lie within parent range
                net = ipaddress.ip_network(token, strict=False)
                first = net.network_address
                last  = net.broadcast_address
                return (first.version == lo.version) and (lo <= first and last <= hi)
        else:
            # parent is a CIDR
            parent_net = ipaddress.ip_network(sup_token, strict=False)
            if isinstance(token, dict):
                clo = ipaddress.ip_address(token["gte"])
                chi = ipaddress.ip_address(token["lte"])
                if clo.version != parent_net.version or chi.version != parent_net.version or clo > chi:
                    return False
                # child range must be fully inside parent net
                return (clo in parent_net) and (chi in parent_net)
            else:
                # child is CIDR: subset check
                child_net = ipaddress.ip_network(token, strict=False)
                return child_net.version == parent_net.version and child_net.subnet_of(parent_net)
    except Exception:
        return False

def _cidrs_cover(child_list: List, parent_list: List) -> bool:
    # Empty parent_list means "any" (covers everything)
    if not child_list:
        return True
    if not parent_list:
        return True
    for c in child_list:
        if not any(_token_covered_by_sup(c, p) for p in parent_list):
            return False
    return True

def _ports_covered(child_ports: Iterable[str], parent_ports: Iterable[str]) -> bool:
    # empty → treat as covered (some exotic rules might not resolve)
    c = set(child_ports or [])
    p = set(parent_ports or [])
    return not c or not p or c.issubset(p)

def is_shadowed(candidate: dict, earlier: List[dict]) -> bool:
    """True if *candidate* is fully shadowed by any earlier SAME-ACTION rule."""
    cand_ports = candidate.get("resolved", {}).get("ports", [])
    for sup in earlier:
        if sup.get("action") != candidate.get("action"):
            continue
        if not _subset_anyaware(candidate["source"]["zones"], sup["source"]["zones"]):
            continue
        if not _subset_anyaware(candidate["destination"]["zones"], sup["destination"]["zones"]):
            continue
        if not _cidrs_cover(candidate["source"]["address"]["cidr"], sup["source"]["address"]["cidr"]):
            continue
        if not _cidrs_cover(candidate["destination"]["address"]["cidr"], sup["destination"]["address"]["cidr"]):
            continue
        if not _ports_covered(cand_ports, sup.get("resolved", {}).get("ports", [])):
            continue
        return True
    return False

# ---------------------------------------------------------------------------
#  __all__
# ---------------------------------------------------------------------------
__all__ = [
    "RuleMetricsCollector",
    "calc_rule_weight",
    "is_shadowed",
    "_subset_anyaware",
    "_cidrs_cover",
]
