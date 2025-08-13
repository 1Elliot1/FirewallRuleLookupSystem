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
from typing import Dict, List, Tuple

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
#  Rule‑weight formula (unchanged logic)
# ---------------------------------------------------------------------------

def calc_rule_weight(doc: dict) -> int:  # noqa: D401 – imper imperative name
    """Return weight score using the same heuristic as the monolith."""
    S = len(doc["source"]["address"]["objects"])
    D = len(doc["destination"]["address"]["objects"])
    serv = len(doc["services"])
    apps = len(doc["applications"])

    metric_logged = math.log(S * D, 10) if S * D != 0 else 1

    weight = int(metric_logged * 10 + serv * 3 + apps * 3)
    if "any" in doc["applications"] and "any" in doc["services"]:
        weight += 24
    return weight

# ---------------------------------------------------------------------------
#  Shadowing detector (identical to old behaviour)
# ---------------------------------------------------------------------------

def is_shadowed(candidate: dict, earlier: List[dict]) -> bool:
    """Return *True* if *candidate* rule is fully shadowed by any earlier."""
    for sup in earlier:  # iterate top‑down
        if sup["action"] != candidate["action"]:
            continue
        if not _subset(candidate["source"]["zones"], sup["source"]["zones"]):
            continue
        if not _subset(candidate["destination"]["zones"], sup["destination"]["zones"]):
            continue
        if not _subset(candidate["applications"], sup["applications"]):
            continue
        if not _subset(candidate["services"], sup["services"]):
            continue
        if not _cidrs_cover(  # src
            candidate["source"]["address"]["cidr"],
            sup["source"]["address"]["cidr"],
        ):
            continue
        if not _cidrs_cover(  # dst
            candidate["destination"]["address"]["cidr"],
            sup["destination"]["address"]["cidr"],
        ):
            continue
        return True
    return False


# ---------------------------------------------------------------------------
#  Helper functions – unchanged
# ---------------------------------------------------------------------------

def _subset(needle: List[str], haystack: List[str]) -> bool:
    if not needle:
        return True
    if "any" in haystack:
        return True
    return set(needle).issubset(haystack)



def _cidrs_cover(child: List[str | dict], parent: List[str | dict]) -> bool:
    if not child:
        return True
    if "any" in parent:
        return True

    parent_norm: List[ipaddress.IPv4Network | ipaddress.IPv6Network | Tuple] = []
    for p in parent:
        if isinstance(p, dict):
            parent_norm.append((
                ipaddress.ip_address(p["gte"]),
                ipaddress.ip_address(p["lte"]),
            ))
        else:
            parent_norm.append(ipaddress.ip_network(p, strict=False))

    for c in child:
        if isinstance(c, dict):
            c_lo = ipaddress.ip_address(c["gte"])
            c_hi = ipaddress.ip_address(c["lte"])
            ok = any(
                (isinstance(p, tuple) and p[0] <= c_lo <= c_hi <= p[1])
                or (not isinstance(p, tuple) and c_lo in p and c_hi in p)
                for p in parent_norm
            )
        else:
            c_net = ipaddress.ip_network(c, strict=False)
            ok = any(
                (isinstance(p, tuple) and p[0] <= c_net.network_address <= c_net.broadcast_address <= p[1])
                or (not isinstance(p, tuple) and c_net.subnet_of(p))
                for p in parent_norm
            )
        if not ok:
            return False
    return True


# ---------------------------------------------------------------------------
#  __all__
# ---------------------------------------------------------------------------
__all__ = [
    "RuleMetricsCollector",
    "calc_rule_weight",
    "is_shadowed",
    "_subset",
    "_cidrs_cover",
]
