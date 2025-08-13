"""ruleGenerator.core.ports
================================
Application/service → port resolution helpers extracted from
`panoramaData.py`.

The public entrypoint is :func:`build_port_maps` which mutates a
:class:`~ruleGenerator.core.inventory.PanoramaInventory` instance **in‑place**
adding

* ``applicationToPorts`` – {app → {proto:[port,…]}}
* ``serviceToPorts``     – {svc → {proto:[port,…]}}
* ``portToEntities``     – {"tcp/443" → {"applications":[…],"services":[…]}}

and returns a **PortResolver** object exposing
:meth:`~PortResolver.enrich_rule_with_ports` (used by
``ruleDocumentBuilder``).
"""

from __future__ import annotations

from collections import defaultdict
import logging
from typing import Dict, List, Set

from .inventory import PanoramaInventory

_LOG = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

_ALLOWED_PROTO = {"tcp", "udp", "icmp"}

# ---------------------------------------------------------------------------
#  Main builder
# ---------------------------------------------------------------------------

def build_port_maps(inv: PanoramaInventory) -> "PortResolver":
    """Populate *inv* with app/service → port maps and return a resolver."""

    inv.applicationToPorts = {}
    inv.serviceToPorts = {}
    port_to_entities: Dict[str, Dict[str, List[str]]] = defaultdict(
        lambda: {"applications": [], "services": []}
    )

    # ---- Applications --------------------------------------------------
    for app in inv.applicationObjects + list(inv._predefAppObjects.values()):
        ports: Dict[str, List[str]] = defaultdict(list)
        for entry in getattr(app, "default_port", []) or []:
            try:
                proto, blob = entry.split("/")
                proto = proto.lower()
                if proto not in _ALLOWED_PROTO:
                    continue
                for part in blob.split(","):
                    part = part.strip()
                    if "-" in part:  # range e.g. 80-90
                        low, high = map(int, part.split("-", 1))
                        for p in range(low, high + 1):
                            ports[proto].append(str(p))
                            port_to_entities[f"{proto}/{p}"]["applications"].append(app.name)
                    else:
                        ports[proto].append(part)
                        port_to_entities[f"{proto}/{part}"]["applications"].append(app.name)
            except ValueError:
                _LOG.debug("Cannot parse app port entry: %s", entry)
        inv.applicationToPorts[app.name] = ports

    # ---- Services ------------------------------------------------------
    for svc in inv.serviceObjects + list(inv._predefServiceObjects.values()):
        if not (svc.protocol and svc.destination_port):
            continue
        proto = svc.protocol.lower()
        if proto not in _ALLOWED_PROTO:
            continue

        inv.serviceToPorts.setdefault(svc.name, {}).setdefault(proto, [])
        if "-" in svc.destination_port:  # range
            low, high = map(int, svc.destination_port.split("-", 1))
            for p in range(low, high + 1):
                port = str(p)
                inv.serviceToPorts[svc.name][proto].append(port)
                port_to_entities[f"{proto}/{port}"]["services"].append(svc.name)
        else:
            port = svc.destination_port.strip()
            inv.serviceToPorts[svc.name][proto].append(port)
            port_to_entities[f"{proto}/{port}"]["services"].append(svc.name)

    inv.portToEntities = dict(port_to_entities)

    _LOG.info(
        "Port maps built: %d apps, %d services",
        len(inv.applicationToPorts),
        len(inv.serviceToPorts),
    )

    return PortResolver(inv)

# ---------------------------------------------------------------------------
#  Resolver class
# ---------------------------------------------------------------------------

class PortResolver:
    """Helper wrapper exposing :meth:`enrich_rule_with_ports`."""

    def __init__(self, inv: PanoramaInventory):
        self.inv = inv

    # ------------------------------------------------------------------
    def enrich_rule_with_ports(
        self,
        apps: List[str],
        services: List[str],
        service_field_raw: List[str],
    ) -> Dict[str, List | Dict]:
        """Resolve <proto>/<port> pairs allowed by a rule.

        Mirrors old `PanoramaData.enrichRuleWithPorts` semantics so that
        `ruleDocumentBuilder` remains unchanged.
        """
        resolved: Set[str] = set()
        reasoning: Dict[str, List[str]] = {}

        # application‑default semantics --------------------------------
        if "application-default" in service_field_raw:
            for app in apps:
                port_map = self.inv.applicationToPorts.get(app, {})
                for proto, port_list in port_map.items():
                    for port in port_list:
                        key = f"{proto}/{port}"
                        resolved.add(key)
                        reasoning.setdefault(key, []).append(f"{app} (application-default)")

        # service any ---------------------------------------------------
        if service_field_raw == ["any"]:
            resolved.update({"tcp/*", "udp/*"})
            reasoning.setdefault("tcp/*", []).append("Service Any")
            reasoning.setdefault("udp/*", []).append("Service Any")

        # explicit service objects -------------------------------------
        for svc in services:
            if svc == "application-default":
                continue
            port_map = self.inv.serviceToPorts.get(svc, {})
            for proto, port_list in port_map.items():
                for port in port_list:
                    key = f"{proto}/{port}"
                    resolved.add(key)
                    reasoning.setdefault(key, []).append(f"{svc} (service object)")

        return {"resolvedPorts": sorted(resolved), "portReasoning": reasoning}

# ---------------------------------------------------------------------------
__all__ = [
    "build_port_maps",
    "PortResolver",
]
