"""Backward‑compat façade around the new *ruleGenerator.core* stack.

Existing code in the repo (ruleDocumentBuilder, old tests, scripts) imports
``PanoramaData`` from this module.  Rather than touching all call‑sites at
once, we keep that symbol alive while delegating to the freshly‑split core
modules:

    • :pyclass:`~ruleGenerator.core.inventory.PanoramaInventory`
    • :pymod:`ruleGenerator.core.ports`
    • :pymod:`ruleGenerator.core.overrides`
    • :pymod:`ruleGenerator.core.metrics`

The public API mirrors the original monolithic class, so callers see the same
attributes and helper methods.
"""

from __future__ import annotations

import warnings
from pathlib import Path
from typing import List, Tuple, Set, Dict

from ruleGenerator.core import (
    PanoramaInventory,
    build_port_maps,
    apply_static_overrides,
    RuleMetricsCollector,
    calc_rule_weight,
    is_shadowed,
    ip_in_cidr,
)
from ruleGenerator.core.inventory import ip_in_cidr as _ip_in_cidr
ip_in_cidr = _ip_in_cidr  
_ip_in_cidr = _ip_in_cidr 
# ---------------------------------------------------------------------------
#  Facade class
# ---------------------------------------------------------------------------

class PanoramaData(PanoramaInventory):  # type: ignore[misc]
    """Legacy wrapper that stitches the new core helpers together."""

    # Back‑compat method aliases will be filled in __init__ -----------------

    def __init__(self, pano, *, overrides_path: str | Path | None = None):
        # Step 1: raw inventory ------------------------------------------------
        super().__init__(pano)

        # Step 2: application / service → port maps ---------------------------
        self._port_resolver = build_port_maps(self)

        # Step 3: optional static‑override YAML --------------------------------
        apply_static_overrides(self, overrides_path)

        # Step 4: hit‑count metrics -------------------------------------------
        self._metrics = RuleMetricsCollector(self)
        self._metrics.collect_hit_counts()

        # Deprecation notice ---------------------------------------------------
        warnings.warn(
            "Importing PanoramaData from panoramaData.py is deprecated; "
            "use ruleGenerator.core instead.",
            DeprecationWarning,
            stacklevel=2,
        )

    # ------------------------------------------------------------------
    #  Ports helper (same signature as old enrichRuleWithPorts)
    # ------------------------------------------------------------------
    def enrichRuleWithPorts(self, apps: List[str], services: List[str], serviceFieldRaw: List[str]):  # noqa: N802
        return self._port_resolver.enrich_rule_with_ports(apps, services, serviceFieldRaw)
    
    # ------------------------------------------------------------------
    #  Group-expansion helpers (delegate to base class)
    # ------------------------------------------------------------------
    resolveAppAndServiceGroups = PanoramaInventory.resolve_app_and_service_groups 
    _expand_app_group = PanoramaInventory._expand_app_group           
    _expand_service_group = PanoramaInventory._expand_service_group  


    # ------------------------------------------------------------------
    #  Metrics helpers (method names unchanged)
    # ------------------------------------------------------------------
    def calcRuleWeight(self, doc: Dict):  # noqa: N802
        return calc_rule_weight(doc)

    def isShadowed(self, candidate: Dict, earlier: List[Dict]):  # noqa: N802
        return is_shadowed(candidate, earlier)

    # ------------------------------------------------------------------
    #  Re‑export the small ip‑in‑cidr helper for callers that used it
    # ------------------------------------------------------------------
    ip_in_cidr = staticmethod(ip_in_cidr)  # pylint: disable=invalid-name

    # ------------------------------------------------------------------
    #  Legacy camel-case helper wrappers (used by old tests & scripts)
    # ------------------------------------------------------------------
    def addressGroupsForObject(self, obj):               # noqa: N802
        return self.address_groups_for_object(obj)

    def expandAddressGroups(self, group_name):           # noqa: N802
        return self.expand_address_groups(group_name)

    def allNestedGroupNames(self, group_name):           # noqa: N802
        return self.all_nested_group_names(group_name)

    def nestedObjectsInNetwork(self, parent_cidr):       # noqa: N802
        return self.nested_objects_in_network(parent_cidr)

    def isExternal(self, cidrList, groupList, zoneList=None):  # noqa: N802
        return self.is_external(cidrList, groupList, zoneList)
# ---------------------------------------------------------------------------
#  Convenience re‑exports for old import paths
# ---------------------------------------------------------------------------
__all__ = [
    "PanoramaData",
    "ip_in_cidr",
    "_ip_in_cidr"
]
