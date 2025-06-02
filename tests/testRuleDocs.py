"""
Light-weight regression tests for the NDJSON produced by integrationTest.py.

Run:
    python testRuleDocs.py
"""

import json
import pathlib
from collections import Counter
from typing import Iterator, Dict, List

NDJSON_PATH = pathlib.Path("out/rule_docs.ndjson")
FAILURES_PATH = pathlib.Path("test_failures.json")

def _iter_docs() -> Iterator[Dict]:
    if not NDJSON_PATH.exists():
        print(f"{NDJSON_PATH} not found – run integrationTest.py first")
        return
    with NDJSON_PATH.open(encoding="utf-8") as fh:
        for ln, line in enumerate(fh, 1):
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"Line {ln} is not valid JSON ({exc})")

def _collect_docs() -> List[Dict]:
    return list(_iter_docs())

def test_ndjson_is_not_empty(docs, failures):
    if not docs:
        failures["test_ndjson_is_not_empty"].append("NDJSON file is empty – nothing to test")

def test_required_top_level_keys_present(docs, failures):
    required = {
        "ruleId",
        "deviceGroup",
        "ruleType",
        "source",
        "destination",
        "applications",
        "services",
        "resolved",
    }
    for doc in docs:
        missing = required - doc.keys()
        if missing:
            failures["test_required_top_level_keys_present"].append(
                {"ruleId": doc.get("ruleId"), "missing": list(missing), "doc": doc}
            )

def test_ruleids_are_unique(docs, failures):
    ids = [d["ruleId"] for d in docs]
    counter = Counter(ids)
    dupes = [i for i, c in counter.items() if c > 1]
    if dupes:
        failures["test_ruleids_are_unique"].append({"dupes": dupes})

def test_ports_deduplicated_and_well_formed(docs, failures):
    for doc in docs:
        ports: List[str] = doc["resolved"]["ports"]
        if ports != sorted(set(ports)):
            failures["test_ports_deduplicated_and_well_formed"].append(
                {"ruleId": doc.get("ruleId"), "reason": "ports not unique/sorted", "ports": ports, "doc": doc}
            )
        for p in ports:
            proto, _, port = p.partition("/")
            if proto not in {"tcp", "udp", "icmp"}:
                failures["test_ports_deduplicated_and_well_formed"].append(
                    {"ruleId": doc.get("ruleId"), "reason": f"bad proto: {p}", "ports": ports, "doc": doc}
                )
            if not port:
                failures["test_ports_deduplicated_and_well_formed"].append(
                    {"ruleId": doc.get("ruleId"), "reason": f"empty port in '{p}'", "ports": ports, "doc": doc}
                )

def test_app_default_rules_have_ports(docs, failures):
    for doc in docs:
        if doc["services"] == ["application-default"] and doc["applications"] != ["any"]:
            if not doc["resolved"]["ports"]:
                failures["test_app_default_rules_have_ports"].append(doc)

def test_every_cidr_is_valid_ip_or_range(docs, failures):
    for doc in docs:
        for field in ("source", "destination"):
            for cidr in doc[field]["address"]["cidr"]:
                if not ("/" in cidr or ":" in cidr or "." in cidr):
                    failures["test_every_cidr_is_valid_ip_or_range"].append(
                        {"ruleId": doc.get("ruleId"), "field": field, "cidr": cidr, "doc": doc}
                    )

def run_all_tests():
    docs = _collect_docs()
    failures = {
        "test_ndjson_is_not_empty": [],
        "test_required_top_level_keys_present": [],
        "test_ruleids_are_unique": [],
        "test_ports_deduplicated_and_well_formed": [],
        "test_app_default_rules_have_ports": [],
        "test_every_cidr_is_valid_ip_or_range": [],
    }
    test_ndjson_is_not_empty(docs, failures)
    test_required_top_level_keys_present(docs, failures)
    test_ruleids_are_unique(docs, failures)
    test_ports_deduplicated_and_well_formed(docs, failures)
    test_app_default_rules_have_ports(docs, failures)
    test_every_cidr_is_valid_ip_or_range(docs, failures)

    # Output to file, clustered by test
    with FAILURES_PATH.open("w", encoding="utf-8") as f:
        json.dump(failures, f, indent=2, default=str)
    print(f"\nTest results written to {FAILURES_PATH.resolve()}")

    # Also print a summary to the console
    print("\nTest Results Summary:")
    for test, failed_docs in failures.items():
        print(f"{test}: {len(failed_docs)} failure(s)")

if __name__ == "__main__":
    run_all_tests()