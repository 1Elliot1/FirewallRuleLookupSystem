"""
• Connects to Panorama (PAN_ADDRESS / API_KEY from env).
• Builds PanoramaData  ➜ rule docs.
• Exports docs to ./out/rule_docs.ndjson  (one doc per line).
• Prints a metrics digest (counts & a few percentiles) to stdout.

Run:
    poetry run python tests/integrationTest.py
or
    python -m tests.integrationTest
"""
from __future__ import annotations

import json
import os
import pathlib
import statistics
from collections import Counter, defaultdict

from panos.panorama import Panorama
from panoramaData import PanoramaData
from .ruleDocumentBuilder import buildRuleDocuments

# ── 0. Config ──────────────────────────────────────────────────────────────
OUT_DIR     = pathlib.Path("out")
OUT_DIR.mkdir(exist_ok=True)

# ── 1. Pull + flatten ──────────────────────────────────────────────────────
from dotenv import load_dotenv
load_dotenv()

pan_addr = os.getenv("PAN_ADDRESS")
api_key  = os.getenv("API_KEY")

if not pan_addr:
    raise RuntimeError("PAN_ADDRESS env-var is empty or missing")

pano = Panorama(pan_addr, api_key=api_key)
inv  = PanoramaData(pano)

rule_docs = buildRuleDocuments(inv)

out_file = OUT_DIR / "rule_docs1.ndjson"
with out_file.open("w", encoding="utf-8") as fh:
    for doc in rule_docs:
        json.dump(doc, fh)
        fh.write("\n")

# ── 2. Metrics ─────────────────────────────────────────────────────────────
print("╭─ Rule-doc generation summary ────────────────────────────────")
print(f"│   Device Groups : {len(inv.deviceGroups):>6}")
rule_obj_cnt = sum(
    len(rule_list)
    for bucket in inv.deviceGroupRules.values()     # per-DG dict
    for rule_list in bucket.values()                # the actual lists
)
print(f"│   Rule objects  : {rule_obj_cnt:>6}")
print(f"│   Rule *docs*   : {len(rule_docs):>6}   (after port fan-out)")

addr_obj_cnt  = len(inv.addressObjects)
addr_grp_cnt  = len(inv.addressGroups)
app_cnt       = len(inv.applicationObjects) + len(inv._predefAppObjects)
svc_cnt       = len(inv.serviceObjects)    + len(inv._predefServiceObjects)
print("│")
print(f"│   AddressObjects: {addr_obj_cnt:>6}")
print(f"│   AddressGroups : {addr_grp_cnt:>6}")
print(f"│   Applications  : {app_cnt:>6}")
print(f"│   Services      : {svc_cnt:>6}")

# --- fan-out stats ---------------------------------------------------------
ports_per_doc = [len(d['resolved']['ports']) for d in rule_docs]
zones_per_doc = [len(d['source']['zones']) + len(d['destination']['zones'])
                 for d in rule_docs]

def pctl(series, q):                                # tiny helper
    return statistics.quantiles(series, n=100)[q-1] if series else 0

print("│")
print("│   Ports per rule-doc : "
      f"p50={pctl(ports_per_doc,50):>2}  "
      f"p95={pctl(ports_per_doc,95):>2}  "
      f"max={max(ports_per_doc or [0]):>2}")
print("│   Zones per rule-doc : "
      f"p50={pctl(zones_per_doc,50):>2}  "
      f"p95={pctl(zones_per_doc,95):>2}  "
      f"max={max(zones_per_doc or [0]):>2}")

# --- top talkers -----------------------------------------------------------
port_counter = Counter(p for d in rule_docs for p in d['resolved']['ports'])
top5 = port_counter.most_common(5)
print("│")
print("│   Top 5 ports (protocol/port) across all docs:")
for proto_port, cnt in top5:
    print(f"│     {proto_port:<9}  {cnt:>7}")

print("╰───────────────────────────────────────────────────────────────")
print(f"📄  Docs written to {out_file.absolute()}")
