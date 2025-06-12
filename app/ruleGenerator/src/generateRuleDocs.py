#!/usr/bin/env python3

import argparse
import json, os, pathlib
from panos.panorama import Panorama
from pathlib import Path
from dotenv import load_dotenv
from panoramaData import PanoramaData
from ruleDocumentBuilder import buildRuleDocuments

load_dotenv()
panAddr = os.getenv("PAN_ADDRESS")
apiKey  = os.getenv("API_KEY")

if not panAddr or not apiKey:
    raise RuntimeError("PAN_ADDRESS or API_KEY env-var is empty or missing")

parser = argparse.ArgumentParser()
parser.add_argument("--out", default="app/out/ruleMetricsTest.ndjson")
args = parser.parse_args()


OUT_FILE = pathlib.Path("app/out/ruleMetricsTest.ndjson")
OUT_FILE.parent.mkdir(exist_ok=True)

pano = Panorama(panAddr, api_key=apiKey)
inv  = PanoramaData(pano)

docs = buildRuleDocuments(inv)

with pathlib.Path(args.out).open("w", encoding="utf-8") as fh:
    for doc in docs:
        json.dump(doc, fh, separators=(",", ":"))
        fh.write("\n")

print(f"✔︎  Wrote {len(docs):,} docs → {OUT_FILE}")