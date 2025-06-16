#!/usr/bin/env python3

import argparse
import datetime
import json, os, pathlib
import sys
from panos.panorama import Panorama
from pathlib import Path
from dotenv import load_dotenv
from panoramaData import PanoramaData
from ruleDocumentBuilder import buildRuleDocuments

def log_message(msg):
    timestamp = datetime.now().isoformat()
    print(f"[{timestamp}] {msg}", flush=True)
    # Also write to a log file
    with open("/app/out/debug.log", "a") as f:
        f.write(f"[{timestamp}] {msg}\n")

log_message("Script started")

load_dotenv()
panAddr = os.getenv("PAN_ADDRESS")
apiKey  = os.getenv("API_KEY")

log_message(f"PAN_ADDRESS: {'SET' if panAddr else 'NOT SET'}")
log_message(f"API_KEY: {'SET' if apiKey else 'NOT SET'}")

if not panAddr or not apiKey:
    raise RuntimeError("PAN_ADDRESS or API_KEY env-var is empty or missing")

parser = argparse.ArgumentParser()
parser.add_argument("--out", default="/app/out/ruleMetricsTest.ndjson")
args = parser.parse_args()

log_message(f"Output file: {args.out}")


OUT_FILE = pathlib.Path(args.out)
OUT_FILE.parent.mkdir(parents=True, exist_ok=True)

log_message("Connecting to Panorama...")
try:
    pano = Panorama(panAddr, api_key=apiKey)
except Exception as e:
    log_message(f"Panorama connection failed: {e}")
    sys.exit(1)

log_message("Getting Panorama data...")
try:
    inv = PanoramaData(pano)
    log_message("PanoramaData created")
except Exception as e:
    log_message(f"PanoramaData failed: {e}")
    sys.exit(1)

log_message("Building rule documents...")
try:
    docs = buildRuleDocuments(inv)
    log_message(f"Built {len(docs)} documents")
except Exception as e:
    log_message(f"buildRuleDocuments failed: {e}")
    sys.exit(1)


log_message(f"Writing to {OUT_FILE}")
with OUT_FILE.open("w", encoding="utf-8") as fh:
    for i, doc in enumerate(docs):
        json.dump(doc, fh, separators=(",", ":"))
        fh.write("\n")
        if i % 100 == 0:  # Log progress every 100 docs
            log_message(f"Wrote {i+1}/{len(docs)} documents")

log_message(f"✔︎  Wrote {len(docs):,} docs → {OUT_FILE}")