#!/usr/bin/env python3

import argparse
from datetime import datetime
import json, os, pathlib
import sys
from panos.panorama import Panorama
from pathlib import Path
from dotenv import load_dotenv
from panoramaData import PanoramaData
from ruleDocumentBuilder import buildRuleDocuments

'''
This script generates rule documents from Panorama data and writes them to an output file.
It connects to Panorama using environment variables for the address and API key.
It logs progress and errors to both console and a log file. (/app/out/debug.log)
'''

def logMessage(msg):
    timestamp = datetime.now().isoformat()
    print(f"[{timestamp}] {msg}", flush=True)
    # Also write to a log file
    with open("/app/out/debug.log", "a") as f:
        f.write(f"[{timestamp}] {msg}\n")

logMessage("Script started")

load_dotenv()
panAddr = os.getenv("PAN_ADDRESS")
apiKey  = os.getenv("API_KEY")
defaultOut = os.getenv("NDJSON", "/app/out/ruleMetricsTest.ndjson")

logMessage(f"PAN_ADDRESS: {'SET' if panAddr else 'NOT SET'}")
logMessage(f"API_KEY: {'SET' if apiKey else 'NOT SET'}")

if not panAddr or not apiKey:
    raise RuntimeError("PAN_ADDRESS or API_KEY env-var is empty or missing")

parser = argparse.ArgumentParser()
parser.add_argument("--out", default=defaultOut)
args = parser.parse_args()

logMessage(f"Output file: {args.out}")


OUT_FILE = pathlib.Path(args.out)
OUT_FILE.parent.mkdir(parents=True, exist_ok=True)

logMessage("Connecting to Panorama...")
try:
    pano = Panorama(panAddr, api_key=apiKey)
except Exception as e:
    logMessage(f"Panorama connection failed: {e}")
    sys.exit(1)

logMessage("Getting Panorama data...")
try:
    inv = PanoramaData(pano)
    logMessage("PanoramaData created")
except Exception as e:
    logMessage(f"PanoramaData failed: {e}")
    sys.exit(1)

logMessage("Building rule documents...")
try:
    docs = buildRuleDocuments(inv)
    logMessage(f"Built {len(docs)} documents")
except Exception as e:
    logMessage(f"buildRuleDocuments failed: {e}")
    sys.exit(1)


logMessage(f"Writing to {OUT_FILE}")
with OUT_FILE.open("w", encoding="utf-8") as fh:
    for i, doc in enumerate(docs):
        json.dump(doc, fh, separators=(",", ":"))
        fh.write("\n")
        if i % 100 == 0:  # Log progress every 100 docs
            logMessage(f"Wrote {i+1}/{len(docs)} documents")

logMessage(f"✔︎  Wrote {len(docs):,} docs → {OUT_FILE}")