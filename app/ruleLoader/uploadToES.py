#!/usr/bin/env python3
"""
File watcher version of uploadToES.py
Watches for new ruleMetrics-*.ndjson files and uploads them automatically
"""
from __future__ import annotations
import argparse
import json
import os
import sys
import time
import pathlib
import requests
import tqdm
from datetime import datetime
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

NOW = datetime.now()
ES_HOST = os.getenv("ES_HOST", "http://elasticsearch:9200")
#TODO: Change template path to be more dynamic. Any name, args to put custom path. Same with index prefix.
TPL_PATH = pathlib.Path(os.getenv("TPL_PATH", "/app/test_template.json"))
OUT_DIR = pathlib.Path("/app/out")
prefix = os.getenv("INDEX_PREFIX", "test-index")
ELASTIC_API_KEY = os.getenv("ELASTIC_API_KEY")

class RuleFileHandler(FileSystemEventHandler):
    def __init__(self):
        self.processedFiles = set()
        self.lock = threading.Lock()
        
    def on_created(self, event):
        if event.is_directory:
            return
            
        filePath = pathlib.Path(event.src_path)
        
        # Only process ruleMetrics-*.ndjson files
        if not (filePath.name.startswith("ruleMetrics-") and filePath.suffix == ".ndjson"):
            return

        # Avoid duplicate processing
        with self.lock:
            if filePath in self.processedFiles:
                return
            self.processedFiles.add(filePath)

        print(f"🔍 New rule file detected: {filePath.name}")

        # Wait a moment for file to be fully written
        time.sleep(2)
        
        # Process the file
        self.processFile(filePath)

    def processFile(self, filePath: pathlib.Path):
        try:
            # Create index name with timestamp
            #! Here you are creating an index based on the minute. This results in oversharding over time. Are there any downsides or complications to instead be indexing monthly? Adding new documents to the same index?
            INDEX = f"{prefix}-{datetime.now():%Y%m%d%H%M}"

            print(f"📤 Processing {filePath.name} → {INDEX}")

            # Install template and upload
            putTemplate()
            bulkLoad(filePath, INDEX)

            print(f"✅ Successfully processed {filePath.name}")

        except Exception as e:
            print(f"❌ Error processing {filePath.name}: {e}")

def putTemplate() -> None:
    tpl = json.load(TPL_PATH.open(encoding="utf-8"))
    r = requests.put(
        f"{ES_HOST}/_index_template/test_template",
        json=tpl,
        headers=esHeaders({"Content-Type": "application/json"})
    )
    r.raise_for_status()

def iterBulkLines(path: pathlib.Path, index_name: str):
    with path.open("r", encoding="utf-8") as fh:
        for doc_line in fh:
            if not doc_line.strip():
                continue
            doc = json.loads(doc_line)
            doc_id = doc.get("uid")
            action = json.dumps({
                "index": {
                    "_index": index_name,
                    **({"_id": doc_id} if doc_id else {})
                }
            }, separators=(",", ":"))
            yield action + "\n"
            yield doc_line if doc_line.endswith("\n") else doc_line + "\n"

def esHeaders(extra: dict | None = None) -> dict:
    """
    Return base headers (+ any caller specific ones) with API key Auth
    """
    header = extra.copy() if extra else {}
    if ELASTIC_API_KEY:
        header["Authorization"] = f"ApiKey {ELASTIC_API_KEY}"
    return header

def bulkLoad(ndjson_path: pathlib.Path, index_name: str) -> None:
    if not ndjson_path.exists():
        print(f"⚠️  File not found: {ndjson_path}")
        return
    
    # Count lines for progress bar
    total_docs = sum(1 for _ in ndjson_path.open("r", encoding="utf-8"))
    
    if total_docs == 0:
        print(f"⚠️  Empty file: {ndjson_path}")
        return
    
    bar = tqdm.tqdm(
        total=total_docs, 
        unit="doc", 
        desc=f"Uploading {ndjson_path.name} → {index_name}"
    )
    
    def gen():
        for line in iterBulkLines(ndjson_path, index_name):
            bar.update(0.5)
            yield line.encode()
    
    r = requests.post(
        f"{ES_HOST}/{index_name}/_bulk",
        data=gen(),
        headers=esHeaders({"Content-Type": "application/x-ndjson"}),
        params={"refresh": "true"}
    )
    bar.close()
    r.raise_for_status()
    
    resp = r.json()
    if resp.get("errors"):
        fails = [item for item in resp["items"] if item["index"].get("error")]
        print(f"⚠️  {len(fails)} docs failed (showing first 5):", file=sys.stderr)
        for item in fails[:5]:
            print(json.dumps(item["index"]["error"], indent=2), file=sys.stderr)
        return
    
    took = resp.get("took", "?")
    print(f"✔︎  Loaded {total_docs:,} docs into {index_name} (took {took} ms)")

def watchForFiles():
    """Watch for new rule files and process them automatically"""
    print(f"👀 Watching {OUT_DIR} for new ruleMetrics-*.ndjson files...")
    
    # Process any existing files first
    handler = RuleFileHandler()


    # Set up file watcher
    observer = Observer()
    observer.schedule(handler, str(OUT_DIR), recursive=False)
    observer.start()
    
    try:
        print("🚀 File watcher started. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Stopping file watcher...")
        observer.stop()
    
    observer.join()

def processLatestFile():
    """Process the most recent ruleMetrics file (original behavior)"""
    candidates = sorted(OUT_DIR.glob("ruleMetrics-*.ndjson"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not candidates:
        print("📭 No NDJSON files to upload – exiting")
        sys.exit(0)
    
    ndjsonPath = candidates[0]
    INDEX = f"{prefix}-{datetime.now():%Y%m%d%H%M}"

    print(f"📤 Processing latest file: {ndjsonPath.name} → {INDEX}")

    putTemplate()
    bulkLoad(ndjsonPath, INDEX)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--watch", action="store_true", 
                    help="Watch for new files and process them automatically")
    ap.add_argument("--replace-index", action="store_true",
                    help="Delete index & re-install template before load")
    args = ap.parse_args()
    
    if args.watch:
        watchForFiles()
    else:
        # Original behavior - process latest file once
        if args.replace_index:
            # Delete existing indices if requested
            try:
                r = requests.delete(f"{ES_HOST}/{prefix}-*", headers=esHeaders())
                print("🗑️  Cleaned up old indices")
            except Exception as e:
                print(f"⚠️  Failed to delete old indices: {e}")

        processLatestFile()