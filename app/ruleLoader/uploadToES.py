#!/usr/bin/env python3
"""
Bulk-load rule_docs.ndjson into Elasticsearch.

Usage
-----
python uploadToES.py [--replace-index]

Environment variables
---------------------
ES_HOST   :  URL to Elasticsearch (default http://elasticsearch:9200)
NDJSON    :  Path to the docs file   (default /app/out/rule_docs.ndjson)
INDEX     :  Target index name       (default rule_view)

The script assumes the NDJSON file is bind-mounted read-only inside the
container, and that `index_template_ruleview.json` sits next to this file.
"""

from __future__ import annotations
import argparse, json, os, sys, time, pathlib, requests, tqdm
from datetime import datetime

NOW = datetime.now()
ES_HOST = os.getenv("ES_HOST" , "http://elasticsearch:9200")
TPL_PATH = pathlib.Path("/app/test_template.json")   # shipped in image

OUT_DIR = pathlib.Path("/app/out")
candidates = sorted(OUT_DIR.glob("ruleMetrics-*.ndjson"), key=lambda p: p.stat().st_mtime, reverse=True)
if not candidates:
    print("no NDJSON to upload – exiting")
    sys.exit(0)
NDJSON = candidates[-1]

prefix = os.getenv("INDEX_PREFIX", "test-index")
INDEX  = f"{prefix}-{datetime.now():%Y%m%d%H%M}"

# ---------------------------------------------------------------------------

def put_template() -> None:
    tpl = json.load(TPL_PATH.open(encoding="utf-8"))
    r = requests.put(f"{ES_HOST}/_index_template/test_template", json=tpl)
    r.raise_for_status()

def delete_index() -> None:
    requests.delete(f"{ES_HOST}/{INDEX}", params={"ignore_unavailable":"true"})

# ––– helper that yields proper _bulk lines ––––––––––––––––––––––––––––––––

def iter_bulk_lines(path: pathlib.Path, index_name: str):
    action = json.dumps({ "index": { "_index": index_name } }, separators=(",",":"))
    with path.open("r", encoding="utf-8") as fh:
        for doc in fh:
            if not doc.strip():                     # skip blank lines
                continue
            yield action + "\n"
            yield doc if doc.endswith("\n") else doc + "\n"

# ---------------------------------------------------------------------------

def bulk_load() -> None:
    if not NDJSON.exists():
        print("NDJSON file missing → nothing to upload")
        return

    # Count lines just for progress bar (cheap on SSDs; if huge, skip)
    total_docs = sum(1 for _ in NDJSON.open("r", encoding="utf-8"))
    bar = tqdm.tqdm(total=total_docs, unit="doc", desc=f"Bulk upload of template{TPL_PATH.name} with Index {INDEX} using data from {NDJSON.name}")

    def gen():
        for line in iter_bulk_lines(NDJSON, INDEX):
            bar.update(0.5)            # 2 lines per doc → +0.5 each line
            yield line.encode()

    r = requests.post(
        f"{ES_HOST}/{INDEX}/_bulk",
        data=gen(),
        headers={"Content-Type":"application/x-ndjson"},
        params={"refresh":"true"}      # make docs searchable immediately
    )
    bar.close()
    r.raise_for_status()

    resp = r.json()
    if resp.get("errors"):
        fails = [item for item in resp["items"] if item["index"].get("error")]
        print(f"⚠️  {len(fails)} docs failed (showing first 5):", file=sys.stderr)
        for item in fails[:5]:
            print(json.dumps(item["index"]["error"], indent=2), file=sys.stderr)
        sys.exit(1)

    took = resp.get("took", "?")
    print(f"✔︎  Loaded {total_docs} docs into “{INDEX}” (took {took} ms)")

# ---------------------------------------------------------------------------

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--replace-index", action="store_true",
                    help="delete index & re-install template before load")
    args = ap.parse_args()

    if args.replace_index:
        delete_index()
        put_template()
        time.sleep(1.0)   # give ES a moment to create the fresh index

    bulk_load()
