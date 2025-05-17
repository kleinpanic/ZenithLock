#!/usr/bin/env python3
"""
generate_blowfish_tables.py

Downloads the full Blowfish P-array & all 4 S-boxes from tombonner’s
GitHub and writes them to include/blowfish_tables.h
"""

import os
import sys
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# URL of the canonical tables
TABLES_URL = (
    "https://raw.githubusercontent.com/"
    "tombonner/blowfish-api/master/include/blowfish_tables.h"
)

# path to your include directory (adjust if your layout differs)
HERE = os.path.dirname(os.path.abspath(__file__))
OUT_PATH = os.path.normpath(os.path.join(HERE, "..", "include", "blowfish_tables.h"))

def fetch_tables(url: str) -> bytes:
    req = Request(url, headers={"User-Agent": "zenithlock-generator/1.0"})
    try:
        with urlopen(req) as resp:
            if resp.status != 200:
                raise HTTPError(url, resp.status, resp.reason, resp.headers, None)
            return resp.read()
    except (HTTPError, URLError) as e:
        sys.exit(f"Error: could not download tables: {e}")

def ensure_dir(path: str):
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)

def write_file(path: str, data: bytes):
    with open(path, "wb") as f:
        f.write(data)
    print(f"✔ Wrote {path}")

def main():
    print(f"Downloading Blowfish tables from:\n  {TABLES_URL}")
    data = fetch_tables(TABLES_URL)
    ensure_dir(OUT_PATH)
    write_file(OUT_PATH, data)

if __name__ == "__main__":
    main()

