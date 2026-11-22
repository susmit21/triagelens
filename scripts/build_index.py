#!/usr/bin/env python3
"""Build the Chroma advisory vector index from data/advisories/.

Run once after fetch_advisories.py:
  source .venv/bin/activate
  python scripts/build_index.py

The index is stored at data/chroma/ and loaded by search_advisories at triage time.
Re-running rebuilds the index from scratch.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from triage.tools.advisories import build_advisory_index

advisories_dir = ROOT / "data" / "advisories"
chroma_dir     = ROOT / "data" / "chroma"

if not advisories_dir.exists():
    print("ERROR: data/advisories/ not found. Run fetch_advisories.py first.")
    sys.exit(1)

total_files = sum(1 for _ in advisories_dir.rglob("*.json"))
if total_files == 0:
    print("ERROR: No advisory JSON files in data/advisories/. Run fetch_advisories.py first.")
    sys.exit(1)

print(f"Building index from {total_files} advisory file(s) in {advisories_dir} …")
result = build_advisory_index(advisories_dir=advisories_dir, chroma_dir=chroma_dir)
print(f"Done: {result['added']} chunks added to collection '{result['collection']}'")
print(f"Index stored at: {chroma_dir}")
