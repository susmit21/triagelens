#!/usr/bin/env python3
"""Fetch vendor/distro advisory pages for all CVE snapshots.

Saves stripped text to data/advisories/<CVE>/<n>.json.
Priority order: vendor → distro → other.  Never fetches exploit URLs.
Run once; re-running skips already-fetched files.

Usage:
  source .venv/bin/activate
  python scripts/fetch_advisories.py
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from triage.tools.advisories import label_ref, vendor_domains_for_cpe

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("ERROR: requests and beautifulsoup4 must be installed.")
    print("  pip install requests beautifulsoup4")
    sys.exit(1)

SNAPSHOTS_DIR  = ROOT / "data" / "snapshots"
ADVISORIES_DIR = ROOT / "data" / "advisories"
MAX_PAGES_PER_CVE = 3
MIN_TEXT_CHARS    = 200
FETCH_DELAY_S     = 2.0
UA = (
    "TriageLens/0.1 (CMU capstone security research project; "
    "read-only fetching for vulnerability analysis)"
)
LABEL_ORDER = {"vendor": 0, "distro": 1, "other": 2, "exploit": 999}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _product_names(nvd_data: dict) -> set[str]:
    """Extract lower-case product names from NVD CPE matches."""
    products: set[str] = set()
    for vuln in nvd_data.get("vulnerabilities", []):
        cve_obj = vuln.get("cve", {})
        for config in cve_obj.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    cpe = cpe_match.get("criteria", "")
                    parts = cpe.split(":")
                    if len(parts) >= 5:
                        products.add(parts[4].lower().replace("_", " "))
                        products.add(parts[3].lower().replace("_", " "))
    products.discard("*")
    products.discard("")
    return products


_PDF = object()  # sentinel returned by _fetch_text when the response is a PDF


def _fetch_text(url: str, timeout: int = 15):
    """
    Fetch a URL and return stripped plain text.

    Returns:
      str   — page text on success
      None  — network/HTTP failure (4xx, 5xx, timeout, etc.)
      _PDF  — response is a PDF (Content-Type application/pdf or body starts with %PDF)
    """
    try:
        resp = requests.get(
            url,
            headers={"User-Agent": UA},
            timeout=timeout,
            allow_redirects=True,
        )
        if resp.status_code != 200:
            return None
        ct = resp.headers.get("Content-Type", "")
        if "application/pdf" in ct or resp.content[:4] == b"%PDF":
            return _PDF
        soup = BeautifulSoup(resp.text, "html.parser")
        for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
            tag.decompose()
        text = soup.get_text(separator="\n")
        lines = [line.strip() for line in text.splitlines()]
        return "\n".join(line for line in lines if line)
    except Exception as exc:
        print(f"    fetch error: {exc}")
        return None


def _quality_ok(text: str, cve_id: str, product_names: set[str]) -> bool:
    """Page is kept if it's long enough AND mentions the CVE or a product name."""
    if len(text) < MIN_TEXT_CHARS:
        return False
    lower = text.lower()
    if cve_id.lower() in lower:
        return True
    return any(p in lower for p in product_names if len(p) > 3)


def _refs_sorted(refs: list[str], vendor_domains: frozenset[str]) -> list[str]:
    """Return non-exploit refs sorted: vendor first, then distro, then other."""
    labelled = [(label_ref(url, vendor_domains=vendor_domains), url) for url in refs]
    labelled = [(lbl, url) for lbl, url in labelled if lbl != "exploit"]
    labelled.sort(key=lambda x: LABEL_ORDER.get(x[0], 99))
    return [url for _, url in labelled]


# ── Main ──────────────────────────────────────────────────────────────────────

def fetch_all(snapshots_dir: Path = SNAPSHOTS_DIR, advisories_dir: Path = ADVISORIES_DIR) -> None:
    advisories_dir.mkdir(parents=True, exist_ok=True)

    cve_dirs = sorted(d for d in snapshots_dir.iterdir() if d.is_dir())
    print(f"Found {len(cve_dirs)} CVE snapshot directories.")

    for cve_dir in cve_dirs:
        cve_id = cve_dir.name
        nvd_path = cve_dir / "nvd.json"
        if not nvd_path.exists():
            print(f"[{cve_id}] No nvd.json — skipping.")
            continue

        nvd_data = json.loads(nvd_path.read_text())
        product_names = _product_names(nvd_data)
        # Vendor domains derived per-CVE from CPE product/vendor tokens
        vendor_domains = vendor_domains_for_cpe(frozenset(product_names))

        # Collect reference URLs from NVD
        raw_refs: list[str] = []
        for vuln in nvd_data.get("vulnerabilities", []):
            for ref in vuln.get("cve", {}).get("references", []):
                url = ref.get("url", "").strip()
                if url:
                    raw_refs.append(url)

        # Deduplicate while preserving order
        seen: set[str] = set()
        unique_refs: list[str] = []
        for url in raw_refs:
            if url not in seen:
                seen.add(url)
                unique_refs.append(url)

        sorted_refs = _refs_sorted(unique_refs, vendor_domains)
        out_dir = advisories_dir / cve_id
        out_dir.mkdir(parents=True, exist_ok=True)

        # Count already-fetched
        existing = {int(f.stem) for f in out_dir.glob("*.json")}
        fetched_count = 0

        for url in sorted_refs:
            if fetched_count >= MAX_PAGES_PER_CVE:
                break

            n = fetched_count
            if n in existing:
                print(f"[{cve_id}] {n}: already exists — skip.")
                fetched_count += 1
                continue

            lbl = label_ref(url, vendor_domains=vendor_domains)
            domain = urlparse(url).netloc.lstrip("www.")
            print(f"[{cve_id}] {n}: fetching [{lbl}] {url}")

            text = _fetch_text(url)
            if text is None:
                print(f"    → fetch failed")
                continue

            if text is _PDF:
                print(f"    → PDF response — marking fallback")
                record = {
                    "cve_id":          cve_id,
                    "url":             url,
                    "domain":          domain,
                    "label":           lbl,
                    "text":            "",
                    "quality_ok":      False,
                    "fallback_reason": "pdf",
                }
                (out_dir / f"{n}.json").write_text(
                    json.dumps(record, ensure_ascii=False, indent=2)
                )
                fetched_count += 1
                time.sleep(FETCH_DELAY_S)
                continue

            quality = _quality_ok(text, cve_id, product_names)
            print(f"    → {len(text)} chars, quality_ok={quality}")

            record = {
                "cve_id":     cve_id,
                "url":        url,
                "domain":     domain,
                "label":      lbl,
                "text":       text,
                "quality_ok": quality,
            }
            (out_dir / f"{n}.json").write_text(json.dumps(record, ensure_ascii=False, indent=2))
            fetched_count += 1
            time.sleep(FETCH_DELAY_S)

        kept = sum(1 for f in out_dir.glob("*.json")
                   if json.loads(f.read_text()).get("quality_ok"))
        print(f"[{cve_id}] done. {fetched_count} fetched, {kept} quality_ok.")


if __name__ == "__main__":
    fetch_all()
