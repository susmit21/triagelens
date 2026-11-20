"""Download NVD, CISA KEV, and EPSS snapshots for the target CVE list."""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from triage.versions import ALIASES, asset_is_vulnerable, find_vulnerable_ranges, first_matching_range

# ── Configuration ─────────────────────────────────────────────────────────────

CVES = [
    "CVE-2024-23897",  # Jenkins arbitrary file read
    "CVE-2021-44228",  # Log4Shell
    "CVE-2023-44487",  # HTTP/2 Rapid Reset (nginx)
    "CVE-2024-6387",   # OpenSSH regreSSHion
    "CVE-2024-10979",  # PostgreSQL environment variable injection
    "CVE-2023-4966",   # Citrix Bleed — NOT in our environment (tests "not present" path)
]

NVD_API_KEY   = os.getenv("NVD_API_KEY")
# NVD rate limits: 50 req/30s with key, 5 req/30s without
NVD_DELAY     = 0.6 if NVD_API_KEY else 6.0
NVD_RETRIES   = 3

SNAPSHOTS_DIR = ROOT / "data" / "snapshots"
ENV_FILE      = ROOT / "data" / "environment.json"

# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _get(url: str, headers: dict[str, str] | None = None) -> bytes:
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


def _fetch_nvd(cve_id: str) -> dict:
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    for attempt in range(NVD_RETRIES):
        try:
            return json.loads(_get(url, headers))
        except urllib.error.HTTPError as exc:
            if exc.code in (429, 503) and attempt < NVD_RETRIES - 1:
                wait = 30 * (attempt + 1)
                print(f"    rate-limited ({exc.code}), retrying in {wait}s …")
                time.sleep(wait)
            else:
                raise
    return {}


def _fetch_kev() -> dict[str, dict]:
    """Return KEV feed as {cveID: entry}."""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    feed = json.loads(_get(url))
    return {v["cveID"]: v for v in feed.get("vulnerabilities", [])}


def _fetch_epss(cve_ids: list[str]) -> dict[str, dict]:
    """Return {cve_id: {"epss": float, "percentile": float}} from one batch EPSS call."""
    url = "https://api.first.org/data/v1/epss?cve=" + ",".join(cve_ids)
    data = json.loads(_get(url))
    return {
        item["cve"]: {
            "epss":       float(item["epss"]),
            "percentile": float(item.get("percentile", 0.0)),
        }
        for item in data.get("data", [])
    }

# ── Snapshot I/O ──────────────────────────────────────────────────────────────

def _save(cve_id: str, name: str, payload: dict) -> None:
    out = SNAPSHOTS_DIR / cve_id
    out.mkdir(parents=True, exist_ok=True)
    path = out / name
    with open(path, "w") as f:
        json.dump({"fetched_at": datetime.now(timezone.utc).isoformat(), **payload}, f, indent=2)
    print(f"    saved {path.relative_to(ROOT)}")

# ── Display helpers ───────────────────────────────────────────────────────────

def _range_text(cpe_match: dict) -> str:
    """Format version bounds from one cpeMatch entry."""
    tokens: list[str] = []
    if cpe_match.get("versionStartIncluding"): tokens.append(f">={cpe_match['versionStartIncluding']}")
    if cpe_match.get("versionStartExcluding"): tokens.append(f">{cpe_match['versionStartExcluding']}")
    if cpe_match.get("versionEndIncluding"):   tokens.append(f"<={cpe_match['versionEndIncluding']}")
    if cpe_match.get("versionEndExcluding"):   tokens.append(f"<{cpe_match['versionEndExcluding']}")
    return ", ".join(tokens) if tokens else "see NVD"


def _propose_vulnerable_version(ranges: list[dict]) -> str:
    """Suggest the last affected version from the first range that has an upper bound."""
    for r in ranges:
        if r.get("versionEndIncluding"):
            return r["versionEndIncluding"]
        if r.get("versionEndExcluding"):
            vee = r["versionEndExcluding"]
            parts = vee.split(".")
            try:
                parts[-1] = str(max(0, int(parts[-1]) - 1))
                return ".".join(parts)
            except ValueError:
                return vee
    return ""

# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    snapshots: dict[str, dict] = {cve_id: {} for cve_id in CVES}

    # 1. NVD ───────────────────────────────────────────────────────────────────
    print("Fetching NVD records …")
    for i, cve_id in enumerate(CVES):
        if i > 0:
            time.sleep(NVD_DELAY)
        print(f"  {cve_id}")
        try:
            nvd = _fetch_nvd(cve_id)
            _save(cve_id, "nvd.json", nvd)
            snapshots[cve_id]["nvd"] = nvd
        except Exception as exc:
            print(f"    ERROR: {exc}")
            snapshots[cve_id]["nvd"] = {}

    # 2. CISA KEV ──────────────────────────────────────────────────────────────
    print("\nFetching CISA KEV …")
    try:
        kev_map = _fetch_kev()
        print(f"  feed has {len(kev_map)} entries")
        for cve_id in CVES:
            entry = kev_map.get(cve_id, {})
            kev_snap = {
                "cveID":          cve_id,
                "in_kev":         bool(entry),
                "dateAdded":      entry.get("dateAdded"),
                "requiredAction": entry.get("requiredAction"),
            }
            _save(cve_id, "kev.json", kev_snap)
            snapshots[cve_id]["kev"] = kev_snap
    except Exception as exc:
        print(f"  ERROR: {exc}")
        for cve_id in CVES:
            snapshots[cve_id]["kev"] = {"in_kev": False}

    # 3. EPSS — saves both epss score and percentile ───────────────────────────
    print("\nFetching EPSS scores …")
    _epss_empty = {"epss": 0.0, "percentile": 0.0}
    try:
        epss_map = _fetch_epss(CVES)
        for cve_id in CVES:
            scores = epss_map.get(cve_id, _epss_empty)
            epss_snap = {"cve": cve_id, **scores}
            _save(cve_id, "epss.json", epss_snap)
            snapshots[cve_id]["epss"] = epss_snap
    except Exception as exc:
        print(f"  ERROR: {exc}")
        for cve_id in CVES:
            snapshots[cve_id]["epss"] = _epss_empty

    # 4. Version matching — runs before the table so the table can show match info
    print("\nChecking against environment.json …")
    assets = json.loads(ENV_FILE.read_text())["assets"]

    for cve_id in CVES:
        nvd = snapshots[cve_id].get("nvd", {})
        hits: list[dict] = []
        misses: list[dict] = []

        for asset in assets:
            for sw in asset.get("software", []):
                alias_list = ALIASES.get(sw["name"])
                if not alias_list:
                    continue
                # Try every (vendor, product) pair. A pair with ranges but no
                # version match does NOT stop iteration; only a version match stops it.
                hit_found   = False
                first_miss  = None
                for vendor, product in alias_list:
                    ranges = find_vulnerable_ranges(nvd, vendor, product)
                    if not ranges:
                        continue
                    entry = {
                        "asset":   asset["name"],
                        "sw_name": sw["name"],
                        "version": sw["version"],
                        "vendor":  vendor,
                        "product": product,
                    }
                    matched = first_matching_range(sw["version"], ranges)
                    if matched:
                        hits.append({**entry, "range": matched})
                        hit_found = True
                        break
                    elif first_miss is None:
                        first_miss = {**entry, "ranges": ranges}
                if not hit_found and first_miss is not None:
                    misses.append(first_miss)

        snapshots[cve_id]["hits"]   = hits
        snapshots[cve_id]["misses"] = misses

    # 5. Summary table ─────────────────────────────────────────────────────────
    W = 96
    print(f"\n{'─' * W}")
    print(f"{'CVE':<18} {'Matched vendor:product':<26} {'Range':<24} {'KEV':<5} {'EPSS':<8} {'Percentile'}")
    print(f"{'─' * W}")
    for cve_id in CVES:
        s      = snapshots[cve_id]
        hits   = s.get("hits", [])
        misses = s.get("misses", [])

        if hits:
            h   = hits[0]
            vp  = f"{h['vendor']}:{h['product']}"
            rng = _range_text(h["range"])
        elif misses:
            m   = misses[0]
            vp  = f"{m['vendor']}:{m['product']} (mismatch)"
            rng = ""
        else:
            vp  = "no match"
            rng = ""

        in_kev  = "yes" if s.get("kev", {}).get("in_kev") else "no"
        epss_d  = s.get("epss", {})
        epss_v  = f"{epss_d.get('epss', 0.0):.4f}"
        pct_v   = f"{epss_d.get('percentile', 0.0):.4f}"
        print(f"{cve_id:<18} {vp:<26} {rng:<24} {in_kev:<5} {epss_v:<8} {pct_v}")
    print(f"{'─' * W}")

    # 6. Detailed match report ─────────────────────────────────────────────────
    print()
    proposed: list[tuple[str, str, str, str]] = []

    for cve_id in CVES:
        hits   = snapshots[cve_id].get("hits", [])
        misses = snapshots[cve_id].get("misses", [])

        if hits:
            print(f"  {cve_id}  MATCH")
            for h in hits:
                print(f"    ✓ {h['asset']} ({h['sw_name']} {h['version']})")
        elif misses:
            m = misses[0]
            print(f"  {cve_id}  version mismatch")
            print(f"    {m['asset']}: {m['sw_name']} {m['version']} not in vulnerable range")
            fix = _propose_vulnerable_version(m["ranges"])
            if fix:
                print(f"    → propose environment.json change: {m['sw_name']} {m['version']!r} → {fix!r}")
                proposed.append((cve_id, m["asset"], m["sw_name"], fix))
        else:
            print(f"  {cve_id}  no matching product in environment")

    if proposed:
        print("\nProposed environment.json fixes (not applied — say 'apply fixes' to update):")
        for cve_id, asset_name, sw_name, fix in proposed:
            print(f"  {cve_id}: {asset_name} · {sw_name} → {fix}")


if __name__ == "__main__":
    main()
