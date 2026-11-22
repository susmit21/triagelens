"""Rules-only baseline: no LLM.

For every (CVE, asset) pair in data/answer_key.json, runs:
  1. find_affected_assets   — confirm the CVE is present in the environment
  2. check_reachability     — walk SG rules to get path and hop count
  3. rank                   — apply priority rules

Prints a table comparing the computed priority to the answer key, then
reports the overall match rate.  Mismatches are shown with the computed
reasons so you can decide whether to adjust the rules.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from triage.tools.asset_search  import find_affected_assets
from triage.tools.environment   import load_cve_snapshot, load_environment
from triage.tools.reachability  import check_reachability
from triage.tools.ranking       import rank


def _path_summary(paths: list) -> str:
    if not paths:
        return "—"
    # Pick shortest path
    p = min(paths, key=lambda x: x.hop_count)
    hops = " → ".join(f"{h.to}:{h.port}" for h in p.hops)
    source = p.source
    ctrl = ",".join(p.all_controls) if p.all_controls else "none"
    return f"{source} → {hops}  [{ctrl}]"


def main() -> None:
    env  = load_environment()
    key  = json.loads((ROOT / "data" / "answer_key.json").read_text())

    rows = []

    for entry in key["entries"]:
        cve_id    = entry.get("cve_id")
        asset_id  = entry.get("asset_id")
        expected  = entry["expected_priority"]
        acceptable = entry.get("acceptable_priorities", [expected])

        # ── Not-present and decoy entries ────────────────────────────────────
        if cve_id is None:
            rows.append({
                "cve":          "—",
                "asset":        entry.get("asset_name", "?"),
                "computed":     "no-finding",
                "expected":     expected,
                "match":        "YES" if "no-finding" in acceptable else "NO",
                "path":         "—",
                "reasons":      [],
                "in_kev":       False,
                "epss":         0.0,
                "always_review": False,
            })
            continue

        if not entry.get("present", True) or asset_id is None:
            # CVE-2023-4966 style: not in this environment
            hits = find_affected_assets(
                cve_id, env=env,
                snapshot=load_cve_snapshot(cve_id),
            )
            computed = "not-present" if not hits else "present (unexpected)"
            rows.append({
                "cve":          cve_id,
                "asset":        "—",
                "computed":     computed,
                "expected":     expected,
                "match":        "YES" if computed in acceptable else "NO",
                "path":         "—",
                "reasons":      [],
                "in_kev":       False,
                "epss":         0.0,
                "always_review": False,
            })
            continue

        # ── Scored entries ───────────────────────────────────────────────────
        try:
            snap  = load_cve_snapshot(cve_id)
            reach = check_reachability(asset_id, env=env)
            rank_result = rank(cve_id, asset_id, reach, env=env, snapshot=snap)
        except Exception as exc:
            rows.append({
                "cve":          cve_id,
                "asset":        asset_id,
                "computed":     f"ERROR: {exc}",
                "expected":     expected,
                "match":        "NO",
                "path":         "—",
                "reasons":      [],
                "in_kev":       False,
                "epss":         0.0,
                "always_review": False,
            })
            continue

        # Build the best path summary (prefer internet if available)
        if reach.internet_paths:
            path_str = _path_summary(reach.internet_paths)
        else:
            path_str = _path_summary(reach.office_paths)

        match = "YES" if rank_result.priority in acceptable else "NO"

        rows.append({
            "cve":          cve_id,
            "asset":        entry.get("asset_name", asset_id),
            "computed":     rank_result.priority,
            "expected":     expected,
            "match":        match,
            "path":         path_str,
            "reasons":      rank_result.reasons,
            "in_kev":       rank_result.in_kev,
            "epss":         rank_result.epss_score,
            "always_review": rank_result.always_review,
        })

    # ── Sort: priority → KEV first → EPSS descending ─────────────────────────
    PRIORITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "not-present": 4, "no-finding": 5}
    rows.sort(key=lambda r: (
        PRIORITY_RANK.get(r["computed"], 9),
        0 if r["in_kev"] else 1,
        -r["epss"],
    ))

    # ── Print table ───────────────────────────────────────────────────────────
    W = 118
    print(f"\n{'─' * W}")
    print(f"{'CVE':<18} {'Asset':<18} {'Computed':<10} {'Expected':<12} {'Match':<6} {'KEV':<5} {'EPSS':<8} {'AR':<4}  Path")
    print(f"{'─' * W}")

    matches = 0
    for r in rows:
        mark    = "✓" if r["match"] == "YES" else "✗"
        kev_col = "yes" if r["in_kev"] else "no"
        ar_col  = "yes" if r["always_review"] else "no"
        epss_col = f"{r['epss']:.4f}" if r["epss"] else "—"
        path_col = r["path"][:44] + ("…" if len(r["path"]) > 44 else "")
        print(f"{mark} {r['cve']:<17} {r['asset']:<18} {r['computed']:<10} {r['expected']:<12} {r['match']:<6} {kev_col:<5} {epss_col:<8} {ar_col:<4}  {path_col}")
        if r["match"] == "YES":
            matches += 1

    total = len(rows)
    print(f"{'─' * W}")
    print(f"\nMatch rate: {matches}/{total}  ({100*matches/total:.0f}%)\n")

    # ── Show reasons for mismatches ───────────────────────────────────────────
    mismatches = [r for r in rows if r["match"] == "NO"]
    if mismatches:
        print("── Mismatch details ─────────────────────────────────────────────────────")
        for r in mismatches:
            print(f"\n  {r['cve']} / {r['asset']}")
            print(f"  computed={r['computed']}  expected={r['expected']}")
            for reason in r["reasons"]:
                print(f"    • {reason}")


if __name__ == "__main__":
    main()
