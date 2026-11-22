"""Offline evaluation of a TriageLens run against the answer key.

Stage 6 additions:
  - fix_from_advisory: fraction of patch findings backed by advisory citations
  - version_in_advisory: fraction of patch findings where version in mitigation_detail
    also appears in an advisory citation text

Computes 8 metrics for the agent (from brief.json) and the rules baseline
(computed in-process using the plain-code tools), then writes results.json
and results.md side-by-side.

Usage:
  python eval/evaluate.py                          # latest run in runs/
  python eval/evaluate.py --run runs/20261122T000213Z
  python eval/evaluate.py --answer-key path/to/key.json
"""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Valid tool-name prefixes for the groundedness check
_VALID_TOOL_PREFIXES = frozenset(
    {"get_cve_details", "find_affected_assets", "check_reachability", "rank_finding",
     "search_advisories"}
)

# Version extraction helpers (Stage 6)
_URL_RE     = re.compile(r"https?://\S+")
_CVE_RE     = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
_CHUNK_ID_RE = re.compile(r"\b[A-Za-z0-9]+-\d{4}-\d+_\d+_\d+\b")
_VERSION_RE = re.compile(r"\b\d+\.\d+(?:\.\d+)*(?:p\d+)?\b")


def _extract_versions(text: str) -> set[str]:
    """Extract version strings after removing URLs, CVE IDs, and chunk IDs."""
    cleaned = _URL_RE.sub(" ", text)
    cleaned = _CVE_RE.sub(" ", cleaned)
    cleaned = _CHUNK_ID_RE.sub(" ", cleaned)
    return set(_VERSION_RE.findall(cleaned))


# ── Rules baseline ────────────────────────────────────────────────────────────

def _run_rules_baseline(key_entries: list[dict]) -> list[dict]:
    """
    Run the plain-code triage tools against every scoreable answer-key entry.
    Returns findings in the same dict shape used for metric computation.
    """
    # Import here so this module can be imported in tests without side effects
    from triage.tools.environment import load_environment, load_cve_snapshot
    from triage.tools.asset_search import find_affected_assets
    from triage.tools.reachability import check_reachability
    from triage.tools.ranking import rank

    env = load_environment()
    findings: list[dict] = []

    for entry in key_entries:
        cve_id   = entry.get("cve_id")
        asset_id = entry.get("asset_id")

        # Decoy: no CVE — the rules baseline never triages this asset,
        # so simply skip it; "no finding" is the correct outcome by definition.
        if cve_id is None:
            continue

        # Not-present CVE
        if not entry.get("present", True) or asset_id is None:
            snap = load_cve_snapshot(cve_id)
            hits = find_affected_assets(cve_id, env=env, snapshot=snap)
            priority = "not-present" if not hits else "present (unexpected)"
            findings.append({
                "cve_id":                 cve_id,
                "asset_id":               None,
                "asset_name":             None,
                "priority":               priority,
                "reasons":                [],
                "in_kev":                 False,
                "epss":                   0.0,
                "always_review":          False,
                "needs_human_review":     False,
                "reachable_from_internet": False,
                "reachable_from_office":   False,
                "min_hops_internet":      None,
                "min_hops_office":        None,
            })
            continue

        # Scored entry
        snap   = load_cve_snapshot(cve_id)
        reach  = check_reachability(asset_id, env=env)
        result = rank(cve_id, asset_id, reach, env=env, snapshot=snap)

        min_internet = (
            min(p.hop_count for p in reach.internet_paths)
            if reach.internet_paths else None
        )
        min_office = (
            min(p.hop_count for p in reach.office_paths)
            if reach.office_paths else None
        )

        findings.append({
            "cve_id":                 cve_id,
            "asset_id":               asset_id,
            "asset_name":             entry.get("asset_name"),
            "priority":               result.priority,
            "reasons":                [{"claim": r, "source": "rank_finding"} for r in result.reasons],
            "in_kev":                 result.in_kev,
            "epss":                   result.epss_score,
            "always_review":          result.always_review,
            "needs_human_review":     False,
            "reachable_from_internet": reach.reachable_from_internet,
            "reachable_from_office":   reach.reachable_from_office,
            "min_hops_internet":      min_internet,
            "min_hops_office":        min_office,
        })

    return findings


# ── Metrics ───────────────────────────────────────────────────────────────────

def _expected_hops(entry: dict) -> tuple[int | None, int | None]:
    """Return (min_internet_hops, min_office_hops) from an answer-key entry."""
    int_hops = [p["hop_count"] for p in entry.get("paths", []) if p["source"] == "internet"]
    off_hops = [p["hop_count"] for p in entry.get("paths", []) if p["source"] == "office"]
    return (min(int_hops) if int_hops else None, min(off_hops) if off_hops else None)


def _is_grounded(reason: dict) -> bool:
    """A reason is grounded when its source starts with a known tool name."""
    src = (reason.get("source") or "").strip()
    return any(src == p or src.startswith(p + ".") or src.startswith(p + " ")
               for p in _VALID_TOOL_PREFIXES)


def compute_metrics(
    agent_findings: list[dict],
    rules_findings: list[dict],
    key_entries: list[dict],
) -> dict:
    """
    Compute all evaluation metrics.  Pure function — no I/O.

    Returns a dict with keys: priority_accuracy, missed_high, exposure_accuracy,
    groundedness, not_present, decoy, human_review, per_finding.
    """
    # Build lookup by (cve_id, asset_id) for quick join
    agent_by = {(f.get("cve_id"), f.get("asset_id")): f for f in agent_findings}
    rules_by = {(f.get("cve_id"), f.get("asset_id")): f for f in rules_findings}

    # Scored entries (present=true, real asset_id)
    scored = [
        e for e in key_entries
        if e.get("present", True) and e.get("cve_id") and e.get("asset_id")
    ]

    # ── Priority accuracy ─────────────────────────────────────────────────────
    agent_pa_correct = 0
    rules_pa_correct = 0
    agent_missed_high = 0
    rules_missed_high = 0

    per_finding: list[dict] = []

    for entry in scored:
        cve_id   = entry["cve_id"]
        asset_id = entry["asset_id"]
        expected = entry["expected_priority"]
        acceptable = entry.get("acceptable_priorities", [expected])
        exp_int_hops, exp_off_hops = _expected_hops(entry)

        agent_f = agent_by.get((cve_id, asset_id))
        rules_f = rules_by.get((cve_id, asset_id))

        a_priority = agent_f.get("priority") if agent_f else None
        r_priority = rules_f.get("priority") if rules_f else None

        a_match = a_priority in acceptable
        r_match = r_priority in acceptable

        if a_match:
            agent_pa_correct += 1
        elif expected in ("critical", "high"):
            agent_missed_high += 1

        if r_match:
            rules_pa_correct += 1
        elif expected in ("critical", "high"):
            rules_missed_high += 1

        # Exposure accuracy for this entry (agent only)
        exp_internet = entry.get("reachable_from_internet", False)
        exp_office   = entry.get("reachable_from_office",   False)

        a_exp_ok = False
        a_int_hops = None
        a_off_hops = None
        if agent_f:
            a_internet = agent_f.get("reachable_from_internet", False)
            a_office   = agent_f.get("reachable_from_office",   False)
            a_int_hops = agent_f.get("min_hops_internet")
            a_off_hops = agent_f.get("min_hops_office")

            bool_ok = (a_internet == exp_internet) and (a_office == exp_office)
            # Hop count: compare primary path (internet if reachable, else office)
            if exp_internet:
                hops_ok = (a_int_hops == exp_int_hops)
            else:
                hops_ok = (a_off_hops == exp_off_hops)
            a_exp_ok = bool_ok and hops_ok

        per_finding.append({
            "cve_id":           cve_id,
            "asset_name":       entry.get("asset_name", asset_id),
            "expected":         expected,
            "acceptable":       acceptable,
            "agent_priority":   a_priority,
            "agent_match":      a_match,
            "rules_priority":   r_priority,
            "rules_match":      r_match,
            "exp_internet":     exp_internet,
            "exp_office":       exp_office,
            "exp_int_hops":     exp_int_hops,
            "exp_off_hops":     exp_off_hops,
            "agent_int_hops":   a_int_hops,
            "agent_off_hops":   a_off_hops,
            "agent_exp_ok":     a_exp_ok,
        })

    agent_exp_correct = sum(1 for pf in per_finding if pf["agent_exp_ok"])

    # ── Groundedness ─────────────────────────────────────────────────────────
    total_reasons    = 0
    grounded_reasons = 0
    for f in agent_findings:
        for r in f.get("reasons", []):
            if isinstance(r, dict):
                total_reasons += 1
                if _is_grounded(r):
                    grounded_reasons += 1

    # ── Not-present check (CVE-2023-4966) ────────────────────────────────────
    agent_not_present_ok = not any(
        f.get("cve_id") == "CVE-2023-4966" and f.get("asset_id") is not None
        for f in agent_findings
    )
    rules_not_present_ok = not any(
        f.get("cve_id") == "CVE-2023-4966" and f.get("asset_id") is not None
        for f in rules_findings
    )

    # ── Decoy check (ftp-server-01 / asset-ftp) ───────────────────────────────
    agent_decoy_ok = not any(f.get("asset_id") == "asset-ftp" for f in agent_findings)
    rules_decoy_ok = not any(f.get("asset_id") == "asset-ftp" for f in rules_findings)

    # ── Human review (exclude not-present findings from denominator) ─────────
    _present_findings   = [
        f for f in agent_findings
        if f.get("priority") not in ("not-present", "no-finding")
    ]
    agent_needs_review  = sum(1 for f in _present_findings if f.get("needs_human_review"))
    agent_always_review = sum(1 for f in agent_findings if f.get("always_review"))
    agent_total         = len(_present_findings)

    # ── Mitigation detail sourced ─────────────────────────────────────────────
    # A detail is "sourced" if it references a tool/snapshot field OR contains a URL.
    def _detail_sourced(detail: str) -> bool:
        if not detail:
            return False
        lower = detail.lower()
        if "http" in lower:
            return True
        return any(tok in lower for tok in (
            "find_affected_assets", "matched_range",
            "get_cve_details", "check_reachability", "rank_finding",
        ))

    mit_detail_total   = sum(1 for f in _present_findings if f.get("mitigation_detail"))
    mit_detail_sourced = sum(
        1 for f in _present_findings
        if _detail_sourced(f.get("mitigation_detail", ""))
    )

    # ── Fix from advisory / version verified (Stage 6) ───────────────────────
    patch_findings = [f for f in _present_findings if f.get("mitigation") == "patch"]
    fix_from_adv_count = sum(
        1 for f in patch_findings
        if f.get("advisory_citations")
    )

    version_verified_count = 0
    for f in patch_findings:
        detail  = f.get("mitigation_detail", "")
        detail_versions = _extract_versions(detail)
        if not detail_versions:
            continue
        # Collect versions mentioned in any advisory citation text
        adv_versions: set[str] = set()
        for citation in f.get("advisory_citations", []):
            adv_versions |= _extract_versions(citation.get("text", ""))
        if detail_versions & adv_versions:
            version_verified_count += 1

    return {
        "priority_accuracy": {
            "agent": {"correct": agent_pa_correct, "total": len(scored)},
            "rules": {"correct": rules_pa_correct, "total": len(scored)},
        },
        "missed_high": {
            "agent": agent_missed_high,
            "rules": rules_missed_high,
        },
        "exposure_accuracy": {
            "agent": {"correct": agent_exp_correct, "total": len(scored)},
        },
        "groundedness": {
            "agent": {"grounded": grounded_reasons, "total": total_reasons},
        },
        "not_present": {
            "agent": agent_not_present_ok,
            "rules": rules_not_present_ok,
        },
        "decoy": {
            "agent": agent_decoy_ok,
            "rules": rules_decoy_ok,
        },
        "human_review": {
            "needs_review":        agent_needs_review,
            "always_review":       agent_always_review,
            "total":               agent_total,
        },
        "mitigation_detail_sourced": {
            "sourced": mit_detail_sourced,
            "total":   mit_detail_total,
        },
        "fix_from_advisory": {
            "cited":        fix_from_adv_count,
            "total_patch":  len(patch_findings),
        },
        "version_in_advisory": {
            "verified":     version_verified_count,
            "total_patch":  len(patch_findings),
        },
        "per_finding": per_finding,
    }


# ── Formatting ────────────────────────────────────────────────────────────────

def _pct(correct: int, total: int) -> str:
    if total == 0:
        return "—"
    return f"{correct}/{total} ({100 * correct / total:.1f}%)"


def _pass_fail(ok: bool) -> str:
    return "pass" if ok else "FAIL"


def format_results_md(metrics: dict, run_meta: dict) -> str:
    lines: list[str] = [
        "# TriageLens Evaluation Results",
        "",
        f"Run: {run_meta.get('run_dir', '—')}",
        f"Model: {run_meta.get('model', '—')}",
        f"Evaluated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        f"Answer key: {run_meta.get('key_entries', 0)} entries "
        f"({run_meta.get('scored', 0)} scored, "
        f"{run_meta.get('not_present', 0)} not-present, "
        f"{run_meta.get('decoy', 0)} decoy)",
        "",
        "---",
        "",
        "## Priority (per finding)",
        "",
        "| CVE | Asset | Expected | Agent | ✓ | Rules | ✓ |",
        "|-----|-------|----------|-------|---|-------|---|",
    ]

    for pf in metrics["per_finding"]:
        a_mark = "✓" if pf["agent_match"] else "✗"
        r_mark = "✓" if pf["rules_match"] else "✗"
        a_pri  = pf["agent_priority"] or "—"
        r_pri  = pf["rules_priority"] or "—"
        exp    = "/".join(pf["acceptable"])
        lines.append(
            f"| {pf['cve_id']} | {pf['asset_name']} | {exp} "
            f"| {a_pri} | {a_mark} | {r_pri} | {r_mark} |"
        )

    lines += [
        "",
        "## Exposure (agent only)",
        "",
        "| Asset | Exp internet | Exp office | Exp hops | Agent int hops | Agent off hops | ✓ |",
        "|-------|-------------|-----------|---------|---------------|--------------|---|",
    ]
    for pf in metrics["per_finding"]:
        exp_hops = (
            f"i:{pf['exp_int_hops']}" if pf["exp_internet"] else f"o:{pf['exp_off_hops']}"
        )
        a_hops = (
            f"i:{pf['agent_int_hops']}" if pf["exp_internet"]
            else f"o:{pf['agent_off_hops']}"
        )
        mark = "✓" if pf["agent_exp_ok"] else "✗"
        lines.append(
            f"| {pf['asset_name']} "
            f"| {'yes' if pf['exp_internet'] else 'no'} "
            f"| {'yes' if pf['exp_office'] else 'no'} "
            f"| {exp_hops} | {pf['agent_int_hops'] or '—'} | {pf['agent_off_hops'] or '—'} "
            f"| {mark} |"
        )

    pa     = metrics["priority_accuracy"]
    mh     = metrics["missed_high"]
    ea     = metrics["exposure_accuracy"]
    grd    = metrics["groundedness"]
    np_    = metrics["not_present"]
    dec    = metrics["decoy"]
    hr     = metrics["human_review"]

    lines += [
        "",
        "## Summary Metrics",
        "",
        "| Metric | Agent | Rules |",
        "|--------|-------|-------|",
        f"| Priority accuracy | {_pct(pa['agent']['correct'], pa['agent']['total'])} "
        f"| {_pct(pa['rules']['correct'], pa['rules']['total'])} |",
        f"| Missed critical/high | {mh['agent']} | {mh['rules']} |",
        f"| Exposure accuracy | {_pct(ea['agent']['correct'], ea['agent']['total'])} | — |",
        f"| Groundedness | "
        f"{_pct(grd['agent']['grounded'], grd['agent']['total'])} | — |",
        f"| Not-present (CVE-2023-4966) | {_pass_fail(np_['agent'])} "
        f"| {_pass_fail(np_['rules'])} |",
        f"| Decoy clean (ftp-server-01) | {_pass_fail(dec['agent'])} "
        f"| {_pass_fail(dec['rules'])} |",
        f"| Needs human review | {_pct(hr['needs_review'], hr['total'])} | — |",
        f"| Always-review findings | {hr['always_review']} | — |",
    ]

    mds = metrics.get("mitigation_detail_sourced", {})
    if mds.get("total", 0) > 0:
        lines.append(
            f"| Mitigation detail sourced | "
            f"{_pct(mds['sourced'], mds['total'])} | — |"
        )
    ffa = metrics.get("fix_from_advisory", {})
    via = metrics.get("version_in_advisory", {})
    if ffa.get("total_patch", 0) > 0:
        lines.append(
            f"| Fix from advisory | "
            f"{_pct(ffa['cited'], ffa['total_patch'])} | — |"
        )
    if via.get("total_patch", 0) > 0:
        lines.append(
            f"| Version verified in advisory | "
            f"{_pct(via['verified'], via['total_patch'])} | — |"
        )
    lines += ["", ""]

    # Token / time usage from run_meta
    per_cve = run_meta.get("per_cve_usage", {})
    total_u = run_meta.get("total_usage", {})
    if per_cve:
        lines += [
            "## Token / Time (Agent)",
            "",
            "| CVE | Input tokens | Output tokens | Seconds |",
            "|-----|-------------|--------------|---------|",
        ]
        for cve_id, s in per_cve.items():
            lines.append(
                f"| {cve_id} | {s.get('input_tokens', 0):,} "
                f"| {s.get('output_tokens', 0):,} "
                f"| {s.get('seconds', 0.0):.1f} |"
            )
        lines.append(
            f"| **Total** | **{total_u.get('input_tokens', 0):,}** "
            f"| **{total_u.get('output_tokens', 0):,}** "
            f"| **{total_u.get('seconds', 0.0):.1f}** |"
        )
        lines.append("")

    return "\n".join(lines)


# ── Main ──────────────────────────────────────────────────────────────────────

def _latest_run(runs_dir: Path) -> Path:
    dirs = sorted(d for d in runs_dir.iterdir() if d.is_dir() and (d / "brief.json").exists())
    if not dirs:
        raise FileNotFoundError(f"No completed run directories found in {runs_dir}")
    return dirs[-1]


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate a TriageLens run")
    parser.add_argument(
        "--run", metavar="DIR",
        help="Run directory (default: latest in runs/)",
    )
    parser.add_argument(
        "--answer-key", metavar="PATH",
        default=str(ROOT / "data" / "answer_key.json"),
        help="Answer key JSON (default: data/answer_key.json)",
    )
    args = parser.parse_args()

    runs_dir = ROOT / "runs"
    run_dir  = Path(args.run) if args.run else _latest_run(runs_dir)

    print(f"Run:        {run_dir}")
    print(f"Answer key: {args.answer_key}")

    brief      = json.loads((run_dir / "brief.json").read_text())
    key        = json.loads(Path(args.answer_key).read_text())
    key_entries = key["entries"]

    agent_findings = brief.get("findings", [])

    print("Running rules baseline …")
    rules_findings = _run_rules_baseline(key_entries)

    metrics = compute_metrics(agent_findings, rules_findings, key_entries)

    scored_count    = sum(1 for e in key_entries if e.get("present", True) and e.get("cve_id") and e.get("asset_id"))
    not_pres_count  = sum(1 for e in key_entries if not e.get("present", True) and e.get("cve_id"))
    decoy_count     = sum(1 for e in key_entries if e.get("cve_id") is None)

    usage    = brief.get("usage", {})
    run_meta = {
        "run_dir":       str(run_dir),
        "model":         brief.get("model", "—"),
        "key_entries":   len(key_entries),
        "scored":        scored_count,
        "not_present":   not_pres_count,
        "decoy":         decoy_count,
        "per_cve_usage": usage.get("per_cve", {}),
        "total_usage":   usage.get("total", {}),
    }

    # Write results.json
    results_json = {
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "run_dir":      str(run_dir),
        "model":        run_meta["model"],
        "metrics":      metrics,
    }
    out_dir = ROOT / "eval"
    (out_dir / "results.json").write_text(json.dumps(results_json, indent=2))

    # Write results.md
    md = format_results_md(metrics, run_meta)
    (out_dir / "results.md").write_text(md)

    print(f"\nResults written to:")
    print(f"  eval/results.json")
    print(f"  eval/results.md")
    print("\n" + "─" * 70)
    print(md)


if __name__ == "__main__":
    main()
