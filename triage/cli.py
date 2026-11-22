"""Command-line interface for TriageLens.

Usage:
  python -m triage.cli --cve CVE-2024-23897
  python -m triage.cli --all
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv
load_dotenv()

import anthropic

from triage.agent import TOOLS, run_cve
from triage.tools.environment import load_environment

# CVEs in the answer key — used by --all
ANSWER_KEY_CVES = [
    "CVE-2024-23897",   # Jenkins arbitrary file read
    "CVE-2021-44228",   # Log4Shell
    "CVE-2023-44487",   # HTTP/2 Rapid Reset (nginx + jenkins)
    "CVE-2024-6387",    # OpenSSH regreSSHion
    "CVE-2024-10979",   # PostgreSQL env-var injection
    "CVE-2023-4966",    # Citrix Bleed — not present in env
]

PRIORITY_RANK: dict[str, int] = {
    "critical": 0, "high": 1, "medium": 2, "low": 3,
    "not-present": 4, "no-finding": 5,
}


def sort_findings(findings: list[dict]) -> list[dict]:
    """Order findings by priority → KEV (yes first) → EPSS (descending)."""
    return sorted(
        findings,
        key=lambda f: (
            PRIORITY_RANK.get(f.get("priority", "low"), 9),
            0 if f.get("in_kev") else 1,
            -float(f.get("epss", 0.0)),
        ),
    )


# ── Brief writer ──────────────────────────────────────────────────────────────

def _priority_header(p: str) -> str:
    labels = {
        "critical": "Critical", "high": "High",
        "medium": "Medium", "low": "Low",
        "not-present": "Not Present in Environment",
    }
    return labels.get(p, p.capitalize())


def _fmt_kev(f: dict) -> str:
    if not f.get("in_kev"):
        return "no"
    date = f.get("kev_date_added")
    return f"yes (added {date})" if date else "yes"


def _fmt_epss(f: dict) -> str:
    epss = f.get("epss", 0.0)
    if not epss:
        return "—"
    pct = f.get("epss_percentile", 0.0)
    return f"{epss:.5f} ({pct * 100:.1f}th pct)"


def _write_brief_md(
    path: Path,
    findings: list[dict],
    cve_list: list[str],
    usage: dict,
) -> None:
    lines: list[str] = [
        "# TriageLens Brief",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        f"CVEs analyzed: {', '.join(cve_list)}",
        "",
        "---",
        "",
    ]

    # Group by priority
    seen_priorities: list[str] = []
    by_priority: dict[str, list[dict]] = {}
    for f in findings:
        p = f.get("priority", "low")
        if p not in by_priority:
            by_priority[p] = []
            seen_priorities.append(p)
        by_priority[p].append(f)

    for p in seen_priorities:
        lines.append(f"## {_priority_header(p)}")
        lines.append("")

        for f in by_priority[p]:
            cve   = f.get("cve_id", "?")
            asset = f.get("asset_id") or "—"
            name  = f.get("asset_name") or asset

            lines.append(f"### {cve} — {name}")
            lines.append("")

            # Badges
            ar   = "yes (always escalate)" if f.get("always_review") else "no"
            kev  = _fmt_kev(f)
            epss = _fmt_epss(f)
            lines.append(f"**Priority:** {p} | **Always review:** {ar} | **KEV:** {kev} | **EPSS:** {epss}")
            lines.append("")

            reach = f.get("reachability_summary", "—")
            lines.append(f"**Path:** {reach}")
            mit   = f.get("mitigation", "—")
            lines.append(f"**Mitigation:** {mit}")
            mit_d = f.get("mitigation_detail", "")
            if mit_d:
                lines.append(f"**Detail:** {mit_d}")
            lines.append("")

            reasons = f.get("reasons", [])
            if reasons:
                lines.append("**Evidence:**")
                for r in reasons:
                    if isinstance(r, dict):
                        lines.append(f"- {r.get('claim', '?')}  *(source: {r.get('source', '?')})*")
                    else:
                        lines.append(f"- {r}")
                lines.append("")

            nhr = f.get("needs_human_review", False)
            rr  = f.get("review_reasons", [])
            lines.append(f"**Needs human review:** {'yes' if nhr else 'no'}")
            if nhr and rr:
                for note in rr:
                    lines.append(f"- {note}")
            lines.append("")
            lines.append("---")
            lines.append("")

    # Token / time section
    per_cve = usage.get("per_cve", {})
    total   = usage.get("total", {})
    if per_cve:
        lines.append("## Token / Time Usage")
        lines.append("")
        lines.append("| CVE | Input tokens | Output tokens | Seconds |")
        lines.append("|-----|-------------|--------------|---------|")
        for cve_id, s in per_cve.items():
            lines.append(
                f"| {cve_id} | {s['input_tokens']:,} | {s['output_tokens']:,} | {s['seconds']:.1f} |"
            )
        lines.append(
            f"| **Total** | **{total.get('input_tokens', 0):,}** "
            f"| **{total.get('output_tokens', 0):,}** "
            f"| **{total.get('seconds', 0.0):.1f}** |"
        )
        lines.append("")

    path.write_text("\n".join(lines))


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m triage.cli",
        description="TriageLens CVE triage agent",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--cve",  metavar="CVE_ID", help="Triage a single CVE")
    group.add_argument("--all",  action="store_true", help="Triage all CVEs in the answer key")
    args = parser.parse_args()

    cve_list = ANSWER_KEY_CVES if args.all else [args.cve]

    # Create run directory
    ts      = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = ROOT / "runs" / ts
    run_dir.mkdir(parents=True, exist_ok=True)

    model  = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5-5")
    client = anthropic.Anthropic()
    env    = load_environment()

    all_findings: list[dict] = []
    per_cve_stats: dict[str, dict] = {}
    total_input  = 0
    total_output = 0
    total_secs   = 0.0

    for cve_id in cve_list:
        print(f"Triaging {cve_id} …", flush=True)
        findings, stats = run_cve(cve_id, client, model, env, run_dir)
        all_findings.extend(findings)
        per_cve_stats[cve_id] = stats
        total_input  += stats["input_tokens"]
        total_output += stats["output_tokens"]
        total_secs   += stats["seconds"]
        print(
            f"  → {len(findings)} finding(s)  "
            f"({stats['input_tokens']} in / {stats['output_tokens']} out tokens, "
            f"{stats['seconds']:.1f}s)"
        )

    all_findings = sort_findings(all_findings)

    usage = {
        "per_cve": per_cve_stats,
        "total":   {
            "input_tokens":  total_input,
            "output_tokens": total_output,
            "seconds":       round(total_secs, 2),
        },
    }

    # Write brief.json
    brief_json = {
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "model":          model,
        "cves_analyzed":  cve_list,
        "finding_count":  len(all_findings),
        "findings":       all_findings,
        "usage":          usage,
    }
    brief_json_path = run_dir / "brief.json"
    brief_json_path.write_text(json.dumps(brief_json, indent=2))

    # Write brief.md
    brief_md_path = run_dir / "brief.md"
    _write_brief_md(brief_md_path, all_findings, cve_list, usage)

    print(f"\nRun saved to: {run_dir}")
    print(f"  brief.json  ({len(all_findings)} finding(s))")
    print(f"  brief.md")
    print(f"  trace.jsonl")
    print(f"\nTotal: {total_input:,} input / {total_output:,} output tokens, {total_secs:.1f}s")

    # Print brief.md to stdout for quick inspection
    print("\n" + "─" * 70)
    print(brief_md_path.read_text())


if __name__ == "__main__":
    main()
