"""TriageLens web UI — read-only brief viewer.

Run: streamlit run app/app.py
"""
from __future__ import annotations

import json
import pathlib

import streamlit as st

ROOT     = pathlib.Path(__file__).resolve().parent.parent
RUNS_DIR = ROOT / "runs"

st.set_page_config(
    page_title="TriageLens",
    page_icon="🔍",
    layout="wide",
)

# ── Load available runs ───────────────────────────────────────────────────────

run_dirs = sorted(
    [d for d in RUNS_DIR.iterdir() if d.is_dir() and (d / "brief.json").exists()],
    reverse=True,
) if RUNS_DIR.exists() else []

if not run_dirs:
    st.error("No completed runs found in `runs/`. Run `python -m triage.cli --all` first.")
    st.stop()

# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.title("🔍 TriageLens")
    st.caption("Read-only brief viewer")

    selected_name = st.selectbox(
        "Run",
        [d.name for d in run_dirs],
        index=0,
        label_visibility="collapsed",
    )
    selected_run = RUNS_DIR / selected_name

    # Load brief
    try:
        brief = json.loads((selected_run / "brief.json").read_text())
    except Exception as exc:
        st.error(f"Could not read brief.json: {exc}")
        st.stop()

    findings  = brief.get("findings", [])
    usage     = brief.get("usage", {})
    total_u   = usage.get("total", {})
    model     = brief.get("model", "—")

    st.divider()
    st.markdown("**Run summary**")
    c1, c2 = st.columns(2)
    c1.metric("CVEs",     len(brief.get("cves_analyzed", [])))
    c2.metric("Findings", brief.get("finding_count", 0))
    c1.metric("In tokens",  f"{total_u.get('input_tokens', 0):,}")
    c2.metric("Out tokens", f"{total_u.get('output_tokens', 0):,}")
    st.metric("Wall-clock", f"{total_u.get('seconds', 0):.1f} s")
    st.markdown(f"**Model:** `{model}`")
    st.markdown(f"**Generated:** {brief.get('generated_at', '—')[:19]}")

# ── Load trace ────────────────────────────────────────────────────────────────

trace_entries: list[dict] = []
trace_path = selected_run / "trace.jsonl"
if trace_path.exists():
    for line in trace_path.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                trace_entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass

# ── Badge helpers ─────────────────────────────────────────────────────────────

_P_COLOR = {
    "critical":    ("#c0392b", "white"),
    "high":        ("#e67e22", "white"),
    "medium":      ("#d4ac0d", "white"),
    "low":         ("#27ae60", "white"),
    "not-present": ("#7f8c8d", "white"),
}


def _badge(text: str, bg: str, fg: str = "white") -> str:
    return (
        f'<span style="background:{bg};color:{fg};padding:2px 10px;'
        f'border-radius:12px;font-weight:bold;font-size:0.82em">{text}</span>'
    )


def _priority_badge(priority: str) -> str:
    bg, fg = _P_COLOR.get(priority, ("#95a5a6", "white"))
    return _badge(priority.upper(), bg, fg)


def _kev_badge(f: dict) -> str:
    if f.get("in_kev"):
        d = f.get("kev_date_added") or ""
        label = f"KEV {d}".strip()
        return _badge(label, "#8e44ad")
    return _badge("KEV: no", "#bdc3c7", "#555")


def _epss_str(f: dict) -> str:
    epss = f.get("epss", 0.0)
    if not epss:
        return "EPSS —"
    pct = f.get("epss_percentile", 0.0)
    return f"EPSS {epss:.5f} ({pct * 100:.1f}th pct)"


def _render_trace_entry(entry: dict) -> None:
    t = entry.get("type")
    if t == "thought":
        st.info(f"💭 {entry.get('text', '')}")
    elif t == "tool_call":
        name = entry.get("name", "?")
        inp  = entry.get("input", {})
        st.markdown(f"**🔧 `{name}`**")
        st.code(json.dumps(inp, indent=2, default=str), language="json")
    elif t == "tool_result":
        name   = entry.get("name", "?")
        output = entry.get("output", {})
        st.markdown(f"**📋 `{name}` result**")
        output_str = json.dumps(output, indent=2, default=str)
        if len(output_str) > 2000:
            output_str = output_str[:2000] + "\n… (truncated)"
        if isinstance(output, dict) and "error" in output:
            st.warning(output_str)
        else:
            st.code(output_str, language="json")


# ── Main area ─────────────────────────────────────────────────────────────────

st.title("TriageLens Brief")
st.caption(f"Run `{selected_name}`  ·  {brief.get('generated_at', '')[:19]} UTC")

# Eval results panel
eval_md_path = ROOT / "eval" / "results.md"
if eval_md_path.exists():
    with st.expander("📊 Evaluation results", expanded=False):
        st.markdown(eval_md_path.read_text())

st.divider()

# ── Findings ─────────────────────────────────────────────────────────────────

if not findings:
    st.info("No findings in this run.")
    st.stop()

shown_traces: set[str | None] = set()

for f in findings:
    cve_id     = f.get("cve_id") or "—"
    asset_id   = f.get("asset_id") or "—"
    asset_name = f.get("asset_name") or asset_id
    priority   = f.get("priority", "low")

    # Header: CVE + asset + priority badge
    st.markdown(
        f"### {cve_id} &mdash; {asset_name} &nbsp;"
        + _priority_badge(priority),
        unsafe_allow_html=True,
    )

    # Badge row: KEV, EPSS, always_review, needs_human_review
    badges: list[str] = [_kev_badge(f), _epss_str(f)]
    if f.get("always_review"):
        badges.append(_badge("⚠ ALWAYS REVIEW", "#c0392b"))
    if f.get("needs_human_review"):
        badges.append(_badge("👁 HUMAN REVIEW", "#e74c3c"))
    st.markdown(" &nbsp; ".join(badges) + " &nbsp;", unsafe_allow_html=True)
    st.markdown("")

    # Reachability path
    path = f.get("reachability_summary") or "—"
    st.markdown(f"**Path:** `{path}`")

    # Mitigation
    mit   = f.get("mitigation", "—")
    mit_d = f.get("mitigation_detail", "")
    st.markdown(f"**Mitigation:** {mit}")
    if mit_d:
        st.markdown(f"**Detail:** {mit_d}")

    # Evidence
    reasons = f.get("reasons", [])
    if reasons:
        st.markdown("**Evidence:**")
        for r in reasons:
            if isinstance(r, dict):
                st.markdown(
                    f"- {r.get('claim', '?')}  "
                    f"*(source: {r.get('source', '?')})*"
                )
            else:
                st.markdown(f"- {r}")

    # Review notes
    nhr = f.get("needs_human_review", False)
    rr  = f.get("review_reasons") or []
    if nhr and rr:
        st.markdown("**Review notes:**")
        for note in rr:
            st.markdown(f"- {note}")

    # Trace expander (deduplicated per CVE)
    cve_trace = [
        e for e in trace_entries
        if e.get("cve_id") == cve_id
        and e.get("type") in ("thought", "tool_call", "tool_result")
    ]
    already_shown = cve_id in shown_traces
    expander_label = (
        f"🔍 Agent trace — {cve_id} ({len(cve_trace)} steps)"
        if not already_shown
        else f"🔍 Trace for {cve_id} (see first occurrence above)"
    )
    with st.expander(expander_label, expanded=False):
        if already_shown:
            st.caption("The agent trace for this CVE was shown in the expander above.")
        else:
            for entry in cve_trace:
                _render_trace_entry(entry)

    if cve_id not in shown_traces:
        shown_traces.add(cve_id)

    st.divider()
