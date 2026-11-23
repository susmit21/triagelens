"""TriageLens web UI — read-only brief viewer with integrated run trigger.

Run: streamlit run app/app.py
"""
from __future__ import annotations

import json
import pathlib
import queue
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

import streamlit as st

ROOT            = pathlib.Path(__file__).resolve().parent.parent
RUNS_DIR        = ROOT / "runs"
ANSWER_KEY_PATH = ROOT / "data" / "answer_key.json"

st.set_page_config(
    page_title="TriageLens",
    page_icon="🔍",
    layout="wide",
)


# ── CVE list from answer key ──────────────────────────────────────────────────

def _load_cve_ids() -> list[str]:
    try:
        key = json.loads(ANSWER_KEY_PATH.read_text())
        return list(dict.fromkeys(
            e["cve_id"] for e in key.get("entries", []) if e.get("cve_id")
        ))
    except Exception:
        return []

_KNOWN_CVES = _load_cve_ids()


# ── Load available runs ───────────────────────────────────────────────────────

def _load_run_dirs() -> list[pathlib.Path]:
    if not RUNS_DIR.exists():
        return []
    return sorted(
        [d for d in RUNS_DIR.iterdir()
         if d.is_dir() and (d / "brief.json").exists()],
        reverse=True,
    )

run_dirs = _load_run_dirs()


# ── Run-name formatter ────────────────────────────────────────────────────────

def _fmt_run_name(name: str) -> str:
    """'20261122T212326Z' → 'Nov 22, 1:23 PM' in local time. Falls back to raw name."""
    try:
        dt = datetime.strptime(name, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
        local = dt.astimezone()
        # %-d / %-I strips leading zeros on macOS/Linux
        return local.strftime("%b %-d, %-I:%M %p")
    except ValueError:
        return name


# ── Sidebar ───────────────────────────────────────────────────────────────────

brief:        dict | None           = None
findings:     list[dict]            = []
selected_run: pathlib.Path | None   = None
selected_name: str | None           = None

with st.sidebar:
    st.title("🔍 TriageLens")
    st.caption("CVE triage agent")

    # ── Run-triage controls (always visible) ──────────────────────────────────
    st.markdown("**Run triage**")

    cve_options = ["All CVEs"] + _KNOWN_CVES
    selected_cve = st.selectbox("CVEs to run", cve_options, index=0)

    _running = st.session_state.get("triage_running", False)
    run_clicked = st.button(
        "Run triage now",
        disabled=_running,
        use_container_width=True,
        type="primary",
    )
    st.caption("Calls Claude; about $0.67 and 2 minutes for all CVEs.")

    st.divider()

    # ── Run picker (only when completed runs exist) ───────────────────────────
    if run_dirs:
        selected_name = st.selectbox(
            "Run",
            [d.name for d in run_dirs],
            index=0,
            format_func=_fmt_run_name,
            label_visibility="collapsed",
        )
        selected_run = RUNS_DIR / selected_name

        try:
            brief = json.loads((selected_run / "brief.json").read_text())
        except Exception as exc:
            st.error(f"Could not read brief.json: {exc}")
            st.stop()

        findings = brief.get("findings", [])
        usage    = brief.get("usage", {})
        total_u  = usage.get("total", {})
        model    = brief.get("model", "—")

        st.divider()
        st.markdown("**Run summary**")
        c1, c2 = st.columns(2)
        c1.metric("CVEs",        len(brief.get("cves_analyzed", [])))
        present_findings  = sum(1 for f in findings if f.get("priority") != "not-present")
        not_pres_findings = sum(1 for f in findings if f.get("priority") == "not-present")
        c2.metric("Findings",    present_findings)
        c1.metric("Not-present", not_pres_findings)
        c1.metric("In tokens",  f"{total_u.get('input_tokens', 0):,}")
        c2.metric("Out tokens", f"{total_u.get('output_tokens', 0):,}")
        st.metric("Wall-clock", f"{total_u.get('seconds', 0):.1f} s")
        st.markdown(f"**Model:** `{model}`")
        st.markdown(f"**Generated:** {brief.get('generated_at', '—')[:19]}")


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
        return _badge(f"KEV {d}".strip(), "#8e44ad")
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


# ── Card helpers ─────────────────────────────────────────────────────────────

_CVSS_RE = re.compile(r"\bCVSS\s+(\d+(?:\.\d+)?)\b")


def _cvss_score(f: dict) -> str:
    """Extract CVSS score from the cvss_vector reason claim, e.g. '10.0'."""
    for r in f.get("reasons", []):
        if isinstance(r, dict) and "cvss_vector" in r.get("source", ""):
            m = _CVSS_RE.search(r.get("claim", ""))
            if m:
                return m.group(1)
    return "—"


def _reach_str(f: dict) -> str:
    """One-line reachability summary, e.g. 'internet, 2 hops'."""
    if f.get("priority") == "not-present":
        return "not present"
    if f.get("reachable_from_internet"):
        h = f.get("min_hops_internet") or "?"
        return f"internet, {h} {'hop' if h == 1 else 'hops'}"
    if f.get("reachable_from_office"):
        h = f.get("min_hops_office") or "?"
        return f"office only, {h} {'hop' if h == 1 else 'hops'}"
    return "not reachable"


def _render_card(f: dict, trace_entries: list[dict], shown_traces: set) -> None:
    """Render one finding as a bordered card in the current column."""
    priority   = f.get("priority", "low")
    cve_id     = f.get("cve_id") or "—"
    asset_id   = f.get("asset_id") or "—"
    asset_name = f.get("asset_name") or asset_id

    with st.container(border=True):
        if priority == "not-present":
            st.markdown(f"**{cve_id}**")
            st.caption("Not present in this environment")
            return

        # Title
        st.markdown(f"**{cve_id}** · {asset_name}")

        # Badge row
        badges = [_priority_badge(priority), _kev_badge(f)]
        if f.get("needs_human_review"):
            badges.append(_badge("👁 Review", "#e74c3c"))
        st.markdown(" &nbsp; ".join(badges), unsafe_allow_html=True)

        # One-liners
        st.caption(f"CVSS {_cvss_score(f)} · {_reach_str(f)}")
        st.caption(f"Fix: {f.get('mitigation', '—')}")

        # Details expander — everything else
        with st.expander("Details"):
            path = f.get("reachability_summary") or "—"
            st.markdown(f"**Path:** `{path}`")

            mit_d = f.get("mitigation_detail", "")
            if mit_d:
                st.markdown(f"**Detail:** {mit_d}")

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

            citations = f.get("advisory_citations") or []
            if citations:
                st.markdown("**Advisory sources:**")
                for c in citations:
                    url    = c.get("url", "")
                    domain = c.get("domain", url)
                    label  = c.get("label", "other")
                    text   = c.get("text", "")[:200]
                    st.markdown(f"- [{domain}]({url}) `{label}` — {text}")

            nhr = f.get("needs_human_review", False)
            rr  = f.get("review_reasons") or []
            if nhr and rr:
                st.markdown("**Review notes:**")
                for note in rr:
                    st.markdown(f"- {note}")

            # Agent trace (deduplicated per CVE)
            cve_trace = [
                e for e in trace_entries
                if e.get("cve_id") == cve_id
                and e.get("type") in ("thought", "tool_call", "tool_result")
            ]
            already_shown = cve_id in shown_traces
            trace_label = (
                f"🔍 Agent trace — {cve_id} ({len(cve_trace)} steps)"
                if not already_shown
                else f"🔍 Trace for {cve_id} (see another card above)"
            )
            with st.expander(trace_label):
                if already_shown:
                    st.caption("Trace already shown in a card above for this CVE.")
                else:
                    for entry in cve_trace:
                        _render_trace_entry(entry)

            if cve_id not in shown_traces:
                shown_traces.add(cve_id)


# ── Subprocess runner ─────────────────────────────────────────────────────────

def _stream_subprocess(cmd: list[str], timeout_s: int = 300) -> tuple[list[str], int]:
    """Run cmd from ROOT, stream stdout+stderr into the current st context.

    Returns (all_output_lines, exit_code). exit_code -1 means timeout.
    """
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=str(ROOT),
        bufsize=1,
    )

    q: queue.Queue[str | None] = queue.Queue()

    def _reader() -> None:
        for line in iter(proc.stdout.readline, ""):
            q.put(line)
        q.put(None)  # sentinel

    threading.Thread(target=_reader, daemon=True).start()

    output_lines: list[str] = []
    deadline = time.monotonic() + timeout_s
    out_area = st.empty()

    while True:
        try:
            line = q.get(timeout=0.5)
            if line is None:
                break
            output_lines.append(line.rstrip())
            out_area.code("\n".join(output_lines[-50:]))
        except queue.Empty:
            if time.monotonic() > deadline:
                proc.kill()
                return output_lines, -1

    proc.wait(timeout=10)
    return output_lines, proc.returncode


# ── Handle "Run triage now" ───────────────────────────────────────────────────

if run_clicked:
    st.session_state.triage_running = True

    cli_cmd = (
        [sys.executable, "-m", "triage.cli", "--all"]
        if selected_cve == "All CVEs"
        else [sys.executable, "-m", "triage.cli", "--cve", selected_cve]
    )

    output_lines: list[str] = []
    exit_code = 0

    try:
        with st.status("Running agent…", expanded=True) as agent_status:
            st.caption(f"`{' '.join(cli_cmd)}`")
            output_lines, exit_code = _stream_subprocess(cli_cmd, timeout_s=300)
            if exit_code == -1:
                agent_status.update(label="Timed out after 5 minutes", state="error")
            elif exit_code != 0:
                agent_status.update(label=f"Agent failed (exit {exit_code})", state="error")
            else:
                agent_status.update(label="Agent finished ✓", state="complete")
    except Exception as exc:
        st.session_state.triage_running = False
        st.error(f"Unexpected error launching agent: {exc}")
        st.stop()

    if exit_code == -1:
        st.session_state.triage_running = False
        st.error(
            "Triage timed out after 5 minutes.\n\n"
            "**Last output:**\n```\n" + "\n".join(output_lines[-20:]) + "\n```"
        )
        st.stop()

    if exit_code != 0:
        st.session_state.triage_running = False
        st.error(
            f"Triage failed (exit {exit_code}).\n\n"
            "**Last output:**\n```\n" + "\n".join(output_lines[-20:]) + "\n```"
        )
        st.stop()

    # Successful run — also evaluate for --all
    if selected_cve == "All CVEs":
        eval_cmd = [sys.executable, str(ROOT / "eval" / "evaluate.py")]
        with st.status("Running evaluation…", expanded=False) as eval_status:
            try:
                eval_result = subprocess.run(
                    eval_cmd,
                    capture_output=True,
                    text=True,
                    cwd=str(ROOT),
                    timeout=60,
                )
                if eval_result.returncode == 0:
                    eval_status.update(label="Evaluation complete ✓", state="complete")
                else:
                    eval_status.update(label="Evaluation had errors", state="error")
                    st.warning(
                        "Eval stderr:\n```\n" + eval_result.stderr[-500:] + "\n```"
                    )
            except subprocess.TimeoutExpired:
                eval_status.update(label="Evaluation timed out", state="error")

    st.session_state.triage_running = False
    st.rerun()


# ── Main area ─────────────────────────────────────────────────────────────────

if brief is None:
    st.title("TriageLens")
    st.info(
        "No completed runs found in `runs/`.  "
        "Select CVEs in the sidebar and click **Run triage now** to start."
    )
    st.stop()

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

# Load trace
trace_entries: list[dict] = []
trace_path = selected_run / "trace.jsonl"
if trace_path.exists():
    for _line in trace_path.read_text().splitlines():
        _line = _line.strip()
        if _line:
            try:
                trace_entries.append(json.loads(_line))
            except json.JSONDecodeError:
                pass

shown_traces: set[str | None] = set()

for _row_start in range(0, len(findings), 3):
    _row = findings[_row_start:_row_start + 3]
    for _col, _f in zip(st.columns(3), _row):
        with _col:
            _render_card(_f, trace_entries, shown_traces)
