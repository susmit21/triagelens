# TriageLens

TriageLens is a single-agent CVE triage system that checks new vulnerabilities
against a synthetic company cloud network and ranks them by real exposure.
Given a CVE ID it walks the security-group graph to find whether an attacker
can reach each affected asset, then scores severity × reachability and writes a
human-readable brief with per-finding mitigations drawn from vendor advisories
(RAG over ChromaDB).  A human analyst must approve each critical or conflicting
finding before action is taken.  Built as a CMU Agentic AI capstone project.

## Architecture

```
CVE ID ──► Coordinator (ReAct loop, max 16 tool calls)
                │
                ├─ get_cve_details       NVD snapshot → CVSS, KEV, EPSS, refs
                ├─ find_affected_assets  CPE match across synthetic inventory
                ├─ check_reachability    Graph walk over security groups → hop path
                ├─ rank_finding          Priority rules (severity × exposure)
                ├─ search_advisories     Chroma vector store + keyword fallback
                └─ submit_finding        Validate cited chunks, persist finding
                │
                ▼
           brief.md / brief.json  (Streamlit reads brief.json)
```

Controls marked `detect-only` (IPS in detect mode) are treated as no barrier;
only block-mode controls count.  Reachability never uses `public_ip`; it always
walks the graph.  Every claim in the brief carries a `*(source: …)*` tag.

## Setup

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Auth — either:
ant auth login          # Anthropic CLI SSO
# or add ANTHROPIC_API_KEY=sk-ant-... to a .env file (never commit it)

# Optional: override model
echo "ANTHROPIC_MODEL=claude-sonnet-4-6" >> .env
```

## Usage (run in this order)

**1. Fetch NVD snapshots** (already in `data/snapshots/`; re-run to refresh):
```bash
python scripts/fetch_snapshots.py
```

**2. Fetch vendor advisory pages** (requires network; skips already-fetched):
```bash
python scripts/fetch_advisories.py
```

**3. Build the advisory vector index**:
```bash
python scripts/build_index.py
```

**4. Run triage** (single CVE or all):
```bash
python -m triage.cli --cve CVE-2024-23897
python -m triage.cli --all                 # writes runs/<timestamp>/
```

**5. Evaluate against answer key**:
```bash
python eval/evaluate.py runs/<timestamp>/
```

**6. Browse results in the UI**:
```bash
streamlit run app/app.py
# point it at the run directory in the sidebar
```

## Results (sample run 2026-11-22)

| Metric | Agent | Rules baseline |
|--------|-------|---------------|
| Priority accuracy | 6/6 (100%) | 6/6 (100%) |
| Missed critical/high | 0 | 0 |
| Exposure accuracy | 6/6 (100%) | — |
| Groundedness | 36/36 (100%) | — |
| Not-present (CVE-2023-4966) | pass | pass |
| Decoy clean (ftp-server-01) | pass | pass |
| Fix from advisory | 4/5 (80%) | — |
| Version verified in advisory | 4/5 (80%) | — |
| Needs human review | 3/6 (50%) | — |
| Total tokens | 270,068 in / 12,843 out | — |
| Total time | 108.7 s (6 CVEs) | — |

Full brief: [`samples/final_run/brief.md`](samples/final_run/brief.md)

## Limitations

- **Six hand-picked CVEs** — the answer key was written for the same set used in
  evaluation, so this is not a held-out test; accuracy numbers are optimistic.
- **Rules baseline not held out** — ranking rules were tuned on the same CVEs.
- **No route tables** — reachability walks security groups only; VPC route tables
  and NACLs are not modelled.
- **JavaScript-rendered pages** — F5 and Citrix advisory pages require a browser;
  `fetch_advisories.py` falls back to keyword search for those CVEs.
- **Some advisory slots are NVD reference links** — a few fetched pages are the
  NVD entry itself rather than a primary vendor advisory.

## Next steps

- **Five-agent split** — Threat Researcher, Exposure Analyst, Mitigation Planner
  (Tree-of-Thought, beam 3 × depth 3), Critic, Coordinator as separate agents.
- **Discover mode** — scan the full inventory for affected assets without being
  given a CVE list.
- **Held-out CVE evaluation** — answer key built before triage runs to get
  unbiased accuracy numbers.
- **Prompt caching** — the system prompt and inventory data are identical across
  CVEs; caching would cut ~40 k tokens per run.
- **Route-table modelling** — add VPC route tables and NACLs to the reachability
  graph for a more accurate hop count.
