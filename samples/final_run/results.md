# TriageLens Evaluation Results

Run: /Users/susmitmogarkar/Projects/triagelens/runs/20261122T213854Z
Model: claude-sonnet-5-5
Evaluated: 2026-11-22T21:40:43Z
Answer key: 8 entries (6 scored, 1 not-present, 1 decoy)

---

## Priority (per finding)

| CVE | Asset | Expected | Agent | ✓ | Rules | ✓ |
|-----|-------|----------|-------|---|-------|---|
| CVE-2024-23897 | jenkins-01 | high | high | ✓ | high | ✓ |
| CVE-2021-44228 | app-server-01 | critical | critical | ✓ | critical | ✓ |
| CVE-2023-44487 | nginx-lb-01 | high | high | ✓ | high | ✓ |
| CVE-2023-44487 | jenkins-01 | low/medium | medium | ✓ | medium | ✓ |
| CVE-2024-6387 | admin-host-01 | high | high | ✓ | high | ✓ |
| CVE-2024-10979 | postgres-db-01 | medium | medium | ✓ | medium | ✓ |

## Exposure (agent only)

| Asset | Exp internet | Exp office | Exp hops | Agent int hops | Agent off hops | ✓ |
|-------|-------------|-----------|---------|---------------|--------------|---|
| jenkins-01 | no | yes | o:2 | — | 2 | ✓ |
| app-server-01 | yes | yes | i:2 | 2 | 2 | ✓ |
| nginx-lb-01 | yes | yes | i:1 | 1 | 1 | ✓ |
| jenkins-01 | no | yes | o:2 | — | 2 | ✓ |
| admin-host-01 | no | yes | o:1 | — | 1 | ✓ |
| postgres-db-01 | yes | yes | i:3 | 3 | 3 | ✓ |

## Summary Metrics

| Metric | Agent | Rules |
|--------|-------|-------|
| Priority accuracy | 6/6 (100.0%) | 6/6 (100.0%) |
| Missed critical/high | 0 | 0 |
| Exposure accuracy | 6/6 (100.0%) | — |
| Groundedness | 36/36 (100.0%) | — |
| Not-present (CVE-2023-4966) | pass | pass |
| Decoy clean (ftp-server-01) | pass | pass |
| Needs human review | 3/6 (50.0%) | — |
| Always-review findings | 1 | — |
| Mitigation detail sourced | 6/6 (100.0%) | — |
| Fix from advisory | 4/5 (80.0%) | — |
| Version verified in advisory | 4/5 (80.0%) | — |


## Token / Time (Agent)

| CVE | Input tokens | Output tokens | Seconds |
|-----|-------------|--------------|---------|
| CVE-2024-23897 | 47,627 | 1,938 | 18.3 |
| CVE-2021-44228 | 47,826 | 2,397 | 19.7 |
| CVE-2023-44487 | 65,394 | 3,574 | 24.4 |
| CVE-2024-6387 | 44,190 | 2,260 | 20.4 |
| CVE-2024-10979 | 46,458 | 1,901 | 17.0 |
| CVE-2023-4966 | 18,573 | 773 | 8.9 |
| **Total** | **270,068** | **12,843** | **108.7** |
