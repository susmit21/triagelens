# TriageLens Evaluation Results

Run: /Users/susmitmogarkar/Projects/triagelens/runs/20261122T012358Z
Model: claude-sonnet-5-5
Evaluated: 2026-11-22T01:25:46Z
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
| Groundedness | 33/33 (100.0%) | — |
| Not-present (CVE-2023-4966) | pass | pass |
| Decoy clean (ftp-server-01) | pass | pass |
| Needs human review | 1/6 (16.7%) | — |
| Always-review findings | 1 | — |
| Mitigation detail sourced | 6/6 (100.0%) | — |


## Token / Time (Agent)

| CVE | Input tokens | Output tokens | Seconds |
|-----|-------------|--------------|---------|
| CVE-2024-23897 | 25,893 | 1,468 | 14.8 |
| CVE-2021-44228 | 27,334 | 1,900 | 17.1 |
| CVE-2023-44487 | 45,195 | 2,533 | 23.2 |
| CVE-2024-6387 | 25,162 | 1,554 | 12.5 |
| CVE-2024-10979 | 26,320 | 1,609 | 15.5 |
| CVE-2023-4966 | 15,420 | 710 | 8.2 |
| **Total** | **165,324** | **9,774** | **91.2** |
