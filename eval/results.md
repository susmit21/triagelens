# TriageLens Evaluation Results

Run: /Users/susmitmogarkar/Projects/triagelens/runs/20261122T000213Z
Model: claude-sonnet-5-5
Evaluated: 2026-11-22T00:30:13Z
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
| Groundedness | 32/32 (100.0%) | — |
| Not-present (CVE-2023-4966) | pass | pass |
| Decoy clean (ftp-server-01) | pass | pass |
| Needs human review | 3/7 (42.9%) | — |
| Always-review findings | 1 | — |

## Token / Time (Agent)

| CVE | Input tokens | Output tokens | Seconds |
|-----|-------------|--------------|---------|
| CVE-2024-23897 | 23,932 | 1,894 | 17.8 |
| CVE-2021-44228 | 25,172 | 2,123 | 19.1 |
| CVE-2023-44487 | 41,581 | 2,580 | 24.1 |
| CVE-2024-6387 | 23,063 | 1,720 | 15.5 |
| CVE-2024-10979 | 24,279 | 1,996 | 17.9 |
| CVE-2023-4966 | 13,866 | 679 | 7.5 |
| **Total** | **151,893** | **10,992** | **101.9** |
