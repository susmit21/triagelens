# TriageLens Brief
Generated: 2026-11-22T21:40:43Z
CVEs analyzed: CVE-2024-23897, CVE-2021-44228, CVE-2023-44487, CVE-2024-6387, CVE-2024-10979, CVE-2023-4966

---

## Critical

### CVE-2021-44228 — app-server-01

**Priority:** critical | **Always review:** yes (always escalate) | **KEV:** yes (added 2021-12-10) | **EPSS:** 0.99999 (100.0th pct)

**Path:** internet → nginx-lb-01:443 (WAF) → app-server-01:8080 (IPS) (2 hops, WAF+IPS); office → nginx-lb-01:443 → app-server-01:8080 (2 hops)
**Mitigation:** patch
**Detail:** Upgrade log4j-core on app-server-01 from 2.14.1 to 2.16.0 if it runs Java 8 or later (2.12.3 for Java 7, 2.3.1 for Java 6), per the Apache Logging Services advisory at https://logging.apache.org/log4j/2.x/security.html. The matched_range from find_affected_assets is >=2.13.0, <2.15.0.

**Evidence:**
- CVSS 10.0, network-exploitable with no privileges or user interaction (AV:N/AC:L/PR:N/UI:N)  *(source: get_cve_details.cvss_vector)*
- CVE is KEV-listed (added 2021-12-10) with EPSS 0.99999, so it is actively exploited in the wild  *(source: get_cve_details.in_kev / epss)*
- app-server-01 runs log4j-core 2.14.1, which falls in the vulnerable range >=2.13.0, <2.15.0  *(source: find_affected_assets)*
- Asset is reachable from the internet and the office in 2 hops via nginx-lb-01:443 and app-server-01:8080, crossing ctrl-waf and ctrl-ips  *(source: check_reachability)*
- Asset criticality is critical and it holds customer-pii, session-data and order-data. Computed priority is critical and always_review=true.  *(source: rank_finding)*
- The Apache advisory lists fixed releases 2.3.1 (Java 6), 2.12.3 (Java 7) and 2.16.0 (Java 8 and later)  *(source: search_advisories chunk CVE-2021-44228_0_71)*

**Needs human review:** yes
- rank_finding returned always_review=true.
- The find_affected_assets matched_range (<2.15.0) implies a fix at 2.15.0. The vendor advisory (chunk CVE-2021-44228_0_71) names 2.16.0, 2.12.3 and 2.3.1 as the fixed releases, and the CVE description says 2.15.0 is also affected. Please confirm the target version for the Java runtime in use.

---

## High

### CVE-2024-23897 — jenkins-01

**Priority:** high | **Always review:** no | **KEV:** yes (added 2024-08-19) | **EPSS:** 0.99999 (100.0th pct)

**Path:** office → admin-host-01:22 → jenkins-01:8080 (2 hops, IPS detect-only); not reachable from internet
**Mitigation:** patch
**Detail:** Upgrade Jenkins to >= 2.426.3 (source: find_affected_assets matched_range); the vendor advisory lists LTS 2.426.3 or 2.440.1 as fixed, and disabling CLI access is the interim workaround (https://www.jenkins.io/security/advisory/2024-01-24/#SECURITY-3314).

**Evidence:**
- CVSS 9.8 critical, network-exploitable, no auth or user interaction required (AV:N/AC:L/PR:N/UI:N)  *(source: get_cve_details.cvss_vector)*
- Listed in CISA KEV (added 2024-08-19) with EPSS 0.99999, so it is actively exploited  *(source: get_cve_details.in_kev / get_cve_details.epss)*
- jenkins-01 runs Jenkins 2.426.1, which matches the vulnerable range <2.426.3  *(source: find_affected_assets.matched_range)*
- Not reachable from the internet. Reachable from the office network in 2 hops via admin-host-01:22 then jenkins-01:8080, with only ctrl-ips on the path  *(source: check_reachability)*
- Office-only exposure, but the asset holds sensitive data (deployment-credentials, aws-access-keys, build-secrets, source-code), which gives a high priority  *(source: rank_finding)*
- Vendor advisory states the fix is Jenkins LTS 2.426.3 or 2.440.1, and that disabling CLI access prevents exploitation  *(source: search_advisories (CVE-2024-23897_0_35, CVE-2024-23897_0_13))*

**Needs human review:** no

---

### CVE-2023-44487 — nginx-lb-01

**Priority:** high | **Always review:** no | **KEV:** yes (added 2023-10-10) | **EPSS:** 0.99999 (100.0th pct)

**Path:** internet → nginx-lb-01:443 (1 hop, WAF); office → nginx-lb-01:443 (1 hop, WAF)
**Mitigation:** workaround
**Detail:** Fixed version not stated in the available data (matched_range ends at the inclusive bound <=1.25.2); as a workaround, use the nginx "limit_req" directive to rate-limit and reject excessive requests (source: https://mailman.nginx.org/pipermail/nginx-devel/2023-October/S36Q5HBXR7CAIMPLLPRSSSYR4PCMWILK.html), and confirm the fixed release in the vendor advisory at https://lists.apache.org/thread/5py8h42mxfsn8l1wy6o41xwhsjlsd87q.

**Evidence:**
- CVSS 7.5, network-exploitable with no authentication, availability-only impact (A:H)  *(source: get_cve_details.cvss_vector)*
- Listed in KEV (added 2023-10-10) with EPSS 0.99999, so exploited in the wild  *(source: get_cve_details.in_kev / epss)*
- nginx 1.24.0 falls in the vulnerable range >=1.9.5, <=1.25.2  *(source: find_affected_assets.matched_range)*
- Reachable directly from the internet on port 443 in 1 hop, crossing only a WAF control  *(source: check_reachability)*
- Priority is high: internet-reachable and unauthenticated, lowered one level because impact is DoS-only; asset criticality is high  *(source: rank_finding)*
- The nginx maintainer states nginx is not considered affected in its default configuration, and recommends the limit_req directive as additional protection. This conflicts with the matched vulnerable range.  *(source: search_advisories CVE-2023-44487_1_2)*

**Needs human review:** yes
- Conflicting evidence: find_affected_assets matches nginx 1.24.0 to the vulnerable range, but the nginx vendor advisory chunk (CVE-2023-44487_1_2) says nginx is not considered affected in its default configuration.
- No fixed nginx version is stated in the tool results, so the exact remediation version needs confirming.

---

### CVE-2024-6387 — admin-host-01

**Priority:** high | **Always review:** no | **KEV:** no | **EPSS:** 0.99506 (99.9th pct)

**Path:** office-network → admin-host-01:22 (1 hop, no controls); not reachable from internet
**Mitigation:** patch
**Detail:** Upgrade OpenSSH on admin-host-01 to the 9.8 release or a later one, which the vendor advisory at https://www.openssh.com/txt/release-9.8 says fixes this race condition, or install the distro's patched openssh package (e.g. RHSA-2024:4340).

**Evidence:**
- admin-host-01 runs openssh-server 9.3p1, within the vulnerable range >=8.6, <=9.8  *(source: find_affected_assets)*
- CVSS 8.1 (AV:N/AC:H/PR:N/UI:N), unauthenticated remote race condition in sshd; not in KEV  *(source: get_cve_details.cvss_vector)*
- EPSS 0.995 (99.9th percentile), very high exploitation probability  *(source: get_cve_details.epss)*
- Not reachable from internet; reachable from office network on port 22 in 1 hop with no controls crossed  *(source: check_reachability)*
- Office-only exposure but asset holds sensitive data (ssh-private-keys, admin-audit-logs), criticality high, giving high priority  *(source: rank_finding)*
- Vendor advisory says Portable OpenSSH 8.5p1 through 9.7p1 is affected and that the 9.8 release contains the fix  *(source: search_advisories (CVE-2024-6387_0_0, CVE-2024-6387_0_1))*

**Needs human review:** yes
- The matched_range from find_affected_assets (>=8.6, <=9.8) includes 9.8 as vulnerable, but the vendor advisory says 9.8 contains the fix and that 8.5p1–9.7p1 is affected. The two sources conflict on the fixed boundary.
- The installed version 9.3p1 may be a distro-backported build, so confirm the exact patched package version for this OS before closing the finding.

---

## Medium

### CVE-2023-44487 — jenkins-01

**Priority:** medium | **Always review:** no | **KEV:** yes (added 2023-10-10) | **EPSS:** 0.99999 (100.0th pct)

**Path:** office → admin-host-01:22 → jenkins-01:8080 (2 hops, IPS); not reachable from internet
**Mitigation:** patch
**Detail:** Fixed version not stated in the available data (matched_range ends at the inclusive bound <=2.427); confirm the fixed Jenkins release in the vendor advisory at https://lists.apache.org/thread/5py8h42mxfsn8l1wy6o41xwhsjlsd87q.

**Evidence:**
- CVSS 7.5, network-exploitable with no authentication, availability-only impact (A:H)  *(source: get_cve_details.cvss_vector)*
- Listed in KEV (added 2023-10-10) with EPSS 0.99999  *(source: get_cve_details.in_kev / epss)*
- Jenkins 2.426.1 falls in the vulnerable range <=2.427  *(source: find_affected_assets.matched_range)*
- Not reachable from the internet. Reachable from the office only through admin-host-01 (2 hops), crossing an IPS control.  *(source: check_reachability)*
- Priority is medium: office-only exposure and DoS-only impact; asset criticality is high  *(source: rank_finding)*

**Needs human review:** no

---

### CVE-2024-10979 — postgres-db-01

**Priority:** medium | **Always review:** no | **KEV:** no | **EPSS:** 0.04393 (91.5th pct)

**Path:** internet → nginx-lb-01:443 (WAF) → app-server-01:8080 (IPS) → postgres-db-01:5432 (3 hops, WAF+IPS); office follows the same path
**Mitigation:** patch
**Detail:** Upgrade PostgreSQL to >= 14.14 (source: find_affected_assets matched_range <14.14; confirmed by the vendor advisory at https://www.postgresql.org/support/security/CVE-2024-10979/). No configuration workaround appeared in the advisory search results.

**Evidence:**
- CVSS 8.8 (AV:N/AC:L/PR:L): network exploitable but requires a low-privileged authenticated database user; PL/Perl env variable change can lead to arbitrary code execution  *(source: get_cve_details.cvss_vector)*
- Not in KEV; EPSS 0.0439 (91.5th percentile)  *(source: get_cve_details)*
- postgres-db-01 runs PostgreSQL 14.9, within vulnerable range >=14.0, <14.14  *(source: find_affected_assets.matched_range)*
- Reachable from internet and office via 3 hops, with WAF and IPS controls crossed; the database port is reached only from app-server-01  *(source: check_reachability)*
- Computed priority is medium: PR:LOW and chained access (3 hops) lowered it from high. The asset is critical and holds customer PII, order history, payment metadata and hashed credentials.  *(source: rank_finding)*
- Vendor advisory lists 14.14 as the fixed version for the 14 branch  *(source: search_advisories (CVE-2024-10979_0_1))*

**Needs human review:** no

---

## Not Present in Environment

### CVE-2023-4966 — —

**Priority:** not-present | **Always review:** no | **KEV:** no | **EPSS:** —

**Path:** not present in this environment
**Mitigation:** monitor_only
**Detail:** No action required; CVE does not affect this environment.

**Evidence:**
- No matching software found in environment  *(source: find_affected_assets)*

**Needs human review:** no

---

## Token / Time Usage

| CVE | Input tokens | Output tokens | Seconds |
|-----|-------------|--------------|---------|
| CVE-2024-23897 | 47,627 | 1,938 | 18.3 |
| CVE-2021-44228 | 47,826 | 2,397 | 19.7 |
| CVE-2023-44487 | 65,394 | 3,574 | 24.4 |
| CVE-2024-6387 | 44,190 | 2,260 | 20.4 |
| CVE-2024-10979 | 46,458 | 1,901 | 17.0 |
| CVE-2023-4966 | 18,573 | 773 | 8.9 |
| **Total** | **270,068** | **12,843** | **108.7** |
