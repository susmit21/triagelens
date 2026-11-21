"""Rank a (CVE, asset) pair by real exposure using plain rules — no LLM.

Priority ladder (highest → lowest): critical > high > medium > low.

Rules applied in order
──────────────────────
1. Exposure base
   • internet + network + unauth (PR:N)       → critical
   • internet + other                          → high
   • office-only + DoS-only (C:N and I:N)     → medium
   • office-only + data/code impact            → high  (or medium if no sensitive data)

2. DoS penalty (applied only to internet-base priority)
   • C:N and I:N (availability-only)           → lower by one level

3. Auth-chain penalty
   • PR != NONE  AND  min_hop_count > 1        → lower by one level
   (models "exploit requires authentication at target, reached only via other assets")

4. KEV and EPSS are reported as reasons but do not change the computed priority.
   (They inform human review, not the automated ranking.)
"""
from __future__ import annotations

from dataclasses import dataclass, field

from triage.tools.environment import Asset, CveSnapshot, Environment
from triage.tools.environment import load_cve_snapshot, load_environment
from triage.tools.reachability import ReachabilityResult

PRIORITY_ORDER = ["critical", "high", "medium", "low"]

# Data categories that constitute "sensitive" for the office-reachability exception.
SENSITIVE_DATA = frozenset({
    "customer-pii", "aws-access-keys", "deployment-credentials",
    "ssh-private-keys", "build-secrets", "hashed-credentials",
    "payment-metadata", "session-tokens", "source-code",
})


@dataclass
class CvssData:
    attack_vector:          str   # NETWORK | ADJACENT | LOCAL | PHYSICAL
    privileges_required:    str   # NONE | LOW | HIGH
    confidentiality_impact: str   # NONE | LOW | HIGH
    integrity_impact:       str   # NONE | LOW | HIGH
    availability_impact:    str   # NONE | LOW | HIGH
    base_score:             float
    vector_string:          str = ""


@dataclass
class RankResult:
    priority: str             # critical | high | medium | low
    reasons: list[str] = field(default_factory=list)


def _lower(p: str) -> str:
    idx = PRIORITY_ORDER.index(p)
    return PRIORITY_ORDER[min(idx + 1, len(PRIORITY_ORDER) - 1)]


def _extract_cvss(nvd: dict) -> CvssData | None:
    vulns = (nvd.get("vulnerabilities") or [])
    if not vulns:
        return None
    metrics = vulns[0].get("cve", {}).get("metrics", {})
    # Prefer most recent CVSS version
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            cd = entries[0].get("cvssData", {})
            if not cd:
                continue
            # CVSSv2 uses different field names
            if key == "cvssMetricV2":
                return CvssData(
                    attack_vector=cd.get("accessVector", "NETWORK"),
                    privileges_required=cd.get("authentication", "NONE"),
                    confidentiality_impact=cd.get("confidentialityImpact", "NONE"),
                    integrity_impact=cd.get("integrityImpact", "NONE"),
                    availability_impact=cd.get("availabilityImpact", "NONE"),
                    base_score=cd.get("baseScore", 0.0),
                    vector_string=cd.get("vectorString", ""),
                )
            return CvssData(
                attack_vector=cd.get("attackVector", "NETWORK"),
                privileges_required=cd.get("privilegesRequired", "NONE"),
                confidentiality_impact=cd.get("confidentialityImpact", "NONE"),
                integrity_impact=cd.get("integrityImpact", "NONE"),
                availability_impact=cd.get("availabilityImpact", "NONE"),
                base_score=cd.get("baseScore", 0.0),
                vector_string=cd.get("vectorString", ""),
            )
    return None


def _min_hop_count(r: ReachabilityResult) -> int:
    all_paths = r.internet_paths + r.office_paths
    return min((p.hop_count for p in all_paths), default=0)


def _holds_sensitive(asset: Asset) -> bool:
    return bool(SENSITIVE_DATA & set(asset.data_held))


def rank(
    cve_id: str,
    asset_id: str,
    reachability: ReachabilityResult,
    env: Environment | None = None,
    snapshot: CveSnapshot | None = None,
) -> RankResult:
    """Apply the priority rules and return a RankResult with plain-English reasons."""
    if env is None:
        env = load_environment()
    if snapshot is None:
        snapshot = load_cve_snapshot(cve_id)

    asset = env.assets_by_id[asset_id]
    cvss  = _extract_cvss(snapshot.nvd)

    if cvss is None:
        return RankResult(priority="medium", reasons=["No CVSS data available; defaulting to medium"])

    internet = reachability.reachable_from_internet
    office   = reachability.reachable_from_office

    if not internet and not office:
        return RankResult(priority="medium",
                          reasons=["Asset is not reachable from any tested source"])

    is_unauth    = cvss.privileges_required == "NONE"
    is_network   = cvss.attack_vector == "NETWORK"
    is_dos_only  = (cvss.confidentiality_impact == "NONE"
                    and cvss.integrity_impact == "NONE")
    has_data_code = (cvss.confidentiality_impact != "NONE"
                     or cvss.integrity_impact != "NONE")
    sensitive    = _holds_sensitive(asset)

    reasons: list[str] = []
    reasons.append(f"CVSS {cvss.base_score} ({cvss.vector_string})")

    # ── Rule 1: Exposure base ─────────────────────────────────────────────────
    if internet:
        if is_unauth and is_network:
            priority = "critical"
            reasons.append("Internet-reachable, unauthenticated network attack → critical base")
        else:
            priority = "high"
            reasons.append("Internet-reachable (requires auth or non-network AV) → high base")

        # Rule 2: DoS penalty on internet base
        if is_dos_only:
            priority = _lower(priority)
            reasons.append(f"DoS-only impact (C:N, I:N) → lower one level to {priority}")

    else:   # office-only
        if is_dos_only:
            priority = "medium"
            reasons.append("Office-only + DoS-only → medium base")
        elif sensitive:
            priority = "high"
            reasons.append(
                f"Office-only but asset holds sensitive data "
                f"({', '.join(SENSITIVE_DATA & set(asset.data_held))}) → high base"
            )
        else:
            priority = "medium"
            reasons.append("Office-only without sensitive data → medium base")

    # ── Rule 3: Auth-chain penalty ────────────────────────────────────────────
    min_hops = _min_hop_count(reachability)
    if not is_unauth and min_hops > 1:
        old = priority
        priority = _lower(priority)
        reasons.append(
            f"Requires authentication (PR:{cvss.privileges_required}) and "
            f"chained access ({min_hops} hops) → lower one level to {priority} from {old}"
        )

    # ── Rule 4: Informational signals (do not change priority) ───────────────
    in_kev = snapshot.kev.get("in_kev", False)
    if in_kev:
        reasons.append(
            f"KEV-listed ({snapshot.kev.get('dateAdded', '?')}): "
            "actively exploited in the wild"
        )
    epss_val = snapshot.epss.get("epss", 0.0)
    pct_val  = snapshot.epss.get("percentile", 0.0)
    if epss_val:
        reasons.append(f"EPSS {epss_val:.4f} ({pct_val:.1%} of CVEs)")

    reasons.append(
        f"Asset: {asset.name} (criticality={asset.criticality}), "
        f"holds: {', '.join(asset.data_held[:4]) or 'nothing sensitive'}"
    )

    return RankResult(priority=priority, reasons=reasons)
