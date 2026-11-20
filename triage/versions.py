"""Version parsing and CPE-match utilities shared across triage tools."""

from __future__ import annotations

import re

# Maps software names from environment.json to lists of (vendor, product) CPE pairs.
# Each entry is a list so a single software name can match multiple NVD vendor strings
# (e.g. nginx appears as both "nginx:nginx" and "f5:nginx" in different CVEs).
ALIASES: dict[str, list[tuple[str, str]]] = {
    "nginx":          [("nginx", "nginx"), ("f5", "nginx")],
    "openssh-server": [("openbsd",        "openssh")],
    "log4j-core":     [("apache",         "log4j")],
    "jenkins":        [("jenkins",        "jenkins")],
    "postgresql":     [("postgresql",     "postgresql")],
    "tomcat":         [("apache",         "tomcat")],
    "redis":          [("redis",          "redis")],
    "vsftpd":         [("vsftpd_project", "vsftpd")],
    "prometheus":     [("prometheus",     "prometheus")],
    "grafana":        [("grafana",        "grafana")],
    "openjdk":        [("oracle",         "openjdk")],
}


def parse_version(v: str) -> tuple[int, ...]:
    """
    Parse a version string into a comparable integer tuple.

    Rules:
      "9.3p1"     -> (9, 3, 1)      p-suffix is an extra numeric component
      "2.0-beta9" -> (2, 0, -191)   pre-release gets a negative slot (beta=-200+N)
      "2.426.1"   -> (2, 426, 1)
      "14.9"      -> (14, 9)

    Always compare via version_lt / version_lte — they pad both tuples to the
    same length first, which is required for pre-release to work correctly.
    """
    v = v.strip().lower().lstrip("v")
    result: list[int] = []

    for seg in v.split("."):
        # "3p1"  — portable/patch suffix
        m = re.fullmatch(r"(\d+)p(\d+)", seg)
        if m:
            result.append(int(m.group(1)))
            result.append(int(m.group(2)))
            continue

        # "0-beta9", "1-rc2", "0_alpha3"
        m = re.fullmatch(r"(\d+)[-_](alpha|beta|rc)(\d*)", seg, re.I)
        if m:
            pre_weights = {"alpha": -300, "beta": -200, "rc": -100}
            result.append(int(m.group(1)))
            result.append(pre_weights[m.group(2).lower()] + (int(m.group(3)) if m.group(3) else 0))
            continue

        # Plain integer
        if re.fullmatch(r"\d+", seg):
            result.append(int(seg))
            continue

        # Leading digits only (e.g. "14a")
        m = re.match(r"(\d+)", seg)
        if m:
            result.append(int(m.group(1)))

    return tuple(result) if result else (0,)


def _pad(a: tuple[int, ...], b: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Pad both tuples with zeros to the same length."""
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)), b + (0,) * (n - len(b))


def version_lt(a: str, b: str) -> bool:
    pa, pb = _pad(parse_version(a), parse_version(b))
    return pa < pb


def version_lte(a: str, b: str) -> bool:
    pa, pb = _pad(parse_version(a), parse_version(b))
    return pa <= pb


def version_eq(a: str, b: str) -> bool:
    pa, pb = _pad(parse_version(a), parse_version(b))
    return pa == pb


def version_in_range(version: str, cpe_match: dict) -> bool:
    """
    Return True if version falls within the range from one cpeMatch entry.

    Checks versionStartIncluding/Excluding and versionEndIncluding/Excluding.
    If none of those fields are set, falls back to exact match against the CPE
    version field (position 5 in the colon-separated criteria string).
    """
    vsi = cpe_match.get("versionStartIncluding")
    vse = cpe_match.get("versionStartExcluding")
    vei = cpe_match.get("versionEndIncluding")
    vee = cpe_match.get("versionEndExcluding")

    if vsi and not version_lte(vsi, version):
        return False
    if vse and not version_lt(vse, version):
        return False
    if vei and not version_lte(version, vei):
        return False
    if vee and not version_lt(version, vee):
        return False

    # No range fields: fall back to exact CPE version
    if not any([vsi, vse, vei, vee]):
        parts = cpe_match.get("criteria", "").split(":")
        cpe_ver = parts[5] if len(parts) > 5 else "*"
        if cpe_ver not in ("*", "-", ""):
            return version_eq(version, cpe_ver)

    return True


def _collect_matches(node: dict, vendor: str, product: str) -> list[dict]:
    """Recursively collect vulnerable cpeMatch entries for (vendor, product)."""
    matches = []
    for cpe_match in node.get("cpeMatch", []):
        if not cpe_match.get("vulnerable", False):
            continue
        parts = cpe_match.get("criteria", "").split(":")
        if len(parts) >= 5 and parts[3] == vendor and parts[4] == product:
            matches.append(cpe_match)
    for child in node.get("nodes", []):
        matches.extend(_collect_matches(child, vendor, product))
    return matches


def find_vulnerable_ranges(nvd_response: dict, vendor: str, product: str) -> list[dict]:
    """
    Return all cpeMatch entries with vulnerable=True for (vendor, product).

    Accepts the full NVD 2.0 API response (top-level key: 'vulnerabilities').
    Returns [] when the product is absent or has no vulnerable entries.
    """
    vulns = nvd_response.get("vulnerabilities") or []
    if not vulns:
        return []
    cve_data = vulns[0].get("cve", {})
    matches = []
    for config in cve_data.get("configurations", []):
        for node in config.get("nodes", []):
            matches.extend(_collect_matches(node, vendor, product))
    return matches


def asset_is_vulnerable(version: str, vulnerable_ranges: list[dict]) -> bool:
    """Return True if version falls in ANY of the vulnerable CPE ranges."""
    return any(version_in_range(version, r) for r in vulnerable_ranges)


def first_matching_range(version: str, ranges: list[dict]) -> dict | None:
    """Return the first cpeMatch entry that version falls in, or None."""
    for r in ranges:
        if version_in_range(version, r):
            return r
    return None
