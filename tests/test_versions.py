"""Unit tests for triage.versions — no network calls."""

from triage.versions import (
    ALIASES,
    find_vulnerable_ranges,
    first_matching_range,
    parse_version,
    version_eq,
    version_in_range,
    version_lt,
    version_lte,
)


# ── parse_version ─────────────────────────────────────────────────────────────

class TestParseVersion:
    def test_p_suffix(self):
        assert parse_version("9.3p1") == (9, 3, 1)

    def test_p_suffix_larger(self):
        assert parse_version("9.8p1") == (9, 8, 1)

    def test_prerelease_beta_slot_is_negative(self):
        v = parse_version("2.0-beta9")
        # Third element must be negative — pre-release < release
        assert len(v) == 3 and v[2] < 0

    def test_semver_three_part(self):
        assert parse_version("2.426.1") == (2, 426, 1)

    def test_two_part(self):
        assert parse_version("14.9") == (14, 9)

    def test_equal_versions(self):
        assert parse_version("2.14.1") == parse_version("2.14.1")


# ── version_lt / version_lte ─────────────────────────────────────────────────

class TestVersionComparisons:
    def test_p_suffix_lt(self):
        # 9.3p1 < 9.8p1 (OpenSSH regreSSHion boundary)
        assert version_lt("9.3p1", "9.8p1")

    def test_p_suffix_not_lt_reversed(self):
        assert not version_lt("9.8p1", "9.3p1")

    def test_prerelease_lt_its_release(self):
        # 2.0-beta9 < 2.0  (padding makes (2,0,-191) vs (2,0,0))
        assert version_lt("2.0-beta9", "2.0")

    def test_prerelease_lt_later_release(self):
        # 2.0-beta9 < 2.14.1
        assert version_lt("2.0-beta9", "2.14.1")

    def test_equal_is_lte(self):
        assert version_lte("2.14.1", "2.14.1")

    def test_equal_is_not_lt(self):
        assert not version_lt("2.14.1", "2.14.1")

    def test_equal_is_eq(self):
        assert version_eq("14.9", "14.9")

    def test_14_9_lt_14_13(self):
        # PostgreSQL: 14.9 < 14.13
        assert version_lt("14.9", "14.13")


# ── version_in_range ──────────────────────────────────────────────────────────

class TestVersionInRange:
    # Jenkins CVE-2024-23897 style: >=2.361.1, <2.426.3
    _jenkins_range = {
        "vulnerable": True,
        "criteria": "cpe:2.3:a:jenkins:jenkins:*:*:*:*:lts:*:*:*",
        "versionStartIncluding": "2.361.1",
        "versionEndExcluding": "2.426.3",
    }

    def test_jenkins_our_version_is_vulnerable(self):
        assert version_in_range("2.426.1", self._jenkins_range)

    def test_jenkins_boundary_excluded(self):
        assert not version_in_range("2.426.3", self._jenkins_range)

    def test_jenkins_patched_version_safe(self):
        assert not version_in_range("2.441.0", self._jenkins_range)

    def test_jenkins_below_start_not_in_range(self):
        # 2.300 < versionStartIncluding 2.361.1 — not vulnerable
        assert not version_in_range("2.300", self._jenkins_range)

    # versionStartExcluding edge: the start version itself is NOT in range
    _start_excluding_range = {
        "vulnerable": True,
        "criteria": "cpe:2.3:a:jenkins:jenkins:*",
        "versionStartExcluding": "2.361.1",
        "versionEndExcluding": "2.426.3",
    }

    def test_start_excluding_boundary_not_in_range(self):
        # versionStartExcluding means strictly greater-than — 2.361.1 itself is out
        assert not version_in_range("2.361.1", self._start_excluding_range)

    def test_start_excluding_just_above_is_in_range(self):
        assert version_in_range("2.361.2", self._start_excluding_range)

    # Log4Shell style: >=2.0-beta9, <=2.14.1
    _log4j_range = {
        "vulnerable": True,
        "criteria": "cpe:2.3:a:apache:log4j:*",
        "versionStartIncluding": "2.0-beta9",
        "versionEndIncluding": "2.14.1",
    }

    def test_log4j_our_version_is_vulnerable(self):
        assert version_in_range("2.14.1", self._log4j_range)

    def test_log4j_lower_boundary_vulnerable(self):
        assert version_in_range("2.0-beta9", self._log4j_range)

    def test_log4j_patched_version_safe(self):
        assert not version_in_range("2.15.0", self._log4j_range)

    def test_log4j_1x_below_start_not_in_range(self):
        # 1.2.17 < versionStartIncluding 2.0-beta9 — different major, not vulnerable
        assert not version_in_range("1.2.17", self._log4j_range)

    # OpenSSH regreSSHion style: <9.8p1
    _openssh_range = {
        "vulnerable": True,
        "criteria": "cpe:2.3:a:openbsd:openssh:*",
        "versionEndExcluding": "9.8p1",
    }

    def test_openssh_our_version_is_vulnerable(self):
        assert version_in_range("9.3p1", self._openssh_range)

    def test_openssh_patched_version_safe(self):
        assert not version_in_range("9.8p1", self._openssh_range)

    # PostgreSQL style: >=14.0, <14.13
    _pg_range = {
        "vulnerable": True,
        "criteria": "cpe:2.3:a:postgresql:postgresql:*",
        "versionStartIncluding": "14.0",
        "versionEndExcluding": "14.13",
    }

    def test_postgresql_14_9_parses_without_crash(self):
        # Regression guard: two-part version must not raise
        result = version_in_range("14.9", self._pg_range)
        assert isinstance(result, bool)

    def test_postgresql_14_9_is_in_range(self):
        assert version_in_range("14.9", self._pg_range)


# ── ALIASES ───────────────────────────────────────────────────────────────────

# Minimal NVD fixture for CVE-2023-44487 nginx entry (f5 vendor)
_NVD_44487_NGINX_FIXTURE = {
    "vulnerabilities": [{
        "cve": {
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [{
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:f5:nginx:*",
                        "versionStartIncluding": "1.9.5",
                        "versionEndIncluding": "1.25.2",
                    }]
                }]
            }]
        }
    }]
}


class TestAliases:
    def test_nginx_accepts_nginx_vendor(self):
        assert ("nginx", "nginx") in ALIASES["nginx"]

    def test_nginx_accepts_f5_vendor(self):
        assert ("f5", "nginx") in ALIASES["nginx"]

    def test_openssh_server_maps_to_openbsd(self):
        assert ("openbsd", "openssh") in ALIASES["openssh-server"]

    def test_log4j_core_maps_to_apache(self):
        assert ("apache", "log4j") in ALIASES["log4j-core"]

    def test_all_environment_software_covered(self):
        required = [
            "nginx", "log4j-core", "tomcat", "jenkins",
            "openssh-server", "postgresql", "vsftpd",
            "redis", "prometheus", "grafana", "openjdk",
        ]
        for name in required:
            assert name in ALIASES and len(ALIASES[name]) > 0, \
                f"ALIASES missing entry for {name!r}"

    def test_nginx_1_24_0_matches_f5_range(self):
        # 1.24.0 falls in f5:nginx >=1.9.5, <=1.25.2 from CVE-2023-44487
        all_ranges = []
        for vendor, product in ALIASES["nginx"]:
            all_ranges.extend(find_vulnerable_ranges(_NVD_44487_NGINX_FIXTURE, vendor, product))
        assert any(version_in_range("1.24.0", r) for r in all_ranges)

    def test_nginx_vendor_nginx_not_in_f5_fixture(self):
        # Confirm the nginx:nginx pair finds nothing in this fixture — only f5:nginx matches
        ranges_via_nginx_vendor = find_vulnerable_ranges(
            _NVD_44487_NGINX_FIXTURE, "nginx", "nginx"
        )
        assert ranges_via_nginx_vendor == []

    def test_second_alias_pair_matches_when_first_misses(self):
        # Fixture: nginx:nginx has a range that excludes 1.24.0 (>=2.0.0, <=2.9.9)
        #          f5:nginx  has a range that includes 1.24.0 (>=1.9.5, <=1.25.2)
        # Iterating over ALIASES["nginx"] must still return a match.
        nvd = {
            "vulnerabilities": [{
                "cve": {
                    "configurations": [{
                        "nodes": [{
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:nginx:nginx:*",
                                    "versionStartIncluding": "2.0.0",
                                    "versionEndIncluding": "2.9.9",
                                },
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:f5:nginx:*",
                                    "versionStartIncluding": "1.9.5",
                                    "versionEndIncluding": "1.25.2",
                                },
                            ]
                        }]
                    }]
                }
            }]
        }
        # Replicate the loop from fetch_snapshots.py
        hit = None
        for vendor, product in ALIASES["nginx"]:
            ranges = find_vulnerable_ranges(nvd, vendor, product)
            if not ranges:
                continue
            hit = first_matching_range("1.24.0", ranges)
            if hit:
                break
        assert hit is not None, "Should match via f5:nginx even though nginx:nginx range misses"

    def test_first_alias_pair_non_matching_range_does_not_block_second(self):
        # Inverse: 2.5.0 is in the nginx:nginx range but NOT in the f5:nginx range.
        # Verifies the fixture is correctly partitioned (guards test integrity).
        nvd = {
            "vulnerabilities": [{
                "cve": {
                    "configurations": [{
                        "nodes": [{
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:nginx:nginx:*",
                                    "versionStartIncluding": "2.0.0",
                                    "versionEndIncluding": "2.9.9",
                                },
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:f5:nginx:*",
                                    "versionStartIncluding": "1.9.5",
                                    "versionEndIncluding": "1.25.2",
                                },
                            ]
                        }]
                    }]
                }
            }]
        }
        nginx_ranges = find_vulnerable_ranges(nvd, "nginx", "nginx")
        f5_ranges    = find_vulnerable_ranges(nvd, "f5",    "nginx")
        assert first_matching_range("2.5.0", nginx_ranges) is not None
        assert first_matching_range("2.5.0", f5_ranges)    is None
