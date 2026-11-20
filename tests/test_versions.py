"""Unit tests for triage.versions — no network calls."""

from triage.versions import (
    ALIASES,
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

class TestAliases:
    def test_openssh_server_maps_to_openbsd(self):
        assert ALIASES["openssh-server"] == ("openbsd", "openssh")

    def test_log4j_core_maps_to_apache(self):
        assert ALIASES["log4j-core"] == ("apache", "log4j")

    def test_all_environment_software_covered(self):
        required = [
            "nginx", "log4j-core", "tomcat", "jenkins",
            "openssh-server", "postgresql", "vsftpd",
            "redis", "prometheus", "grafana", "openjdk",
        ]
        for name in required:
            assert name in ALIASES, f"ALIASES missing entry for {name!r}"
