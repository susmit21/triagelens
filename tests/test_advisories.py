"""Tests for triage/tools/advisories.py — no live network, no Chroma persistence."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from triage.tools.advisories import (
    _set_index_for_testing,
    label_ref,
    search_advisories,
)


# ── label_ref ─────────────────────────────────────────────────────────────────

class TestLabelRef:
    def test_vendor_jenkins(self):
        assert label_ref("https://www.jenkins.io/security/advisory/2024-01-24/") == "vendor"

    def test_vendor_apache_subdomain(self):
        assert label_ref("https://logging.apache.org/log4j/2.x/security.html") == "vendor"

    def test_vendor_nginx(self):
        assert label_ref("http://nginx.org/en/security_advisories.html") == "vendor"

    def test_vendor_openssh(self):
        assert label_ref("https://www.openssh.com/security.html") == "vendor"

    def test_distro_redhat(self):
        assert label_ref("https://access.redhat.com/security/cve/CVE-2021-44228") == "distro"

    def test_distro_debian(self):
        assert label_ref("https://debian.org/security/2024/dsa-5611") == "distro"

    def test_distro_ubuntu(self):
        assert label_ref("https://ubuntu.com/security/CVE-2024-6387") == "distro"

    def test_distro_netapp(self):
        assert label_ref("https://security.netapp.com/advisory/ntap-20211210-0007/") == "distro"

    def test_exploit_packetstorm(self):
        assert label_ref("http://packetstormsecurity.com/files/176839/Jenkins.html") == "exploit"

    def test_exploit_exploit_db(self):
        assert label_ref("https://exploit-db.com/exploits/51904") == "exploit"

    def test_other_github_normal(self):
        assert label_ref("https://github.com/apache/logging-log4j2/releases/tag/2.17.1") == "other"

    def test_other_github_poc(self):
        assert label_ref("https://github.com/evil/CVE-2024-23897-poc") == "exploit"

    def test_other_cisa(self):
        assert label_ref("https://www.cisa.gov/known-exploited-vulnerabilities") == "other"

    def test_other_unknown(self):
        assert label_ref("https://example.com/page") == "other"


# ── Keyword fallback ──────────────────────────────────────────────────────────

class TestKeywordFallback:
    def _make_advisory(self, tmp_path: Path, cve_id: str, n: int, text: str,
                       quality_ok: bool = True) -> None:
        d = tmp_path / cve_id
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{n}.json").write_text(json.dumps({
            "cve_id":     cve_id,
            "url":        f"https://example.com/{cve_id}/{n}",
            "domain":     "example.com",
            "label":      "other",
            "text":       text,
            "quality_ok": quality_ok,
        }))

    def test_returns_chunks(self, tmp_path):
        self._make_advisory(
            tmp_path, "CVE-TEST-001", 0,
            "Upgrade example-software to 1.2.3 to fix the arbitrary file read issue.",
        )
        _set_index_for_testing(force_missing=True)
        try:
            result = search_advisories(
                "CVE-TEST-001", "upgrade version",
                k=3, advisories_dir=tmp_path,
            )
        finally:
            _set_index_for_testing()

        assert result["source"] == "keyword_fallback"
        assert len(result["chunks"]) == 1
        assert "example.com" in result["chunks"][0]["url"]
        assert "chunk_id" in result["chunks"][0]

    def test_empty_when_no_cve_dir(self, tmp_path):
        _set_index_for_testing(force_missing=True)
        try:
            result = search_advisories(
                "CVE-MISSING-999", "upgrade",
                k=3, advisories_dir=tmp_path,
            )
        finally:
            _set_index_for_testing()

        assert result["chunks"] == []
        assert result["source"] == "keyword_fallback"

    def test_quality_failed_advisory_excluded(self, tmp_path):
        self._make_advisory(tmp_path, "CVE-TEST-002", 0, "Short.", quality_ok=False)
        _set_index_for_testing(force_missing=True)
        try:
            result = search_advisories(
                "CVE-TEST-002", "short",
                k=3, advisories_dir=tmp_path,
            )
        finally:
            _set_index_for_testing()

        assert result["chunks"] == []

    def test_multiple_advisories_scored_by_query_overlap(self, tmp_path):
        self._make_advisory(tmp_path, "CVE-TEST-003", 0, "Upgrade to 1.2.3 to fix the buffer overflow.")
        self._make_advisory(tmp_path, "CVE-TEST-003", 1, "Completely unrelated text about network routing.")
        _set_index_for_testing(force_missing=True)
        try:
            result = search_advisories(
                "CVE-TEST-003", "upgrade fix buffer overflow",
                k=3, advisories_dir=tmp_path,
            )
        finally:
            _set_index_for_testing()

        assert len(result["chunks"]) == 2
        # Higher-scoring chunk should come first
        assert "1.2.3" in result["chunks"][0]["text"] or "overflow" in result["chunks"][0]["text"]

    def test_respects_k_limit(self, tmp_path):
        for i in range(5):
            self._make_advisory(tmp_path, "CVE-TEST-004", i, f"Advisory text number {i}.")
        _set_index_for_testing(force_missing=True)
        try:
            result = search_advisories(
                "CVE-TEST-004", "advisory text",
                k=2, advisories_dir=tmp_path,
            )
        finally:
            _set_index_for_testing()

        assert len(result["chunks"]) <= 2
