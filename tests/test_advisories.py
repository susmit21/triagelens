"""Tests for triage/tools/advisories.py and scripts/fetch_advisories.py.

No live network calls, no Chroma persistence.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from triage.tools.advisories import (
    _chunk_text,
    _set_index_for_testing,
    label_ref,
    search_advisories,
    vendor_domains_for_cpe,
)


# ── label_ref ─────────────────────────────────────────────────────────────────

class TestLabelRef:
    # Vendor tests require passing the per-CVE vendor_domains set.
    def test_vendor_jenkins(self):
        assert label_ref(
            "https://www.jenkins.io/security/advisory/2024-01-24/",
            vendor_domains=frozenset({"jenkins.io"}),
        ) == "vendor"

    def test_vendor_apache_subdomain(self):
        assert label_ref(
            "https://logging.apache.org/log4j/2.x/security.html",
            vendor_domains=frozenset({"logging.apache.org", "apache.org"}),
        ) == "vendor"

    def test_vendor_nginx(self):
        assert label_ref(
            "http://nginx.org/en/security_advisories.html",
            vendor_domains=frozenset({"nginx.org", "mailman.nginx.org", "f5.com", "my.f5.com"}),
        ) == "vendor"

    def test_vendor_openssh(self):
        assert label_ref(
            "https://www.openssh.com/security.html",
            vendor_domains=frozenset({"openssh.com"}),
        ) == "vendor"

    def test_apache_not_vendor_for_nginx_cve(self):
        """apache.org must not be labelled vendor for a nginx CVE."""
        nginx_vd = frozenset({"nginx.org", "mailman.nginx.org", "f5.com", "my.f5.com"})
        assert label_ref("https://lists.apache.org/thread/something", vendor_domains=nginx_vd) == "other"

    def test_vendor_requires_explicit_domains(self):
        """Without vendor_domains, known vendor sites fall through to 'other'."""
        assert label_ref("https://www.jenkins.io/security/advisory/2024-01-24/") == "other"

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


# ── vendor_domains_for_cpe ───────────────────────────────────────────────────

class TestVendorDomainsForCpe:
    def test_jenkins(self):
        assert "jenkins.io" in vendor_domains_for_cpe(frozenset({"jenkins"}))

    def test_log4j_via_apache_vendor(self):
        domains = vendor_domains_for_cpe(frozenset({"apache", "log4j"}))
        assert "logging.apache.org" in domains
        assert "apache.org" in domains

    def test_nginx(self):
        domains = vendor_domains_for_cpe(frozenset({"nginx"}))
        assert "nginx.org" in domains
        assert "f5.com" in domains

    def test_openssh(self):
        assert "openssh.com" in vendor_domains_for_cpe(frozenset({"openbsd", "openssh"}))

    def test_postgresql(self):
        assert "postgresql.org" in vendor_domains_for_cpe(frozenset({"postgresql"}))

    def test_citrix_via_vendor_token(self):
        assert "citrix.com" in vendor_domains_for_cpe(frozenset({"citrix", "netscaler adc"}))

    def test_apache_not_in_nginx_domains(self):
        """Log4j/apache vendor domains must not bleed into nginx CVEs."""
        nginx_domains = vendor_domains_for_cpe(frozenset({"nginx"}))
        assert "apache.org" not in nginx_domains
        assert "logging.apache.org" not in nginx_domains

    def test_unknown_product_empty(self):
        assert vendor_domains_for_cpe(frozenset({"unknownvendor"})) == frozenset()


# ── _chunk_text ───────────────────────────────────────────────────────────────

class TestChunkText:
    def test_short_text_single_chunk(self):
        assert _chunk_text("Short.") == ["Short."]

    def test_exact_max_single_chunk(self):
        text = "x" * 800
        chunks = _chunk_text(text)
        assert chunks == [text]

    def test_long_text_produces_multiple_chunks(self):
        text = "a" * 2000
        chunks = _chunk_text(text, max_chars=800, overlap=100)
        # step=700: starts at 0, 700, 1400 → 3 chunks
        assert len(chunks) == 3

    def test_chunk_size_capped_at_max_chars(self):
        text = "b" * 5000
        for chunk in _chunk_text(text, max_chars=800, overlap=100):
            assert len(chunk) <= 800

    def test_overlap_between_consecutive_chunks(self):
        text = "c" * 2000
        chunks = _chunk_text(text, max_chars=800, overlap=100)
        # chunk[0] ends at 800, chunk[1] starts at 700 → 100-char overlap
        assert chunks[0] == text[0:800]
        assert chunks[1] == text[700:1500]

    def test_full_text_covered(self):
        text = "d" * 2000
        chunks = _chunk_text(text, max_chars=800, overlap=100)
        assert chunks[0].startswith(text[0])
        assert chunks[-1].endswith(text[-1])

    def test_empty_text_returns_empty(self):
        assert _chunk_text("") == []

    def test_large_text_many_chunks(self):
        # Simulate a 15 000-char advisory page; expect ~21 chunks (step=700)
        text = "word " * 3000  # ~15 000 chars
        chunks = _chunk_text(text, max_chars=800, overlap=100)
        assert len(chunks) > 15


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


# ── PDF detection in fetch_advisories ────────────────────────────────────────

def _load_fetch_advisories():
    """Import scripts/fetch_advisories.py without it being a package."""
    spec = importlib.util.spec_from_file_location(
        "fetch_advisories",
        Path(__file__).parent.parent / "scripts" / "fetch_advisories.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def fa():
    return _load_fetch_advisories()


class TestPdfDetection:

    def _fake_resp(self, *, status=200, content_type="text/html", body=b"hello"):
        class R:
            status_code = status
            headers = {"Content-Type": content_type}
            content = body
            text = body.decode("utf-8", errors="replace")
        return R()

    def test_pdf_content_type_returns_pdf_sentinel(self, fa, monkeypatch):
        """Content-Type: application/pdf → _fetch_text returns the _PDF sentinel."""
        monkeypatch.setattr(
            fa.requests, "get",
            lambda *a, **kw: self._fake_resp(content_type="application/pdf", body=b"binary"),
        )
        assert fa._fetch_text("https://example.com/report.pdf") is fa._PDF

    def test_pdf_body_prefix_returns_pdf_sentinel(self, fa, monkeypatch):
        """Body starting with %PDF → _fetch_text returns the _PDF sentinel even if
        Content-Type is application/octet-stream."""
        monkeypatch.setattr(
            fa.requests, "get",
            lambda *a, **kw: self._fake_resp(
                content_type="application/octet-stream",
                body=b"%PDF-1.4 some content",
            ),
        )
        assert fa._fetch_text("https://example.com/whitepaper") is fa._PDF

    def test_normal_html_not_pdf(self, fa, monkeypatch):
        """Normal HTML response is not mistaken for a PDF."""
        html = b"<html><body><p>Upgrade to 2.4 to fix CVE-2024-1234.</p></body></html>"
        monkeypatch.setattr(
            fa.requests, "get",
            lambda *a, **kw: self._fake_resp(content_type="text/html", body=html),
        )
        result = fa._fetch_text("https://example.com/advisory")
        assert result is not fa._PDF
        assert result is not None
        assert "Upgrade" in result

    def test_pdf_fallback_record_saved(self, fa, monkeypatch, tmp_path):
        """When _fetch_text returns _PDF, fetch_all saves a quality_ok=False record."""
        # Seed a minimal NVD snapshot so fetch_all has something to process
        snap_dir = tmp_path / "snapshots" / "CVE-TEST-PDF"
        snap_dir.mkdir(parents=True)
        nvd = {"vulnerabilities": [{"cve": {
            "references": [{"url": "https://example.com/vuln.pdf"}],
            "configurations": [],
        }}]}
        (snap_dir / "nvd.json").write_text(json.dumps(nvd))

        monkeypatch.setattr(
            fa.requests, "get",
            lambda *a, **kw: self._fake_resp(content_type="application/pdf", body=b"binary"),
        )
        import time
        monkeypatch.setattr(time, "sleep", lambda _: None)

        adv_dir = tmp_path / "advisories"
        fa.fetch_all(snapshots_dir=tmp_path / "snapshots", advisories_dir=adv_dir)

        saved = list((adv_dir / "CVE-TEST-PDF").glob("*.json"))
        assert len(saved) == 1
        record = json.loads(saved[0].read_text())
        assert record["quality_ok"] is False
        assert record["fallback_reason"] == "pdf"
        assert record["url"] == "https://example.com/vuln.pdf"
