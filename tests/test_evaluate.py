"""Tests for eval/evaluate.py — hand-made brief fixtures, no live APIs or LLM."""

from __future__ import annotations

import pytest

from eval.evaluate import _is_grounded, compute_metrics


# ── Minimal fixtures ──────────────────────────────────────────────────────────

def _scored_entry(
    cve_id: str,
    asset_id: str,
    asset_name: str,
    expected: str,
    acceptable: list[str] | None = None,
    internet: bool = True,
    office: bool = True,
    int_hops: int | None = 1,
    off_hops: int | None = 1,
) -> dict:
    paths = []
    if internet:
        paths.append({"source": "internet", "hop_count": int_hops or 1})
    if office and not internet:
        paths.append({"source": "office", "hop_count": off_hops or 1})
    return {
        "cve_id":               cve_id,
        "asset_id":             asset_id,
        "asset_name":           asset_name,
        "present":              True,
        "reachable_from_internet": internet,
        "reachable_from_office":   office,
        "paths":                paths,
        "expected_priority":    expected,
        "acceptable_priorities": acceptable or [expected],
    }


def _not_present_entry(cve_id: str) -> dict:
    return {
        "cve_id":               cve_id,
        "asset_id":             None,
        "asset_name":           None,
        "present":              False,
        "reachable_from_internet": False,
        "reachable_from_office":   False,
        "paths":                [],
        "expected_priority":    "not-present",
        "acceptable_priorities": ["not-present"],
    }


def _decoy_entry(asset_id: str = "asset-ftp") -> dict:
    return {
        "cve_id":               None,
        "asset_id":             asset_id,
        "asset_name":           "ftp-server-01",
        "present":              False,
        "reachable_from_internet": True,
        "reachable_from_office":   True,
        "paths":                [{"source": "internet", "hop_count": 1}],
        "expected_priority":    "no-finding",
        "acceptable_priorities": ["no-finding"],
    }


def _agent_finding(
    cve_id: str,
    asset_id: str | None,
    priority: str,
    *,
    internet: bool = True,
    office: bool = True,
    int_hops: int | None = 1,
    off_hops: int | None = 1,
    in_kev: bool = False,
    always_review: bool = False,
    needs_human_review: bool = False,
    reasons: list[dict] | None = None,
) -> dict:
    return {
        "cve_id":                 cve_id,
        "asset_id":               asset_id,
        "priority":               priority,
        "reachable_from_internet": internet,
        "reachable_from_office":   office,
        "min_hops_internet":      int_hops,
        "min_hops_office":        off_hops,
        "in_kev":                 in_kev,
        "epss":                   0.5,
        "always_review":          always_review,
        "needs_human_review":     needs_human_review,
        "reasons":                reasons or [{"claim": "test", "source": "rank_finding"}],
    }


# ── Groundedness unit tests ───────────────────────────────────────────────────

class TestIsGrounded:
    def test_exact_tool_name(self):
        assert _is_grounded({"source": "rank_finding"}) is True

    def test_dotted_tool_field(self):
        assert _is_grounded({"source": "get_cve_details.cvss_vector"}) is True

    def test_space_separated_dual_source(self):
        # e.g. "get_cve_details.in_kev / epss" — starts with valid tool name
        assert _is_grounded({"source": "get_cve_details.in_kev / epss"}) is True

    def test_invalid_source(self):
        assert _is_grounded({"source": "my_memory"})      is False
        assert _is_grounded({"source": "the internet"})   is False
        assert _is_grounded({"source": ""})               is False

    def test_missing_source_key(self):
        assert _is_grounded({"claim": "something"}) is False


# ── compute_metrics ───────────────────────────────────────────────────────────

class TestPriorityAccuracy:
    def _two_entry_key(self):
        return [
            _scored_entry("CVE-A", "asset-a", "server-a", "critical"),
            _scored_entry("CVE-B", "asset-b", "server-b", "high"),
        ]

    def test_all_correct(self):
        agent_f = [
            _agent_finding("CVE-A", "asset-a", "critical"),
            _agent_finding("CVE-B", "asset-b", "high"),
        ]
        m = compute_metrics(agent_f, agent_f, self._two_entry_key())
        assert m["priority_accuracy"]["agent"] == {"correct": 2, "total": 2}

    def test_one_wrong(self):
        agent_f = [
            _agent_finding("CVE-A", "asset-a", "critical"),
            _agent_finding("CVE-B", "asset-b", "medium"),  # wrong
        ]
        m = compute_metrics(agent_f, agent_f, self._two_entry_key())
        assert m["priority_accuracy"]["agent"]["correct"] == 1

    def test_acceptable_alternative_counts_as_correct(self):
        key = [_scored_entry("CVE-A", "asset-a", "server-a", "medium",
                              acceptable=["low", "medium"])]
        agent_f = [_agent_finding("CVE-A", "asset-a", "low")]
        m = compute_metrics(agent_f, [], key)
        assert m["priority_accuracy"]["agent"] == {"correct": 1, "total": 1}

    def test_missing_finding_counts_as_miss(self):
        key = [_scored_entry("CVE-A", "asset-a", "server-a", "critical")]
        m = compute_metrics([], [], key)  # agent produced nothing
        assert m["priority_accuracy"]["agent"]["correct"] == 0

    def test_missed_high_priority_counted(self):
        key = [
            _scored_entry("CVE-A", "asset-a", "server-a", "critical"),
            _scored_entry("CVE-B", "asset-b", "server-b", "high"),
            _scored_entry("CVE-C", "asset-c", "server-c", "medium"),
        ]
        agent_f = [
            _agent_finding("CVE-A", "asset-a", "medium"),  # missed critical
            _agent_finding("CVE-B", "asset-b", "low"),     # missed high
            _agent_finding("CVE-C", "asset-c", "medium"),  # ok
        ]
        m = compute_metrics(agent_f, [], key)
        assert m["missed_high"]["agent"] == 2


class TestExposureAccuracy:
    def test_exact_match(self):
        key = [_scored_entry("CVE-A", "asset-a", "srv", "high",
                             internet=True, office=True, int_hops=2, off_hops=2)]
        agent_f = [_agent_finding("CVE-A", "asset-a", "high",
                                  internet=True, office=True,
                                  int_hops=2, off_hops=2)]
        m = compute_metrics(agent_f, [], key)
        assert m["exposure_accuracy"]["agent"] == {"correct": 1, "total": 1}

    def test_wrong_internet_flag(self):
        key = [_scored_entry("CVE-A", "asset-a", "srv", "high",
                             internet=False, office=True, int_hops=None, off_hops=1)]
        agent_f = [_agent_finding("CVE-A", "asset-a", "high",
                                  internet=True,  # wrong
                                  office=True, int_hops=1, off_hops=1)]
        m = compute_metrics(agent_f, [], key)
        assert m["exposure_accuracy"]["agent"]["correct"] == 0

    def test_wrong_hop_count(self):
        key = [_scored_entry("CVE-A", "asset-a", "srv", "high",
                             internet=True, office=True, int_hops=2)]
        agent_f = [_agent_finding("CVE-A", "asset-a", "high",
                                  internet=True, office=True, int_hops=3)]  # wrong
        m = compute_metrics(agent_f, [], key)
        assert m["exposure_accuracy"]["agent"]["correct"] == 0


class TestGroundedness:
    def test_all_grounded(self):
        agent_f = [
            _agent_finding("CVE-A", "asset-a", "high", reasons=[
                {"claim": "CVSS 9.8", "source": "get_cve_details.cvss_vector"},
                {"claim": "KEV listed", "source": "get_cve_details.in_kev"},
            ])
        ]
        m = compute_metrics(agent_f, [], [])
        g = m["groundedness"]["agent"]
        assert g["total"] == 2
        assert g["grounded"] == 2

    def test_some_ungrounded(self):
        agent_f = [
            _agent_finding("CVE-A", "asset-a", "high", reasons=[
                {"claim": "CVSS 9.8",        "source": "get_cve_details"},
                {"claim": "my own reasoning", "source": "intuition"},
            ])
        ]
        m = compute_metrics(agent_f, [], [])
        g = m["groundedness"]["agent"]
        assert g["total"] == 2
        assert g["grounded"] == 1


class TestNotPresentAndDecoy:
    def test_not_present_pass_when_no_asset_finding(self):
        key = [_not_present_entry("CVE-2023-4966")]
        agent_f = [_agent_finding("CVE-2023-4966", None, "not-present")]
        m = compute_metrics(agent_f, [], key)
        assert m["not_present"]["agent"] is True

    def test_not_present_fail_when_asset_found(self):
        key = [_not_present_entry("CVE-2023-4966")]
        # Agent wrongly matches an asset
        agent_f = [_agent_finding("CVE-2023-4966", "asset-some", "high")]
        m = compute_metrics(agent_f, [], key)
        assert m["not_present"]["agent"] is False

    def test_decoy_pass_when_ftp_absent(self):
        key = [_decoy_entry("asset-ftp")]
        agent_f = [_agent_finding("CVE-A", "asset-a", "high")]
        m = compute_metrics(agent_f, [], key)
        assert m["decoy"]["agent"] is True

    def test_decoy_fail_when_ftp_present(self):
        key = [_decoy_entry("asset-ftp")]
        agent_f = [_agent_finding("CVE-A", "asset-ftp", "medium")]
        m = compute_metrics(agent_f, [], key)
        assert m["decoy"]["agent"] is False


class TestHumanReview:
    def test_needs_review_count(self):
        agent_f = [
            _agent_finding("CVE-A", "asset-a", "critical", needs_human_review=True),
            _agent_finding("CVE-B", "asset-b", "high",     needs_human_review=False),
            _agent_finding("CVE-C", "asset-c", "medium",   needs_human_review=True),
        ]
        m = compute_metrics(agent_f, [], [])
        assert m["human_review"]["needs_review"]  == 2
        assert m["human_review"]["total"]         == 3

    def test_always_review_count(self):
        agent_f = [
            _agent_finding("CVE-A", "asset-a", "critical", always_review=True,  in_kev=True),
            _agent_finding("CVE-B", "asset-b", "high",     always_review=False),
        ]
        m = compute_metrics(agent_f, [], [])
        assert m["human_review"]["always_review"] == 1
