"""Tests for triage/agent.py — fake Anthropic client, no live API calls."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from triage.agent import MAX_TOOL_CALLS, ToolExecutor, run_cve
from triage.tools.environment import load_environment


# ── Fake Anthropic client ─────────────────────────────────────────────────────

@dataclass
class FakeUsage:
    input_tokens:  int = 10
    output_tokens: int = 5


@dataclass
class FakeTextBlock:
    text: str
    type: str = "text"


@dataclass
class FakeToolUseBlock:
    id: str
    name: str
    input: dict
    type: str = "tool_use"


@dataclass
class FakeMessage:
    content: list
    stop_reason: str = "tool_use"
    usage: FakeUsage = field(default_factory=FakeUsage)


class FakeMessages:
    def __init__(self, responses: list[FakeMessage]):
        self._iter = iter(responses)

    def create(self, **kwargs) -> FakeMessage:
        return next(self._iter)


class FakeAnthropicClient:
    def __init__(self, responses: list[FakeMessage]):
        self.messages = FakeMessages(responses)


# ── Shared fixtures ───────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def env():
    return load_environment()


def _not_present_responses(cve_id: str = "CVE-2023-4966") -> list[FakeMessage]:
    """Simulate an agent triaging a CVE that is not in the environment."""
    return [
        FakeMessage(content=[
            FakeTextBlock("Let me get the CVE details first."),
            FakeToolUseBlock("tu_1", "get_cve_details", {"cve_id": cve_id}),
        ], stop_reason="tool_use"),
        FakeMessage(content=[
            FakeToolUseBlock("tu_2", "find_affected_assets", {"cve_id": cve_id}),
        ], stop_reason="tool_use"),
        FakeMessage(content=[
            FakeToolUseBlock("tu_3", "submit_finding", {
                "cve_id":               cve_id,
                "asset_id":             None,
                "priority":             "not-present",
                "reachability_summary": "not present in this environment",
                "reasons":              [{"claim": "No matching software found", "source": "find_affected_assets"}],
                "mitigation":           "monitor_only",
                "mitigation_detail":    "No action required; CVE does not affect this environment.",
                "needs_human_review":   False,
                "review_reasons":       [],
            }),
        ], stop_reason="tool_use"),
        FakeMessage(content=[FakeTextBlock("Done.")], stop_reason="end_turn"),
    ]


def _jenkins_responses(cve_id: str = "CVE-2024-23897") -> list[FakeMessage]:
    """Simulate a full 5-step flow for a CVE that affects jenkins-01."""
    return [
        FakeMessage(content=[
            FakeTextBlock("Getting CVE details."),
            FakeToolUseBlock("tu_1", "get_cve_details", {"cve_id": cve_id}),
        ], stop_reason="tool_use"),
        FakeMessage(content=[
            FakeToolUseBlock("tu_2", "find_affected_assets", {"cve_id": cve_id}),
        ], stop_reason="tool_use"),
        FakeMessage(content=[
            FakeToolUseBlock("tu_3", "check_reachability", {"asset_id": "asset-jenkins"}),
        ], stop_reason="tool_use"),
        FakeMessage(content=[
            FakeToolUseBlock("tu_4", "rank_finding", {"cve_id": cve_id, "asset_id": "asset-jenkins"}),
        ], stop_reason="tool_use"),
        FakeMessage(content=[
            FakeToolUseBlock("tu_5", "submit_finding", {
                "cve_id":               cve_id,
                "asset_id":             "asset-jenkins",
                "priority":             "high",
                "reachability_summary": "office-network → admin-host-01:22 → jenkins-01:8080 (2 hops, ctrl-ips)",
                "reasons": [
                    {"claim": "Jenkins 2.426.1 falls in vulnerable range",    "source": "find_affected_assets"},
                    {"claim": "Office-only, holds deployment-credentials",     "source": "check_reachability"},
                    {"claim": "Priority high per exposure rules",              "source": "rank_finding"},
                ],
                "mitigation":        "patch",
                "mitigation_detail": "Upgrade Jenkins to >= 2.426.3 (matched_range end from find_affected_assets).",
                "needs_human_review":   False,
                "review_reasons":       [],
            }),
        ], stop_reason="tool_use"),
        FakeMessage(content=[FakeTextBlock("All findings submitted.")], stop_reason="end_turn"),
    ]


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestRunCve:
    def test_not_present_cve_returns_one_finding(self, tmp_path, env):
        client = FakeAnthropicClient(_not_present_responses())
        findings, _ = run_cve("CVE-2023-4966", client, "fake-model", env, tmp_path)
        assert len(findings) == 1
        assert findings[0]["priority"] == "not-present"

    def test_full_flow_jenkins_returns_finding(self, tmp_path, env):
        client = FakeAnthropicClient(_jenkins_responses())
        findings, _ = run_cve("CVE-2024-23897", client, "fake-model", env, tmp_path)
        assert len(findings) == 1
        f = findings[0]
        assert f["cve_id"]   == "CVE-2024-23897"
        assert f["asset_id"] == "asset-jenkins"
        assert f["priority"] == "high"

    def test_finding_has_required_fields(self, tmp_path, env):
        client = FakeAnthropicClient(_jenkins_responses())
        findings, _ = run_cve("CVE-2024-23897", client, "fake-model", env, tmp_path)
        f = findings[0]
        for key in ("cve_id", "asset_id", "priority", "reachability_summary",
                    "reasons", "mitigation", "mitigation_detail",
                    "needs_human_review", "review_reasons"):
            assert key in f, f"Missing key: {key}"

    def test_finding_augmented_with_rank_metadata(self, tmp_path, env):
        client = FakeAnthropicClient(_jenkins_responses())
        findings, _ = run_cve("CVE-2024-23897", client, "fake-model", env, tmp_path)
        f = findings[0]
        assert "always_review" in f
        assert "in_kev"        in f
        assert "epss"          in f
        assert "epss_percentile" in f
        assert "kev_date_added"  in f

    def test_finding_augmented_with_reachability(self, tmp_path, env):
        client = FakeAnthropicClient(_jenkins_responses())
        findings, _ = run_cve("CVE-2024-23897", client, "fake-model", env, tmp_path)
        f = findings[0]
        assert "reachable_from_internet" in f
        assert "reachable_from_office"   in f
        assert f["reachable_from_office"]   is True
        assert f["reachable_from_internet"] is False

    def test_finding_has_asset_name(self, tmp_path, env):
        client = FakeAnthropicClient(_jenkins_responses())
        findings, _ = run_cve("CVE-2024-23897", client, "fake-model", env, tmp_path)
        assert findings[0].get("asset_name") == "jenkins-01"

    def test_run_returns_stats_dict(self, tmp_path, env):
        client = FakeAnthropicClient(_jenkins_responses())
        _, stats = run_cve("CVE-2024-23897", client, "fake-model", env, tmp_path)
        assert "input_tokens"  in stats
        assert "output_tokens" in stats
        assert "seconds"       in stats
        assert stats["input_tokens"]  > 0
        assert stats["output_tokens"] > 0

    def test_stats_accumulate_across_turns(self, tmp_path, env):
        # 6 turns in _jenkins_responses, each with FakeUsage(10, 5) → 60 in, 30 out
        client = FakeAnthropicClient(_jenkins_responses())
        _, stats = run_cve("CVE-2024-23897", client, "fake-model", env, tmp_path)
        assert stats["input_tokens"]  == 6 * 10
        assert stats["output_tokens"] == 6 * 5


class TestGuardrails:
    def test_priority_corrected_when_agent_changes_it(self, tmp_path, env):
        """Agent submits 'critical' but rank_finding returned 'high' → auto-corrected."""
        responses = [
            FakeMessage(content=[
                FakeToolUseBlock("tu_1", "rank_finding",
                                 {"cve_id": "CVE-2024-23897", "asset_id": "asset-jenkins"}),
            ], stop_reason="tool_use"),
            FakeMessage(content=[
                FakeToolUseBlock("tu_2", "submit_finding", {
                    "cve_id":               "CVE-2024-23897",
                    "asset_id":             "asset-jenkins",
                    "priority":             "critical",   # WRONG — rank returns "high"
                    "reachability_summary": "...",
                    "reasons":              [{"claim": "test", "source": "rank_finding"}],
                    "mitigation":           "patch",
                    "mitigation_detail":    "Upgrade Jenkins.",
                    "needs_human_review":   False,
                    "review_reasons":       [],
                }),
            ], stop_reason="tool_use"),
            FakeMessage(content=[], stop_reason="end_turn"),
        ]
        client = FakeAnthropicClient(responses)
        findings, _ = run_cve("CVE-2024-23897", client, "fake-model", env, tmp_path)

        assert len(findings) == 1
        f = findings[0]
        assert f["priority"] == "high"           # corrected from "critical"
        assert f["needs_human_review"] is True
        assert any("Guardrail" in r for r in f["review_reasons"])

    def test_priority_unchanged_when_agent_is_correct(self, tmp_path, env):
        client = FakeAnthropicClient(_jenkins_responses())
        findings, _ = run_cve("CVE-2024-23897", client, "fake-model", env, tmp_path)
        f = findings[0]
        assert f["priority"] == "high"
        assert not any("Guardrail" in r for r in (f.get("review_reasons") or []))


class TestCapAndTrace:
    def test_loop_stops_at_max_tool_calls(self, tmp_path, env):
        """Even with 20 tool_use responses, the loop stops after MAX_TOOL_CALLS."""
        responses = [
            FakeMessage(content=[
                FakeToolUseBlock(f"tu_{i}", "find_affected_assets",
                                 {"cve_id": "CVE-2021-44228"}),
            ], stop_reason="tool_use")
            for i in range(MAX_TOOL_CALLS + 8)
        ]
        client = FakeAnthropicClient(responses)
        run_cve("CVE-2021-44228", client, "fake-model", env, tmp_path)

        trace_path = tmp_path / "trace.jsonl"
        lines = [json.loads(l) for l in trace_path.read_text().splitlines() if l.strip()]
        tool_calls = [l for l in lines if l["type"] == "tool_call"]
        assert len(tool_calls) == MAX_TOOL_CALLS

    def test_trace_file_created(self, tmp_path, env):
        client = FakeAnthropicClient(_not_present_responses())
        run_cve("CVE-2023-4966", client, "fake-model", env, tmp_path)
        assert (tmp_path / "trace.jsonl").exists()

    def test_trace_contains_expected_types(self, tmp_path, env):
        client = FakeAnthropicClient(_jenkins_responses())
        run_cve("CVE-2024-23897", client, "fake-model", env, tmp_path)

        lines = [
            json.loads(l)
            for l in (tmp_path / "trace.jsonl").read_text().splitlines()
            if l.strip()
        ]
        types = {l["type"] for l in lines}
        assert "thought"     in types
        assert "tool_call"   in types
        assert "tool_result" in types
        assert "finding"     in types
        assert "usage"       in types

    def test_trace_entries_have_cve_id(self, tmp_path, env):
        client = FakeAnthropicClient(_not_present_responses("CVE-2023-4966"))
        run_cve("CVE-2023-4966", client, "fake-model", env, tmp_path)

        lines = [
            json.loads(l)
            for l in (tmp_path / "trace.jsonl").read_text().splitlines()
            if l.strip()
        ]
        assert all(l.get("cve_id") == "CVE-2023-4966" for l in lines)

    def test_trace_usage_entries_have_token_counts(self, tmp_path, env):
        client = FakeAnthropicClient(_jenkins_responses())
        run_cve("CVE-2024-23897", client, "fake-model", env, tmp_path)

        lines = [
            json.loads(l)
            for l in (tmp_path / "trace.jsonl").read_text().splitlines()
            if l.strip()
        ]
        usage_entries = [l for l in lines if l["type"] == "usage"]
        assert len(usage_entries) > 0
        for u in usage_entries:
            assert "input_tokens"  in u
            assert "output_tokens" in u


class TestToolExecutorDirectly:
    """Unit tests for ToolExecutor without running the full loop."""

    def test_get_cve_details_returns_description(self, env):
        ex = ToolExecutor(env)
        r  = ex.execute("get_cve_details", {"cve_id": "CVE-2024-23897"})
        assert "description" in r
        assert r.get("cve_id") == "CVE-2024-23897"

    def test_get_cve_details_includes_percentile(self, env):
        ex = ToolExecutor(env)
        r  = ex.execute("get_cve_details", {"cve_id": "CVE-2024-23897"})
        assert "epss_percentile" in r
        assert r["epss_percentile"] > 0

    def test_find_affected_assets_jenkins(self, env):
        ex = ToolExecutor(env)
        r  = ex.execute("find_affected_assets", {"cve_id": "CVE-2024-23897"})
        names = [a["asset_name"] for a in r["affected_assets"]]
        assert "jenkins-01" in names

    def test_find_affected_assets_citrix_empty(self, env):
        ex = ToolExecutor(env)
        r  = ex.execute("find_affected_assets", {"cve_id": "CVE-2023-4966"})
        assert r["count"] == 0

    def test_check_reachability_admin_host_office_only(self, env):
        ex = ToolExecutor(env)
        r  = ex.execute("check_reachability", {"asset_id": "asset-admin-host"})
        assert r["reachable_from_internet"] is False
        assert r["reachable_from_office"]   is True

    def test_rank_finding_jenkins_high(self, env):
        ex = ToolExecutor(env)
        r  = ex.execute("rank_finding", {"cve_id": "CVE-2024-23897", "asset_id": "asset-jenkins"})
        assert r["priority"] == "high"

    def test_rank_finding_caches_reachability(self, env):
        ex = ToolExecutor(env)
        ex.execute("rank_finding", {"cve_id": "CVE-2024-23897", "asset_id": "asset-jenkins"})
        cached = ex._rank_cache.get(("CVE-2024-23897", "asset-jenkins"))
        assert cached is not None
        assert "reachable_from_internet" in cached
        assert "reachable_from_office"   in cached
        assert "epss_percentile"         in cached
        assert "kev_date_added"          in cached

    def test_unknown_tool_returns_error(self, env):
        ex = ToolExecutor(env)
        r  = ex.execute("nonexistent_tool", {})
        assert "error" in r
        assert "unknown" in r["error"]
