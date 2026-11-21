"""Tests for triage/tools/ — no network calls; all fixtures are inline."""

import pytest

from triage.tools.environment import (
    Asset,
    Control,
    CveSnapshot,
    InboundRule,
    SecurityGroup,
    Software,
    load_environment,
)
from triage.tools.asset_search import AssetHit, find_affected_assets
from triage.tools.reachability import (
    ReachabilityResult,
    check_reachability,
)
from triage.tools.ranking import RankResult, rank


# ── Shared: load the real environment once ────────────────────────────────────

@pytest.fixture(scope="module")
def env():
    return load_environment()


# ── Environment loader ────────────────────────────────────────────────────────

class TestEnvironment:
    def test_loads_eight_assets(self, env):
        assert len(env.assets) == 8

    def test_loads_eight_security_groups(self, env):
        assert len(env.security_groups) == 8

    def test_loads_two_controls(self, env):
        assert len(env.controls) == 2

    def test_asset_lookup_by_id(self, env):
        a = env.assets_by_id["asset-jenkins"]
        assert a.name == "jenkins-01"
        assert a.criticality == "high"

    def test_asset_has_software(self, env):
        a = env.assets_by_id["asset-app-server"]
        names = [s.name for s in a.software]
        assert "log4j-core" in names

    def test_waf_control_protects_nginx_lb(self, env):
        ctrl = next(c for c in env.controls if c.id == "ctrl-waf")
        assert ctrl.protects_asset_id == "asset-nginx-lb"
        assert ctrl.mode == "block"
        assert "https" in ctrl.inspects

    def test_ips_control_between_public_and_app(self, env):
        ctrl = next(c for c in env.controls if c.id == "ctrl-ips")
        assert "subnet-public" in ctrl.between_subnet_ids
        assert "subnet-app"    in ctrl.between_subnet_ids
        assert ctrl.mode == "detect"

    def test_no_public_ip_on_app_server(self, env):
        # public_ip must not be used for reachability, but is stored faithfully
        a = env.assets_by_id["asset-app-server"]
        assert a.public_ip is None

    def test_admin_host_has_public_ip(self, env):
        a = env.assets_by_id["asset-admin-host"]
        assert a.public_ip is not None   # present in data, but SG restricts access


# ── Asset search ──────────────────────────────────────────────────────────────

# Minimal NVD fixture builders used by multiple tests
def _nvd_fixture(vendor: str, product: str, start_incl: str, end_excl: str) -> dict:
    return {
        "vulnerabilities": [{
            "cve": {
                "configurations": [{
                    "nodes": [{
                        "cpeMatch": [{
                            "vulnerable": True,
                            "criteria": f"cpe:2.3:a:{vendor}:{product}:*",
                            "versionStartIncluding": start_incl,
                            "versionEndExcluding": end_excl,
                        }]
                    }]
                }]
            }
        }]
    }


_SNAP_LOG4SHELL = CveSnapshot(
    cve_id="CVE-2021-44228",
    nvd=_nvd_fixture("apache", "log4j", "2.0-beta9", "2.15.0"),
    kev={"in_kev": True,  "dateAdded": "2021-12-10"},
    epss={"epss": 0.9754, "percentile": 0.9999},
)

_SNAP_JENKINS = CveSnapshot(
    cve_id="CVE-2024-23897",
    nvd=_nvd_fixture("jenkins", "jenkins", "2.361.1", "2.426.3"),
    kev={"in_kev": True,  "dateAdded": "2024-08-19"},
    epss={"epss": 0.9975, "percentile": 0.9999},
)

_SNAP_CITRIX = CveSnapshot(
    cve_id="CVE-2023-4966",
    nvd=_nvd_fixture("citrix", "netscaler_gateway", "13.0", "13.0.92.21"),
    kev={"in_kev": True,  "dateAdded": "2023-10-18"},
    epss={"epss": 0.9748, "percentile": 0.9999},
)

_SNAP_HTTP2 = CveSnapshot(
    cve_id="CVE-2023-44487",
    nvd={
        "vulnerabilities": [{
            "cve": {
                "configurations": [{
                    "nodes": [{
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:f5:nginx:*",
                                "versionStartIncluding": "1.9.5",
                                "versionEndIncluding": "1.25.2",
                            },
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:jenkins:jenkins:*",
                                "versionStartIncluding": "2.0",
                                "versionEndExcluding": "2.427.0",
                            },
                        ]
                    }]
                }]
            }
        }]
    },
    kev={"in_kev": True,  "dateAdded": "2023-10-10"},
    epss={"epss": 0.9748, "percentile": 0.9999},
)


class TestAssetSearch:
    def test_log4shell_hits_app_server(self, env):
        hits = find_affected_assets("CVE-2021-44228", env=env, snapshot=_SNAP_LOG4SHELL)
        names = [h.asset.name for h in hits]
        assert "app-server-01" in names

    def test_log4shell_does_not_hit_jenkins(self, env):
        hits = find_affected_assets("CVE-2021-44228", env=env, snapshot=_SNAP_LOG4SHELL)
        names = [h.asset.name for h in hits]
        assert "jenkins-01" not in names

    def test_jenkins_hits_jenkins_01(self, env):
        hits = find_affected_assets("CVE-2024-23897", env=env, snapshot=_SNAP_JENKINS)
        names = [h.asset.name for h in hits]
        assert "jenkins-01" in names

    def test_citrix_returns_empty(self, env):
        # No asset runs Citrix NetScaler — the "not present" test case
        hits = find_affected_assets("CVE-2023-4966", env=env, snapshot=_SNAP_CITRIX)
        assert hits == []

    def test_http2_hits_nginx(self, env):
        hits = find_affected_assets("CVE-2023-44487", env=env, snapshot=_SNAP_HTTP2)
        names = [h.asset.name for h in hits]
        assert "nginx-lb-01" in names

    def test_http2_hits_jenkins(self, env):
        hits = find_affected_assets("CVE-2023-44487", env=env, snapshot=_SNAP_HTTP2)
        names = [h.asset.name for h in hits]
        assert "jenkins-01" in names

    def test_hit_records_vendor_product(self, env):
        hits = find_affected_assets("CVE-2021-44228", env=env, snapshot=_SNAP_LOG4SHELL)
        h = next(h for h in hits if h.asset.name == "app-server-01")
        assert h.vendor  == "apache"
        assert h.product == "log4j"

    def test_hit_records_matched_range(self, env):
        hits = find_affected_assets("CVE-2021-44228", env=env, snapshot=_SNAP_LOG4SHELL)
        h = next(h for h in hits if h.asset.name == "app-server-01")
        assert "versionStartIncluding" in h.matched_range or "versionEndExcluding" in h.matched_range


# ── Reachability ──────────────────────────────────────────────────────────────

class TestReachability:
    # app-server-01: internet-reachable via nginx-lb-01 in 2 hops
    def test_app_server_reachable_from_internet(self, env):
        r = check_reachability("asset-app-server", env=env)
        assert r.reachable_from_internet is True

    def test_app_server_internet_path_two_hops(self, env):
        r = check_reachability("asset-app-server", env=env)
        assert any(p.hop_count == 2 for p in r.internet_paths)

    def test_app_server_internet_path_has_waf_and_ips(self, env):
        r = check_reachability("asset-app-server", env=env)
        for p in r.internet_paths:
            if p.hop_count == 2:
                assert "ctrl-waf" in p.all_controls
                assert "ctrl-ips" in p.all_controls
                return
        pytest.fail("No 2-hop internet path found")

    def test_app_server_reachable_from_office(self, env):
        r = check_reachability("asset-app-server", env=env)
        assert r.reachable_from_office is True

    # admin-host-01: office-only despite having a public IP
    def test_admin_host_NOT_reachable_from_internet(self, env):
        r = check_reachability("asset-admin-host", env=env)
        assert r.reachable_from_internet is False

    def test_admin_host_reachable_from_office(self, env):
        r = check_reachability("asset-admin-host", env=env)
        assert r.reachable_from_office is True

    def test_admin_host_office_path_one_hop(self, env):
        r = check_reachability("asset-admin-host", env=env)
        assert any(p.hop_count == 1 for p in r.office_paths)

    def test_admin_host_office_path_no_controls(self, env):
        r = check_reachability("asset-admin-host", env=env)
        for p in r.office_paths:
            if p.hop_count == 1:
                assert p.all_controls == []
                return
        pytest.fail("No 1-hop office path found")

    def test_admin_host_office_hop_port_22(self, env):
        r = check_reachability("asset-admin-host", env=env)
        for p in r.office_paths:
            if p.hop_count == 1:
                assert p.hops[0].port == 22
                return

    # postgres-db-01: 3 hops both ways
    def test_postgres_reachable_from_internet(self, env):
        r = check_reachability("asset-postgres", env=env)
        assert r.reachable_from_internet is True

    def test_postgres_internet_path_three_hops(self, env):
        r = check_reachability("asset-postgres", env=env)
        assert any(p.hop_count == 3 for p in r.internet_paths)

    def test_postgres_office_has_three_hop_path(self, env):
        r = check_reachability("asset-postgres", env=env)
        all_office = r.internet_paths + r.office_paths  # internet paths are also reachable from office
        assert any(p.hop_count == 3 for p in all_office)

    def test_postgres_office_path_via_admin_host_exists(self, env):
        r = check_reachability("asset-postgres", env=env)
        for p in r.office_paths:
            names = [h.to for h in p.hops]
            if "admin-host-01" in names and "jenkins-01" in names:
                return
        pytest.fail("No office path via admin-host-01 → jenkins-01 found")

    # nginx-lb-01: directly internet-reachable in 1 hop
    def test_nginx_lb_internet_one_hop(self, env):
        r = check_reachability("asset-nginx-lb", env=env)
        assert any(p.hop_count == 1 for p in r.internet_paths)

    def test_nginx_lb_internet_hop_has_waf(self, env):
        r = check_reachability("asset-nginx-lb", env=env)
        for p in r.internet_paths:
            if p.hop_count == 1:
                assert "ctrl-waf" in p.all_controls
                return

    def test_nginx_lb_internet_hop_prefers_port_443(self, env):
        r = check_reachability("asset-nginx-lb", env=env)
        for p in r.internet_paths:
            if p.hop_count == 1:
                assert p.hops[0].port == 443
                return

    # jenkins-01: 2 hops from office via admin-host-01
    def test_jenkins_NOT_reachable_from_internet(self, env):
        r = check_reachability("asset-jenkins", env=env)
        assert r.reachable_from_internet is False

    def test_jenkins_reachable_from_office(self, env):
        r = check_reachability("asset-jenkins", env=env)
        assert r.reachable_from_office is True

    def test_jenkins_office_path_two_hops_via_admin(self, env):
        r = check_reachability("asset-jenkins", env=env)
        for p in r.office_paths:
            if p.hop_count == 2:
                names = [h.to for h in p.hops]
                if "admin-host-01" in names and "jenkins-01" in names:
                    assert "ctrl-ips" in p.all_controls
                    return
        pytest.fail("No 2-hop office path via admin-host-01 found")


# ── Ranking ───────────────────────────────────────────────────────────────────

def _cvss_snap(cve_id: str, vector: str, score: float,
               pr: str, ci: str, ii: str, ai: str,
               in_kev: bool = False) -> CveSnapshot:
    return CveSnapshot(
        cve_id=cve_id,
        nvd={
            "vulnerabilities": [{
                "cve": {
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "vectorString": vector,
                                "baseScore": score,
                                "attackVector": "NETWORK",
                                "privilegesRequired": pr,
                                "confidentialityImpact": ci,
                                "integrityImpact": ii,
                                "availabilityImpact": ai,
                            }
                        }]
                    }
                }
            }]
        },
        kev={"in_kev": in_kev, "dateAdded": "2024-01-01" if in_kev else None},
        epss={"epss": 0.99, "percentile": 0.9999},
    )


class TestRanking:
    # Log4Shell on app-server-01: internet + unauth + C:H → critical
    def test_critical_log4shell(self, env):
        r = check_reachability("asset-app-server", env=env)
        snap = _cvss_snap("CVE-2021-44228",
                          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0,
                          pr="NONE", ci="HIGH", ii="HIGH", ai="HIGH", in_kev=True)
        result = rank("CVE-2021-44228", "asset-app-server", r, env=env, snapshot=snap)
        assert result.priority == "critical"

    # Jenkins CVE-2024-23897: office-only, C:H, holds credentials → high
    def test_high_jenkins_file_read(self, env):
        r = check_reachability("asset-jenkins", env=env)
        snap = _cvss_snap("CVE-2024-23897",
                          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8,
                          pr="NONE", ci="HIGH", ii="HIGH", ai="HIGH", in_kev=True)
        result = rank("CVE-2024-23897", "asset-jenkins", r, env=env, snapshot=snap)
        assert result.priority == "high"

    # HTTP/2 Rapid Reset on nginx-lb-01: internet + DoS-only → high
    def test_high_nginx_dos(self, env):
        r = check_reachability("asset-nginx-lb", env=env)
        snap = _cvss_snap("CVE-2023-44487",
                          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5,
                          pr="NONE", ci="NONE", ii="NONE", ai="HIGH", in_kev=True)
        result = rank("CVE-2023-44487", "asset-nginx-lb", r, env=env, snapshot=snap)
        assert result.priority == "high"

    # HTTP/2 Rapid Reset on jenkins-01: office-only + DoS-only → medium
    def test_medium_jenkins_dos(self, env):
        r = check_reachability("asset-jenkins", env=env)
        snap = _cvss_snap("CVE-2023-44487",
                          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5,
                          pr="NONE", ci="NONE", ii="NONE", ai="HIGH", in_kev=True)
        result = rank("CVE-2023-44487", "asset-jenkins", r, env=env, snapshot=snap)
        assert result.priority == "medium"

    # OpenSSH on admin-host-01: office-only, C:H, holds credentials → high
    def test_high_openssh(self, env):
        r = check_reachability("asset-admin-host", env=env)
        snap = _cvss_snap("CVE-2024-6387",
                          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1,
                          pr="NONE", ci="HIGH", ii="HIGH", ai="HIGH", in_kev=False)
        result = rank("CVE-2024-6387", "asset-admin-host", r, env=env, snapshot=snap)
        assert result.priority == "high"

    # PostgreSQL CVE-2024-10979: internet, PR:L, 3-hop chain → medium
    def test_medium_postgres_auth_chain(self, env):
        r = check_reachability("asset-postgres", env=env)
        snap = _cvss_snap("CVE-2024-10979",
                          "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8,
                          pr="LOW", ci="HIGH", ii="HIGH", ai="HIGH", in_kev=False)
        result = rank("CVE-2024-10979", "asset-postgres", r, env=env, snapshot=snap)
        assert result.priority == "medium"

    def test_result_includes_reasons(self, env):
        r = check_reachability("asset-app-server", env=env)
        snap = _cvss_snap("CVE-2021-44228",
                          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0,
                          pr="NONE", ci="HIGH", ii="HIGH", ai="HIGH", in_kev=True)
        result = rank("CVE-2021-44228", "asset-app-server", r, env=env, snapshot=snap)
        assert len(result.reasons) >= 2
        assert any("KEV" in s for s in result.reasons)
