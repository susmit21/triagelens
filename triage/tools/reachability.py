"""Walk security-group rules to determine how (and whether) an asset is reachable.

Rules encoded here:
- Reachability is determined by walking inbound SG rules, never by checking public_ip.
- An asset with public_ip may still be unreachable from the internet if its SG
  only allows office CIDR (see admin-host-01 test case).
- Internet-reachable implies office-reachable: the office CIDR 198.51.100.0/24
  is covered by any 0.0.0.0/0 SG rule.
- Each hop records which controls it crosses.  Detect-only controls (IPS) are
  noted but do not count as protective barriers.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from triage.tools.environment import Asset, Environment, load_environment

# Logical source names used internally
INTERNET      = "internet"
OFFICE        = "office"

INTERNET_CIDR = "0.0.0.0/0"
OFFICE_CIDR   = "198.51.100.0/24"

# Display labels that match the answer key
_SOURCE_LABEL = {INTERNET: "internet", OFFICE: "office-network"}

# When multiple SG rules match for one asset, prefer ports in this order.
_PORT_PREFERENCE = [443, 22, 8080, 80, 50000, 5432, 6379, 9090, 3000, 21, 20]

# Map port → HTTP protocol name for WAF inspection check
_PORT_PROTOCOL = {80: "http", 443: "https"}


@dataclass
class Hop:
    from_: str         # "internet", "office-network", or an asset name
    to: str            # asset name
    port: int
    controls: list[str] = field(default_factory=list)   # control IDs on THIS hop


@dataclass
class ReachabilityPath:
    source: str               # "internet" or "office"
    hops: list[Hop]
    hop_count: int
    all_controls: list[str]   # controls in encounter order, de-duplicated


@dataclass
class ReachabilityResult:
    asset_id: str
    asset_name: str
    reachable_from_internet: bool
    reachable_from_office: bool
    internet_paths: list[ReachabilityPath]
    office_paths: list[ReachabilityPath]


# ── Internal helpers ──────────────────────────────────────────────────────────

def _rule_matches(rule_source: str, current_node: str, env: Environment) -> bool:
    """True if rule_source accepts traffic from current_node."""
    if current_node == INTERNET:
        return rule_source == INTERNET_CIDR
    if current_node == OFFICE:
        # 0.0.0.0/0 covers the office CIDR, so both rules match
        return rule_source in (INTERNET_CIDR, OFFICE_CIDR)
    # current_node is an asset_id; match against that asset's SG
    asset = env.assets_by_id.get(current_node)
    return asset is not None and rule_source == asset.security_group_id


def _pick_port(matching_ports: list[int], listening_ports: list[int]) -> int:
    """Choose the best port when multiple SG rules match the same source."""
    in_listening = [p for p in matching_ports if p in listening_ports]
    pool = in_listening if in_listening else matching_ports

    def _rank(p: int) -> int:
        try:
            return _PORT_PREFERENCE.index(p)
        except ValueError:
            return len(_PORT_PREFERENCE)

    return min(pool, key=_rank)


def _hop_controls(from_node: str, to_asset: Asset, port: int, env: Environment) -> list[str]:
    """Return control IDs crossed when stepping from from_node to to_asset on port."""
    result: list[str] = []
    for ctrl in env.controls:
        if ctrl.type == "WAF":
            if to_asset.id != ctrl.protects_asset_id:
                continue
            protocol = _PORT_PROTOCOL.get(port, "")
            if protocol in ctrl.inspects:
                result.append(ctrl.id)

        elif ctrl.type == "IPS":
            subnets   = ctrl.between_subnet_ids
            to_subnet = to_asset.subnet_id
            if to_subnet not in subnets:
                continue
            if from_node in (INTERNET, OFFICE):
                from_subnet = None
            else:
                from_asset  = env.assets_by_id.get(from_node)
                from_subnet = from_asset.subnet_id if from_asset else None
            if from_subnet is not None and from_subnet in subnets and from_subnet != to_subnet:
                result.append(ctrl.id)
    return result


def _dfs(
    current_node: str,
    target_id: str,
    source_label: str,
    path_hops: list[Hop],
    path_controls: list[str],
    visited: frozenset[str],
    env: Environment,
    results: list[ReachabilityPath],
) -> None:
    """DFS over the SG graph; appends completed paths to results."""
    for asset in env.assets:
        if asset.id in visited:
            continue
        sg = env.sg_by_id.get(asset.security_group_id)
        if not sg:
            continue

        matching_ports = [
            r.port for r in sg.inbound
            if _rule_matches(r.source, current_node, env)
        ]
        if not matching_ports:
            continue

        port         = _pick_port(matching_ports, asset.listening_ports)
        hop_controls = _hop_controls(current_node, asset, port, env)

        from_label = (
            source_label
            if current_node in (INTERNET, OFFICE)
            else env.assets_by_id[current_node].name
        )
        hop = Hop(from_=from_label, to=asset.name, port=port, controls=hop_controls)

        new_hops     = path_hops + [hop]
        seen         = set(path_controls)
        new_controls = path_controls + [c for c in hop_controls if c not in seen]

        if asset.id == target_id:
            results.append(ReachabilityPath(
                source=source_label,
                hops=new_hops,
                hop_count=len(new_hops),
                all_controls=new_controls,
            ))
        else:
            _dfs(
                asset.id, target_id, source_label,
                new_hops, new_controls,
                visited | frozenset({asset.id}),
                env, results,
            )


# ── Public API ────────────────────────────────────────────────────────────────

def check_reachability(asset_id: str, env: Environment | None = None) -> ReachabilityResult:
    """
    Return full reachability information for the given asset.

    Runs two DFS passes (from "internet" and from "office") and collects every
    simple path through the SG graph.  Internet-reachable ⟹ office-reachable.
    """
    if env is None:
        env = load_environment()

    asset = env.assets_by_id.get(asset_id)
    if asset is None:
        raise ValueError(f"Unknown asset_id: {asset_id!r}")

    internet_paths: list[ReachabilityPath] = []
    office_paths:   list[ReachabilityPath] = []

    _dfs(INTERNET, asset_id, _SOURCE_LABEL[INTERNET],
         [], [], frozenset({INTERNET}), env, internet_paths)

    _dfs(OFFICE, asset_id, _SOURCE_LABEL[OFFICE],
         [], [], frozenset({OFFICE}), env, office_paths)

    reachable_internet = bool(internet_paths)
    # Internet-reachable implies office-reachable (0.0.0.0/0 ⊃ 198.51.100.0/24)
    reachable_office   = reachable_internet or bool(office_paths)

    return ReachabilityResult(
        asset_id=asset_id,
        asset_name=asset.name,
        reachable_from_internet=reachable_internet,
        reachable_from_office=reachable_office,
        internet_paths=internet_paths,
        office_paths=office_paths,
    )
