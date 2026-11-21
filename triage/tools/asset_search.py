"""Find environment assets whose software falls in a CVE's vulnerable ranges."""
from __future__ import annotations

from dataclasses import dataclass

from triage.tools.environment import Asset, CveSnapshot, Environment
from triage.tools.environment import load_cve_snapshot, load_environment
from triage.versions import ALIASES, find_vulnerable_ranges, first_matching_range


@dataclass
class AssetHit:
    asset: Asset
    sw_name: str
    version: str
    vendor: str
    product: str
    matched_range: dict   # the cpeMatch entry that matched


def find_affected_assets(
    cve_id: str,
    env: Environment | None = None,
    snapshot: CveSnapshot | None = None,
) -> list[AssetHit]:
    """Return every (asset, software) pair whose version falls in the CVE's ranges."""
    if env is None:
        env = load_environment()
    if snapshot is None:
        snapshot = load_cve_snapshot(cve_id)

    nvd  = snapshot.nvd
    hits: list[AssetHit] = []

    for asset in env.assets:
        for sw in asset.software:
            alias_list = ALIASES.get(sw.name)
            if not alias_list:
                continue
            for vendor, product in alias_list:
                ranges = find_vulnerable_ranges(nvd, vendor, product)
                if not ranges:
                    continue
                matched = first_matching_range(sw.version, ranges)
                if matched:
                    hits.append(AssetHit(
                        asset=asset,
                        sw_name=sw.name,
                        version=sw.version,
                        vendor=vendor,
                        product=product,
                        matched_range=matched,
                    ))
                    break   # found match for this (asset, software) pair
    return hits
