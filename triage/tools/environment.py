"""Load data/environment.json and snapshot files into typed dataclasses."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
ENV_FILE      = ROOT / "data" / "environment.json"
SNAPSHOTS_DIR = ROOT / "data" / "snapshots"


@dataclass
class Software:
    name: str
    version: str


@dataclass
class InboundRule:
    source: str   # CIDR string or SG ID like "sg-lb"
    port: int
    protocol: str


@dataclass
class SecurityGroup:
    id: str
    name: str
    inbound: list[InboundRule]


@dataclass
class Control:
    id: str
    type: str            # "WAF" or "IPS"
    mode: str            # "block" or "detect"
    inspects: list[str]              # e.g. ["http", "https"]
    protects_asset_id: str | None    # WAF: the single asset it guards
    between_subnet_ids: list[str]    # IPS: the two subnets it sits between


@dataclass
class Asset:
    id: str
    name: str
    role: str
    subnet_id: str
    private_ip: str
    public_ip: str | None
    software: list[Software]
    listening_ports: list[int]
    security_group_id: str
    criticality: str
    data_held: list[str]


@dataclass
class Environment:
    assets: list[Asset]
    security_groups: list[SecurityGroup]
    controls: list[Control]
    assets_by_id: dict[str, Asset] = field(default_factory=dict)
    assets_by_name: dict[str, Asset] = field(default_factory=dict)
    sg_by_id: dict[str, SecurityGroup] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.assets_by_id   = {a.id:   a  for a in self.assets}
        self.assets_by_name = {a.name: a  for a in self.assets}
        self.sg_by_id       = {sg.id:  sg for sg in self.security_groups}


@dataclass
class CveSnapshot:
    cve_id: str
    nvd:  dict   # full NVD 2.0 response
    kev:  dict   # {in_kev: bool, dateAdded: str|None, requiredAction: str|None}
    epss: dict   # {epss: float, percentile: float}


def load_environment(path: Path = ENV_FILE) -> Environment:
    raw = json.loads(path.read_text())

    assets = [
        Asset(
            id=a["id"],
            name=a["name"],
            role=a.get("role", ""),
            subnet_id=a["subnet_id"],
            private_ip=a["private_ip"],
            public_ip=a.get("public_ip"),
            software=[Software(**s) for s in a.get("software", [])],
            listening_ports=a.get("listening_ports", []),
            security_group_id=a["security_group_id"],
            criticality=a.get("criticality", "medium"),
            data_held=a.get("data_held", []),
        )
        for a in raw["assets"]
    ]

    sgs = [
        SecurityGroup(
            id=sg["id"],
            name=sg["name"],
            inbound=[
                InboundRule(source=r["source"], port=r["port"], protocol=r.get("protocol", "tcp"))
                for r in sg.get("inbound", [])
            ],
        )
        for sg in raw["security_groups"]
    ]

    controls = [
        Control(
            id=c["id"],
            type=c["type"],
            mode=c["mode"],
            inspects=c.get("inspects", []),
            protects_asset_id=c.get("protects_asset_id"),
            between_subnet_ids=c.get("between_subnet_ids", []),
        )
        for c in raw.get("controls", [])
    ]

    return Environment(assets=assets, security_groups=sgs, controls=controls)


def load_cve_snapshot(cve_id: str, snapshots_dir: Path = SNAPSHOTS_DIR) -> CveSnapshot:
    base = snapshots_dir / cve_id

    def _read(name: str) -> dict:
        p = base / name
        return json.loads(p.read_text()) if p.exists() else {}

    return CveSnapshot(
        cve_id=cve_id,
        nvd=_read("nvd.json"),
        kev=_read("kev.json"),
        epss=_read("epss.json"),
    )
