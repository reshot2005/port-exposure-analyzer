"""Scan inventory models."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Service:
    port: int
    protocol: str
    state: str
    name: str = ""
    product: str = ""
    version: str = ""
    banner: str = ""

    @property
    def fingerprint(self) -> str:
        parts = [self.name, self.product, self.version]
        return " ".join(p for p in parts if p).strip() or f"{self.name}/{self.port}"

    def port_spec(self) -> str:
        return f"{self.port}/{self.protocol}"


@dataclass
class Host:
    address: str
    address_type: str = "ipv4"
    hostname: str = ""
    status: str = "up"
    os_name: str = ""
    services: list[Service] = field(default_factory=list)
    exposure_score: float = 0.0
    exposure_tier: str = "none"
    policy_violations: list[str] = field(default_factory=list)

    @property
    def open_services(self) -> list[Service]:
        return [s for s in self.services if s.state == "open"]


@dataclass
class Inventory:
    hosts: list[Host] = field(default_factory=list)
    scan_sources: list[str] = field(default_factory=list)

    def host_count(self) -> int:
        return len(self.hosts)

    def total_open_ports(self) -> int:
        return sum(len(h.open_services) for h in self.hosts)
