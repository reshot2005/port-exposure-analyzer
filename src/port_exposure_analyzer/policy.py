"""YAML exposure policy engine with composite risk scoring."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

import yaml
from secintel_core.security import bounded_read_file

from port_exposure_analyzer.models import Host, Inventory, Service


class ExposureTier(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


TIER_WEIGHTS: dict[str, float] = {
    ExposureTier.CRITICAL: 1.0,
    ExposureTier.HIGH: 0.75,
    ExposureTier.MEDIUM: 0.5,
    ExposureTier.LOW: 0.25,
    ExposureTier.INFO: 0.1,
}


@dataclass
class PortRule:
    """Policy rule matching a port/service combination."""

    id: str
    tier: ExposureTier
    ports: list[int] = field(default_factory=list)
    port_ranges: list[tuple[int, int]] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    products: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    rationale: str = ""
    remediation: str = ""
    cwe: list[str] = field(default_factory=list)

    def matches(self, svc: Service) -> bool:
        if self.protocols and svc.protocol.lower() not in {p.lower() for p in self.protocols}:
            return False

        port_match = False
        if self.ports and svc.port in self.ports:
            port_match = True
        if self.port_ranges and any(lo <= svc.port <= hi for lo, hi in self.port_ranges):
            port_match = True
        if (self.ports or self.port_ranges) and not port_match:
            return False

        if self.services and not any(s.lower() in svc.name.lower() for s in self.services):
            return False
        if self.products and not any(p.lower() in svc.product.lower() for p in self.products):
            return False

        return bool(self.ports or self.port_ranges or self.services or self.products)


@dataclass
class PolicyMatch:
    """A policy rule match against a specific service."""

    rule_id: str
    tier: ExposureTier
    host: str
    port_spec: str
    service_fingerprint: str
    rationale: str
    remediation: str
    categories: list[str]
    cwe: list[str]
    score_contribution: float


@dataclass
class ExposurePolicy:
    """Complete exposure policy document."""

    version: str
    name: str
    rules: list[PortRule]
    tier_weights: dict[str, float] = field(default_factory=lambda: dict(TIER_WEIGHTS))
    max_score: float = 100.0


@dataclass
class HostExposure:
    """Computed exposure for a single host."""

    address: str
    score: float
    tier: ExposureTier
    matches: list[PolicyMatch]
    categories: list[str]


@dataclass
class ExposureReport:
    """Full exposure analysis across inventory."""

    host_exposures: list[HostExposure]
    total_matches: int
    tier_counts: dict[str, int]
    category_counts: dict[str, int]
    aggregate_score: float


def load_policy(path: Path | str) -> ExposurePolicy:
    """Load exposure policy from YAML."""
    resolved = Path(path)
    raw = bounded_read_file(resolved, max_bytes=2 * 1024 * 1024)
    data = yaml.safe_load(raw.decode("utf-8"))
    if not isinstance(data, dict):
        msg = "policy file must be a YAML mapping"
        raise ValueError(msg)

    rules: list[PortRule] = []
    for entry in data.get("rules", []):
        if not isinstance(entry, dict):
            continue
        port_ranges: list[tuple[int, int]] = []
        for pr in entry.get("port_ranges", []):
            if isinstance(pr, list) and len(pr) == 2:
                port_ranges.append((int(pr[0]), int(pr[1])))

        tier_str = str(entry.get("tier", "medium")).lower()
        try:
            tier = ExposureTier(tier_str)
        except ValueError:
            tier = ExposureTier.MEDIUM

        rules.append(PortRule(
            id=str(entry.get("id", "unnamed")),
            tier=tier,
            ports=[int(p) for p in entry.get("ports", [])],
            port_ranges=port_ranges,
            protocols=[str(p) for p in entry.get("protocols", [])],
            services=[str(s) for s in entry.get("services", [])],
            products=[str(p) for p in entry.get("products", [])],
            categories=[str(c) for c in entry.get("categories", [])],
            rationale=str(entry.get("rationale", "")),
            remediation=str(entry.get("remediation", "")),
            cwe=[str(c) for c in entry.get("cwe", [])],
        ))

    weights = data.get("tier_weights", TIER_WEIGHTS)
    return ExposurePolicy(
        version=str(data.get("version", "1.0")),
        name=str(data.get("name", "default")),
        rules=rules,
        tier_weights={str(k): float(v) for k, v in weights.items()},
    )


def evaluate_inventory(inventory: Inventory, policy: ExposurePolicy) -> ExposureReport:
    """Evaluate all hosts against policy and compute exposure scores."""
    host_exposures: list[HostExposure] = []
    tier_counts: dict[str, int] = {t.value: 0 for t in ExposureTier}
    category_counts: dict[str, int] = {}

    for host in inventory.hosts:
        matches = _evaluate_host(host, policy)
        score, tier = _compute_host_score(matches, policy)
        categories = sorted({c for m in matches for c in m.categories})

        host.exposure_score = score
        host.exposure_tier = tier.value
        host.policy_violations = [m.rule_id for m in matches]

        host_exposures.append(HostExposure(
            address=host.address,
            score=score,
            tier=tier,
            matches=matches,
            categories=categories,
        ))
        tier_counts[tier.value] = tier_counts.get(tier.value, 0) + 1
        for cat in categories:
            category_counts[cat] = category_counts.get(cat, 0) + 1

    total_matches = sum(len(h.matches) for h in host_exposures)
    agg = sum(h.score for h in host_exposures) / max(len(host_exposures), 1)

    return ExposureReport(
        host_exposures=host_exposures,
        total_matches=total_matches,
        tier_counts=tier_counts,
        category_counts=category_counts,
        aggregate_score=round(agg, 2),
    )


def _evaluate_host(host: Host, policy: ExposurePolicy) -> list[PolicyMatch]:
    matches: list[PolicyMatch] = []
    seen: set[tuple[str, str]] = set()

    for svc in host.open_services:
        for rule in policy.rules:
            if not rule.matches(svc):
                continue
            key = (rule.id, svc.port_spec())
            if key in seen:
                continue
            seen.add(key)
            weight = policy.tier_weights.get(rule.tier.value, 0.5)
            matches.append(PolicyMatch(
                rule_id=rule.id,
                tier=rule.tier,
                host=host.address,
                port_spec=svc.port_spec(),
                service_fingerprint=svc.fingerprint,
                rationale=rule.rationale,
                remediation=rule.remediation,
                categories=rule.categories,
                cwe=rule.cwe,
                score_contribution=weight,
            ))
    return matches


def _compute_host_score(
    matches: list[PolicyMatch], policy: ExposurePolicy
) -> tuple[float, ExposureTier]:
    if not matches:
        return 0.0, ExposureTier.INFO

    raw = sum(m.score_contribution for m in matches)
    normalized = min(raw / max(len(matches), 1), 1.0) * policy.max_score
    highest = max(matches, key=lambda m: policy.tier_weights.get(m.tier.value, 0))
    return round(normalized, 2), highest.tier
