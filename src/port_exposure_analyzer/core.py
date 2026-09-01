"""Core analysis orchestration and findings emission."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from secintel_core import (
    Classification,
    Confidence,
    Evidence,
    Finding,
    InputArtifact,
    Provenance,
    Report,
    Severity,
    build_environment_info,
    canonical_config_hash,
    deterministic_finding_id,
    reproducible_now,
    sha256_file,
)
from secintel_core.security import safe_resolve_path

from port_exposure_analyzer.models import Inventory
from port_exposure_analyzer.parsers import parse_scan_file
from port_exposure_analyzer.policy import (
    ExposureReport,
    ExposureTier,
    HostExposure,
    PolicyMatch,
    evaluate_inventory,
    load_policy,
)
from port_exposure_analyzer.trend import ExposureTrend, analyze_trend

TOOL_NAME = "port-exposure-analyzer"
TOOL_VERSION = "0.1.0"

_TIER_SEVERITY = {
    ExposureTier.CRITICAL: Severity.CRITICAL,
    ExposureTier.HIGH: Severity.HIGH,
    ExposureTier.MEDIUM: Severity.MEDIUM,
    ExposureTier.LOW: Severity.LOW,
    ExposureTier.INFO: Severity.INFO,
}


@dataclass
class AnalysisConfig:
    base_dir: Path = field(default_factory=lambda: Path.cwd())
    max_bytes: int = 50 * 1024 * 1024
    policy_path: Path | None = None
    trend_scans: list[Path] = field(default_factory=list)
    trend_labels: list[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    report: Report
    inventory: Inventory
    exposure: ExposureReport
    trend: ExposureTrend | None = None


def _resolve(base: Path, p: Path | str) -> Path:
    up = Path(p)
    return up.resolve() if up.is_absolute() else safe_resolve_path(base, p)


def analyze_scan(
    input_path: Path | str,
    *,
    config: AnalysisConfig | None = None,
    is_sample: bool = False,
) -> AnalysisResult:
    cfg = config or AnalysisConfig()
    if not cfg.policy_path:
        raise ValueError("policy file is required (--policy)")

    resolved = _resolve(cfg.base_dir, input_path)
    if not resolved.is_file():
        raise ValueError(f"scan file not found: {resolved}")
    policy_resolved = _resolve(cfg.base_dir, cfg.policy_path)
    if not policy_resolved.is_file():
        raise ValueError(f"policy file not found: {policy_resolved}")
    input_hash = sha256_file(resolved, max_bytes=cfg.max_bytes)
    started = reproducible_now()

    inventory = parse_scan_file(resolved, max_bytes=cfg.max_bytes)
    policy = load_policy(policy_resolved)
    exposure = evaluate_inventory(inventory, policy)

    trend: ExposureTrend | None = None
    if cfg.trend_scans:
        trend_paths: list[Path | str] = [_resolve(cfg.base_dir, p) for p in cfg.trend_scans]
        trend = analyze_trend(trend_paths, policy_resolved, labels=cfg.trend_labels or None)

    findings = _build_findings(
        exposure=exposure, inventory=inventory, trend=trend,
        input_hash=input_hash, input_path=str(resolved),
        policy_name=policy.name, started=started,
    )

    config_dict: dict[str, Any] = {
        "policy": str(policy_resolved),
        "trend_scans": [str(p) for p in cfg.trend_scans],
    }
    ended = reproducible_now()

    report = Report(
        provenance=Provenance(
            tool_name=TOOL_NAME, tool_version=TOOL_VERSION,
            config_hash=canonical_config_hash(config_dict),
            inputs=[InputArtifact(path=str(resolved), sha256=input_hash, size_bytes=resolved.stat().st_size)],
            analysis_started_at=started, analysis_ended_at=ended,
            environment=build_environment_info(),
        ),
        findings=findings,
        is_sample_data=is_sample,
        metadata={
            "exposure_summary": {
                "aggregate_score": exposure.aggregate_score,
                "total_matches": exposure.total_matches,
                "tier_counts": exposure.tier_counts,
                "category_counts": exposure.category_counts,
            },
            "host_exposures": [_host_exposure_dict(he) for he in exposure.host_exposures],
            "trend": _trend_dict(trend) if trend else None,
        },
    )
    return AnalysisResult(report=report, inventory=inventory, exposure=exposure, trend=trend)


def _build_findings(
    *,
    exposure: ExposureReport,
    inventory: Inventory,
    trend: ExposureTrend | None,
    input_hash: str,
    input_path: str,
    policy_name: str,
    started: Any,
) -> list[Finding]:
    findings: list[Finding] = []

    for he in exposure.host_exposures:
        for match in he.matches:
            findings.append(_match_to_finding(match, input_hash, input_path, policy_name, started))

    if exposure.aggregate_score > 0:
        findings.append(Finding(
            id=deterministic_finding_id("aggregate-exposure", input_hash, {"policy": policy_name}),
            title=f"Aggregate exposure score: {exposure.aggregate_score}/100 ({policy_name})",
            classification=Classification.DERIVED,
            evidence=[Evidence(
                source=input_path,
                locator={"aggregate_score": exposure.aggregate_score, "policy": policy_name},
                excerpt=f"Matches={exposure.total_matches} tiers={exposure.tier_counts}",
                retrieved_at=started,
            )],
            method="composite tier-weighted exposure scoring",
            why_it_matters="Aggregate score summarizes organizational port exposure posture.",
            plain_language=(
                f"Across {inventory.host_count()} hosts, the average exposure score is "
                f"{exposure.aggregate_score} out of 100."
            ),
            severity=_score_severity(exposure.aggregate_score),
            tags=["exposure", "aggregate"],
            timestamp=started,
        ))

    if trend and (trend.new_violations or trend.resolved_violations):
        findings.extend(_trend_findings(trend, input_hash, input_path, started))

    return findings


def _match_to_finding(
    match: PolicyMatch, input_hash: str, input_path: str, policy_name: str, started: Any,
) -> Finding:
    confidence_map = {
        ExposureTier.CRITICAL: 0.95,
        ExposureTier.HIGH: 0.88,
        ExposureTier.MEDIUM: 0.75,
        ExposureTier.LOW: 0.60,
        ExposureTier.INFO: 0.40,
    }
    score = confidence_map.get(match.tier, 0.5)
    return Finding(
        id=deterministic_finding_id(
            "policy-violation", input_hash,
            {"host": match.host, "port": match.port_spec, "rule": match.rule_id},
        ),
        title=f"[{match.tier.value.upper()}] {match.rule_id} on {match.host}:{match.port_spec}",
        classification=Classification.INFERRED,
        confidence=Confidence(
            score=score,
            rationale=match.rationale or f"Policy rule '{match.rule_id}' matched {match.port_spec}",
            supporting_indicators=[
                f"tier={match.tier.value}",
                f"service={match.service_fingerprint}",
                f"policy={policy_name}",
            ],
            contradicting_indicators=[],
        ),
        evidence=[Evidence(
            source=input_path,
            locator={"host": match.host, "port_spec": match.port_spec, "rule_id": match.rule_id},
            excerpt=match.service_fingerprint,
            retrieved_at=started,
        )],
        method=f"policy rule: {match.rule_id}",
        why_it_matters=match.rationale or "Exposed service matches a policy-defined risk rule.",
        plain_language=(
            f"Port {match.port_spec} on {match.host} triggered rule '{match.rule_id}' "
            f"({match.tier.value} risk). {match.remediation}"
        ).strip(),
        limitations=["Policy-based inference; verify business justification before remediation."],
        severity=_TIER_SEVERITY.get(match.tier, Severity.MEDIUM),
        tags=["exposure", match.tier.value, *match.categories],
        timestamp=started,
    )


def _trend_findings(
    trend: ExposureTrend, input_hash: str, input_path: str, started: Any,
) -> list[Finding]:
    findings: list[Finding] = []
    if trend.new_violations:
        findings.append(Finding(
            id=deterministic_finding_id("trend-new", input_hash, {"count": len(trend.new_violations)}),
            title=f"Exposure increased: {len(trend.new_violations)} new policy violations",
            classification=Classification.CORRELATED,
            confidence=Confidence(
                score=0.90,
                rationale=(
                    f"Score delta {trend.score_delta:+.1f}, "
                    f"{len(trend.new_violations)} new violations vs baseline trend"
                ),
                supporting_indicators=trend.new_violations[:5],
            ),
            evidence=[Evidence(source=input_path, locator={"trend": "new_violations"}, retrieved_at=started)],
            method="multi-snapshot exposure trend analysis",
            why_it_matters="Increasing exposure may indicate configuration drift or new deployments.",
            plain_language=f"{len(trend.new_violations)} new port exposure violations since the first scan.",
            severity=Severity.HIGH if trend.score_delta > 10 else Severity.MEDIUM,
            tags=["trend", "exposure-increase"],
            timestamp=started,
        ))
    if trend.resolved_violations:
        findings.append(Finding(
            id=deterministic_finding_id(
                "trend-resolved", input_hash, {"count": len(trend.resolved_violations)}
            ),
            title=f"Exposure decreased: {len(trend.resolved_violations)} violations resolved",
            classification=Classification.CORRELATED,
            confidence=Confidence(
                score=0.88,
                rationale=f"Score delta {trend.score_delta:+.1f}, violations resolved in latest scan",
                supporting_indicators=trend.resolved_violations[:5],
            ),
            evidence=[Evidence(
                source=input_path, locator={"trend": "resolved_violations"}, retrieved_at=started,
            )],
            method="multi-snapshot exposure trend analysis",
            why_it_matters="Resolved violations indicate successful remediation or decommissioning.",
            plain_language=(
                f"{len(trend.resolved_violations)} previously flagged exposures are no longer present."
            ),
            severity=Severity.INFO,
            tags=["trend", "exposure-decrease"],
            timestamp=started,
        ))
    return findings


def _score_severity(score: float) -> Severity:
    if score >= 75:
        return Severity.CRITICAL
    if score >= 50:
        return Severity.HIGH
    if score >= 25:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


def _host_exposure_dict(he: HostExposure) -> dict[str, Any]:
    return {
        "address": he.address, "score": he.score, "tier": he.tier.value,
        "categories": he.categories,
        "violations": [m.rule_id for m in he.matches],
    }


def _trend_dict(trend: ExposureTrend) -> dict[str, Any]:
    return {
        "points": [
            {"label": p.timestamp_label, "score": p.aggregate_score, "matches": p.total_matches}
            for p in trend.points
        ],
        "score_delta": trend.score_delta,
        "match_delta": trend.match_delta,
        "new_violations": trend.new_violations,
        "resolved_violations": trend.resolved_violations,
    }
