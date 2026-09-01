"""Trend analysis across multiple scan snapshots."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from port_exposure_analyzer.parsers import parse_scan_file
from port_exposure_analyzer.policy import (
    ExposureReport,
    evaluate_inventory,
    load_policy,
)


@dataclass
class ExposureTrendPoint:
    """Exposure metrics at a single point in time."""

    source: str
    timestamp_label: str
    aggregate_score: float
    total_matches: int
    tier_counts: dict[str, int]
    host_count: int


@dataclass
class ExposureTrend:
    """Trend line across multiple scans."""

    points: list[ExposureTrendPoint]
    score_delta: float
    match_delta: int
    new_violations: list[str]
    resolved_violations: list[str]


def analyze_trend(
    scan_paths: list[Path | str],
    policy_path: Path | str,
    *,
    labels: list[str] | None = None,
) -> ExposureTrend:
    """Analyze exposure trend across ordered scan snapshots."""
    policy = load_policy(policy_path)
    points: list[ExposureTrendPoint] = []
    reports: list[ExposureReport] = []
    all_violation_sets: list[set[str]] = []

    for i, scan_path in enumerate(scan_paths):
        inv = parse_scan_file(scan_path)
        report = evaluate_inventory(inv, policy)
        reports.append(report)

        violations: set[str] = set()
        for he in report.host_exposures:
            for m in he.matches:
                violations.add(f"{m.host}:{m.port_spec}:{m.rule_id}")
        all_violation_sets.append(violations)

        label = labels[i] if labels and i < len(labels) else Path(scan_path).stem
        points.append(ExposureTrendPoint(
            source=str(scan_path),
            timestamp_label=label,
            aggregate_score=report.aggregate_score,
            total_matches=report.total_matches,
            tier_counts=report.tier_counts,
            host_count=inv.host_count(),
        ))

    if len(reports) < 2:
        return ExposureTrend(
            points=points, score_delta=0.0, match_delta=0,
            new_violations=[], resolved_violations=[],
        )

    first, last = reports[0], reports[-1]
    prev_v, curr_v = all_violation_sets[0], all_violation_sets[-1]

    return ExposureTrend(
        points=points,
        score_delta=round(last.aggregate_score - first.aggregate_score, 2),
        match_delta=last.total_matches - first.total_matches,
        new_violations=sorted(curr_v - prev_v),
        resolved_violations=sorted(prev_v - curr_v),
    )
