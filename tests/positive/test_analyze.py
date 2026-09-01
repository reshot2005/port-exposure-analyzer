"""Positive tests."""

from __future__ import annotations

from pathlib import Path

from secintel_core.schema import Classification, Severity

from port_exposure_analyzer.core import AnalysisConfig, analyze_scan

FIXTURES = Path(__file__).resolve().parent.parent.parent / "sample_data"
POLICY = FIXTURES / "exposure_policy.yaml"


class TestPositive:
    def test_detects_critical_database_exposure(self) -> None:
        config = AnalysisConfig(base_dir=FIXTURES, policy_path=POLICY)
        result = analyze_scan("high_exposure_scan.xml", config=config)
        critical = [f for f in result.report.findings if f.severity == Severity.CRITICAL]
        assert any("database" in f.title.lower() or "3306" in f.title for f in critical)

    def test_detects_telnet_critical(self) -> None:
        config = AnalysisConfig(base_dir=FIXTURES, policy_path=POLICY)
        result = analyze_scan("high_exposure_scan.xml", config=config)
        assert any("telnet" in f.title.lower() for f in result.report.findings)

    def test_aggregate_score_computed(self) -> None:
        config = AnalysisConfig(base_dir=FIXTURES, policy_path=POLICY)
        result = analyze_scan("high_exposure_scan.xml", config=config)
        assert result.exposure.aggregate_score > 0
        summary = result.report.metadata["exposure_summary"]
        assert summary["total_matches"] > 0

    def test_inferred_findings_have_confidence(self) -> None:
        config = AnalysisConfig(base_dir=FIXTURES, policy_path=POLICY)
        result = analyze_scan("high_exposure_scan.xml", config=config)
        inferred = [f for f in result.report.findings if f.classification == Classification.INFERRED]
        assert all(f.confidence is not None and f.confidence.rationale for f in inferred)

    def test_trend_detects_new_violations(self) -> None:
        config = AnalysisConfig(
            base_dir=FIXTURES, policy_path=POLICY,
            trend_scans=[Path("trend_baseline.xml"), Path("high_exposure_scan.xml")],
            trend_labels=["week1", "week2"],
        )
        result = analyze_scan("high_exposure_scan.xml", config=config)
        assert result.trend is not None
        assert len(result.trend.new_violations) > 0
        trend_findings = [f for f in result.report.findings if "trend" in f.tags]
        assert len(trend_findings) >= 1
