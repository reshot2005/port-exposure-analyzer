"""Negative tests."""

from __future__ import annotations

from pathlib import Path

from port_exposure_analyzer.core import AnalysisConfig, analyze_scan

FIXTURES = Path(__file__).resolve().parent.parent.parent / "sample_data"
POLICY = FIXTURES / "exposure_policy.yaml"


class TestNegative:
    def test_clean_scan_no_violations(self) -> None:
        config = AnalysisConfig(base_dir=FIXTURES, policy_path=POLICY)
        result = analyze_scan("clean_scan.xml", config=config)
        violations = [f for f in result.report.findings if f.classification.value == "INFERRED"]
        assert len(violations) == 0
        assert result.exposure.total_matches == 0
