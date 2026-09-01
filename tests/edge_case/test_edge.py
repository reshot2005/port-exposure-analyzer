"""Edge cases."""

from __future__ import annotations

from pathlib import Path

import pytest

from port_exposure_analyzer.core import AnalysisConfig, analyze_scan

FIXTURES = Path(__file__).resolve().parent.parent.parent / "sample_data"
POLICY = FIXTURES / "exposure_policy.yaml"


class TestEdgeCases:
    def test_reproducible_ids(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SECINTEL_SOURCE_DATE_EPOCH", "1704067200")
        config = AnalysisConfig(base_dir=FIXTURES, policy_path=POLICY)
        r1 = analyze_scan("high_exposure_scan.xml", config=config)
        r2 = analyze_scan("high_exposure_scan.xml", config=config)
        assert r1.report.findings[0].id == r2.report.findings[0].id

    def test_sample_flag(self) -> None:
        config = AnalysisConfig(base_dir=FIXTURES, policy_path=POLICY)
        result = analyze_scan("high_exposure_scan.xml", config=config, is_sample=True)
        assert result.report.is_sample_data is True
