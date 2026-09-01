"""Malformed input."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from port_exposure_analyzer.core import AnalysisConfig, analyze_scan
from port_exposure_analyzer.policy import load_policy

FIXTURES = Path(__file__).resolve().parent.parent.parent / "sample_data"
POLICY = FIXTURES / "exposure_policy.yaml"


class TestMalformed:
    def test_missing_scan_raises(self) -> None:
        config = AnalysisConfig(base_dir=FIXTURES, policy_path=POLICY)
        with pytest.raises(ValueError):
            analyze_scan("missing.xml", config=config)

    def test_missing_policy_raises(self) -> None:
        config = AnalysisConfig(base_dir=FIXTURES, policy_path=Path("missing.yaml"))
        with pytest.raises(ValueError):
            analyze_scan("high_exposure_scan.xml", config=config)

    def test_no_policy_path_raises(self) -> None:
        with pytest.raises(ValueError, match="policy file is required"):
            analyze_scan("high_exposure_scan.xml", config=AnalysisConfig(base_dir=FIXTURES))

    def test_path_traversal_rejected(self) -> None:
        config = AnalysisConfig(base_dir=FIXTURES, policy_path=POLICY)
        with pytest.raises(ValueError, match="path traversal"):
            analyze_scan("../../etc/passwd", config=config)

    def test_invalid_policy_yaml(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("not: a: valid: yaml: [", encoding="utf-8")
        with pytest.raises((ValueError, yaml.YAMLError)):
            load_policy(bad)
