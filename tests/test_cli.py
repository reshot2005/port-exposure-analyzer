"""CLI tests."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from port_exposure_analyzer.cli import app

FIXTURES = Path(__file__).resolve().parent.parent / "sample_data"
runner = CliRunner()


class TestCLI:
    def test_analyze_json(self) -> None:
        result = runner.invoke(app, [
            "analyze", str(FIXTURES / "high_exposure_scan.xml"),
            "--policy", str(FIXTURES / "exposure_policy.yaml"), "--json",
        ])
        assert result.exit_code == 0
        assert "INFERRED" in result.stdout

    def test_missing_policy_fails(self) -> None:
        result = runner.invoke(app, ["analyze", str(FIXTURES / "high_exposure_scan.xml"), "--json"])
        assert result.exit_code != 0
