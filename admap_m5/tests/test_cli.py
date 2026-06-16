from __future__ import annotations
import pytest
from click.testing import CliRunner
from admap_m5.cli import cli


def test_serve_command_exists():
    assert "serve" in cli.commands


def test_attribute_command_exists():
    assert "attribute" in cli.commands


def test_attribute_missing_required():
    runner = CliRunner()
    result = runner.invoke(cli, ["attribute"])
    assert result.exit_code == 2


def test_attribute_runs_end_to_end(sample_apt_map_report_json, tmp_path):
    report_file = tmp_path / "report.json"
    report_file.write_text(sample_apt_map_report_json, encoding="utf-8")
    
    runner = CliRunner()
    result = runner.invoke(cli, ["attribute", "--apt-map-report", str(report_file)])
    assert result.exit_code == 0
    assert result.output != ""
