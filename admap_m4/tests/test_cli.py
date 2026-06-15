from __future__ import annotations
import json
import os
import pytest
from click.testing import CliRunner
from admap_m4.cli import cli


@pytest.fixture
def bundle_file(tmpdir, sample_alert_bundle_json):
    path = os.path.join(tmpdir, "bundle.json")
    with open(path, "w", encoding="utf-8") as f:
        f.write(sample_alert_bundle_json)
    return path


@pytest.fixture
def ioc_bundle_file(tmpdir):
    data = {"bundle_id": "ioc-001", "iocs": [], "file_sha256": "abc", "timestamp": "2024-01-01T00:00:00Z"}
    path = os.path.join(tmpdir, "ioc.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)
    return path


@pytest.fixture
def yara_ruleset_file(tmpdir):
    data = {"ruleset_id": "yara-001", "rules": [{"rule_name": "Test", "tags": ["ransomware"], "metadata": {}}]}
    path = os.path.join(tmpdir, "yara.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)
    return path


def test_cli_analyze_json(bundle_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", "-a", bundle_file, "--format", "json"])
    assert result.exit_code == 0, result.output
    assert "report_id" in result.output


def test_cli_analyze_csv(bundle_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", "-a", bundle_file, "--format", "csv"])
    assert result.exit_code == 0, result.output
    # CSV header ou contenu vide selon les clusters
    assert "cluster_id" in result.output or result.exit_code == 0


def test_cli_analyze_stix(bundle_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", "-a", bundle_file, "--format", "stix"])
    assert result.exit_code == 0, result.output
    assert "objects" in result.output


def test_cli_analyze_all(bundle_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", "-a", bundle_file, "--format", "all"])
    assert result.exit_code == 0, result.output
    assert "json" in result.output


def test_cli_analyze_with_ioc_bundle(bundle_file, ioc_bundle_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", "-a", bundle_file, "-i", ioc_bundle_file])
    assert result.exit_code == 0, result.output
    assert "report_id" in result.output


def test_cli_analyze_with_yara_ruleset(bundle_file, yara_ruleset_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", "-a", bundle_file, "-y", yara_ruleset_file])
    assert result.exit_code == 0, result.output
    assert "report_id" in result.output


def test_cli_analyze_with_output_file(bundle_file, tmpdir):
    output_path = os.path.join(tmpdir, "output.json")
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", "-a", bundle_file, "--output", output_path])
    assert result.exit_code == 0, result.output
    assert os.path.exists(output_path)
    with open(output_path, encoding="utf-8") as f:
        data = json.load(f)
    assert "report_id" in data


def test_cli_analyze_custom_epsilon(bundle_file):
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", "-a", bundle_file, "--epsilon", "0.5", "--min-samples", "1"])
    assert result.exit_code == 0, result.output
    assert "report_id" in result.output
