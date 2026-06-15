from __future__ import annotations
from click.testing import CliRunner
from admap_m4.cli import cli
import json
import os

def test_cli_analyze_command(tmpdir, sample_alert_bundle_json):
    runner = CliRunner()
    bundle_path = os.path.join(tmpdir, "bundle.json")
    with open(bundle_path, "w") as f:
        f.write(sample_alert_bundle_json)

    result = runner.invoke(cli, ["analyze", "-a", bundle_path])
    assert result.exit_code == 0
    assert "report_id" in result.output
