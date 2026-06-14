"""
Tests unitaires additionnels pour couvrir les exporteurs et le worker.
"""
from __future__ import annotations

import os
import tempfile
from typing import Any

from admap_m3.exporters.csv_exporter import CSVExporter
from admap_m3.exporters.json_exporter import JSONExporter
from admap_m3.exporters.stix_exporter import STIXExporter
from admap_m3.exporters.yara_exporter import YaraFileExporter
from admap_m3.models.rule import RuleMetadata, TLPLevel, YaraRule, YaraRuleSet


def _make_ruleset(compiled: bool = True, confidence: int = 80) -> YaraRuleSet:
    """Fabrique un YaraRuleSet de test."""
    raw: str = (
        'rule ADMAP_M3_test {\n'
        '    meta:\n'
        '        author = "test"\n'
        '    strings:\n'
        '        $s_0 = "CreateRemoteThread" ascii wide nocase\n'
        '    condition:\n'
        '        any of ($s_*)\n'
        '}'
    )
    rule: YaraRule = YaraRule(
        rule_id="ADMAP_M3_exp_test",
        rule_name="ADMAP_M3_test",
        metadata=RuleMetadata(
            description="Test export rule",
            date="2024-01-15",
            corpus_id="export_test",
            hash_corpus="abc123",
            malware_family="TestFamily",
            mitre_attack=["T1059", "T1071"],
        ),
        strings=['$s_0 = "CreateRemoteThread" ascii wide nocase'],
        condition="any of ($s_*)",
        raw_yara=raw,
        compiled=compiled,
        token_count=1,
        confidence_score=confidence,
    )

    return YaraRuleSet(
        ruleset_id="RS_export_test",
        corpus_id="export_test",
        rules=[rule],
        total_rules=1,
        compiled_rules=1 if compiled else 0,
        failed_rules=0 if compiled else 1,
        generation_duration_ms=42.0,
    )


class TestYaraFileExporter:
    """Tests du YaraFileExporter."""

    def test_exporter_name(self) -> None:
        exporter: YaraFileExporter = YaraFileExporter()
        assert exporter.exporter_name == "YaraFileExporter"

    def test_export_creates_file(self) -> None:
        exporter: YaraFileExporter = YaraFileExporter()
        ruleset: YaraRuleSet = _make_ruleset()
        output: str = os.path.join(tempfile.mkdtemp(), "test.yar")

        result: dict[str, Any] = exporter.export(ruleset, output)
        assert result["status"] == "ok"
        assert os.path.isfile(output)

        content: str = open(output, encoding="utf-8").read()
        assert "ADMAP M3" in content
        assert "ADMAP_M3_test" in content

    def test_export_error_returns_dict(self) -> None:
        exporter: YaraFileExporter = YaraFileExporter()
        ruleset: YaraRuleSet = _make_ruleset()
        result: dict[str, Any] = exporter.export(ruleset, "/nonexistent/dir/file.yar")
        assert result["status"] == "error"


class TestJSONExporter:
    """Tests du JSONExporter."""

    def test_exporter_name(self) -> None:
        exporter: JSONExporter = JSONExporter()
        assert exporter.exporter_name == "JSONExporter"

    def test_export_creates_json(self) -> None:
        exporter: JSONExporter = JSONExporter()
        ruleset: YaraRuleSet = _make_ruleset()
        output: str = os.path.join(tempfile.mkdtemp(), "test.json")

        result: dict[str, Any] = exporter.export(ruleset, output)
        assert result["status"] == "ok"
        assert os.path.isfile(output)


class TestSTIXExporter:
    """Tests du STIXExporter."""

    def test_exporter_name(self) -> None:
        exporter: STIXExporter = STIXExporter()
        assert exporter.exporter_name == "STIXExporter"

    def test_export_creates_stix(self) -> None:
        exporter: STIXExporter = STIXExporter()
        ruleset: YaraRuleSet = _make_ruleset(confidence=80)
        output: str = os.path.join(tempfile.mkdtemp(), "test_stix.json")

        result: dict[str, Any] = exporter.export(ruleset, output)
        assert result["status"] == "ok"
        assert os.path.isfile(output)

        import json

        with open(output, encoding="utf-8") as fh:
            bundle: dict[str, Any] = json.load(fh)
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"
        # At least identity + 1 indicator
        assert len(bundle["objects"]) >= 2

    def test_low_confidence_excluded(self) -> None:
        """Rules with confidence < 60 are excluded from STIX."""
        exporter: STIXExporter = STIXExporter()
        ruleset: YaraRuleSet = _make_ruleset(confidence=30)
        output: str = os.path.join(tempfile.mkdtemp(), "test_low.json")

        result: dict[str, Any] = exporter.export(ruleset, output)
        assert result["status"] == "ok"

        import json

        with open(output, encoding="utf-8") as fh:
            bundle: dict[str, Any] = json.load(fh)
        # Only identity, no indicators (confidence too low)
        assert len(bundle["objects"]) == 1


class TestCSVExporter:
    """Tests du CSVExporter."""

    def test_exporter_name(self) -> None:
        exporter: CSVExporter = CSVExporter()
        assert exporter.exporter_name == "CSVExporter"

    def test_export_creates_csv(self) -> None:
        exporter: CSVExporter = CSVExporter()
        ruleset: YaraRuleSet = _make_ruleset()
        output: str = os.path.join(tempfile.mkdtemp(), "test.csv")

        result: dict[str, Any] = exporter.export(ruleset, output)
        assert result["status"] == "ok"
        assert os.path.isfile(output)

        content: str = open(output, encoding="utf-8").read()
        # Check header columns
        assert "rule_id" in content
        assert "malware_family" in content
        assert "T1059|T1071" in content
