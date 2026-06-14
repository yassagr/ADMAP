"""
Tests unitaires pour le validateur YARA (admap_m3.core.validator).
"""
from __future__ import annotations

import pytest

from admap_m3.core.validator import YaraValidator
from admap_m3.models.rule import RuleMetadata, YaraRule, YaraRuleSet


@pytest.fixture
def validator() -> YaraValidator:
    return YaraValidator()


@pytest.fixture
def valid_yara_rule() -> YaraRule:
    """Règle YARA syntaxiquement correcte."""
    raw: str = (
        'rule ADMAP_M3_test_valid {\n'
        '    meta:\n'
        '        author = "test"\n'
        '    strings:\n'
        '        $s_0 = "CreateRemoteThread" ascii wide nocase\n'
        '    condition:\n'
        '        any of ($s_*)\n'
        '}'
    )
    return YaraRule(
        rule_id="ADMAP_M3_test001",
        rule_name="ADMAP_M3_test_valid",
        metadata=RuleMetadata(
            description="Test valid rule",
            date="2024-01-15",
            corpus_id="test",
            hash_corpus="abc123",
        ),
        strings=['$s_0 = "CreateRemoteThread" ascii wide nocase'],
        condition="any of ($s_*)",
        raw_yara=raw,
        compiled=False,
        token_count=1,
        confidence_score=70,
    )


@pytest.fixture
def invalid_yara_rule() -> YaraRule:
    """Règle YARA syntaxiquement incorrecte."""
    raw: str = (
        'rule ADMAP_M3_test_invalid {\n'
        '    strings:\n'
        '        $s_0 = "test"\n'
        '    condition:\n'
        '        INVALID SYNTAX HERE @@@\n'
        '}'
    )
    return YaraRule(
        rule_id="ADMAP_M3_test002",
        rule_name="ADMAP_M3_test_invalid",
        metadata=RuleMetadata(
            description="Test invalid rule",
            date="2024-01-15",
            corpus_id="test",
            hash_corpus="abc123",
        ),
        strings=['$s_0 = "test"'],
        condition="INVALID SYNTAX HERE @@@",
        raw_yara=raw,
        compiled=False,
        token_count=1,
        confidence_score=50,
    )


class TestYaraValidator:
    """Tests du validateur YARA."""

    def test_valid_rule_compiles(
        self, validator: YaraValidator, valid_yara_rule: YaraRule
    ) -> None:
        """Une règle syntaxiquement correcte → compiled=True."""
        result: YaraRule = validator.validate_rule(valid_yara_rule)
        assert result.compiled is True

    def test_invalid_rule_does_not_raise(
        self, validator: YaraValidator, invalid_yara_rule: YaraRule
    ) -> None:
        """Une règle malformée → compiled=False, PAS d'exception levée."""
        result: YaraRule = validator.validate_rule(invalid_yara_rule)
        assert result.compiled is False

    def test_ruleset_counts_updated(
        self,
        validator: YaraValidator,
        valid_yara_rule: YaraRule,
        invalid_yara_rule: YaraRule,
    ) -> None:
        """validate_ruleset() met à jour compiled_rules et failed_rules."""
        ruleset: YaraRuleSet = YaraRuleSet(
            ruleset_id="RS_test",
            corpus_id="test",
            rules=[valid_yara_rule, invalid_yara_rule],
            total_rules=2,
            compiled_rules=0,
            failed_rules=0,
            generation_duration_ms=100.0,
        )

        validated: YaraRuleSet = validator.validate_ruleset(ruleset)
        assert validated.compiled_rules == 1
        assert validated.failed_rules == 1
        assert validated.total_rules == 2
