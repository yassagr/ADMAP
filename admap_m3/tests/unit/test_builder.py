"""
Tests unitaires pour le builder de règles YARA (admap_m3.core.builder).
"""
from __future__ import annotations

import pytest

from admap_m3.config import Settings
from admap_m3.core.builder import YaraRuleBuilder
from admap_m3.models.rule import RuleMetadata, YaraRule
from admap_m3.models.token import TokenScore


@pytest.fixture
def builder(settings: Settings) -> YaraRuleBuilder:
    return YaraRuleBuilder(settings=settings)


@pytest.fixture
def sample_metadata() -> RuleMetadata:
    return RuleMetadata(
        description="Test rule description",
        date="2024-01-15",
        corpus_id="test_corpus",
        hash_corpus="abc123def456",
    )


def _make_token_score(
    token: str = "test_token",
    delta_score: float = 0.50,
    confidence: int = 70,
) -> TokenScore:
    return TokenScore(
        token=token,
        delta_score=delta_score,
        confidence=confidence,
        selected=True,
    )


class TestYaraRuleBuilder:
    """Tests du constructeur de règles YARA."""

    def test_rule_name_sanitized(self, builder: YaraRuleBuilder) -> None:
        """Les caractères spéciaux sont remplacés par _ et préfixe ADMAP_M3_."""
        sanitized: str = builder._sanitize_rule_name("ma règle 2024")
        assert sanitized.startswith("ADMAP_M3_")
        assert " " not in sanitized
        assert "è" not in sanitized
        # Seuls alphanum et _ autorisés
        for char in sanitized:
            assert char.isalnum() or char == "_"

    def test_condition_any_for_few_tokens(
        self, builder: YaraRuleBuilder, sample_metadata: RuleMetadata
    ) -> None:
        """≤ 5 tokens → condition = 'any of ($s_*)'."""
        tokens: list[TokenScore] = [_make_token_score(f"token_{i}_xxxxx") for i in range(3)]
        rule: YaraRule = builder.build_rule(tokens, sample_metadata, "test_few")
        assert rule.condition == "any of ($s_*)"

    def test_condition_three_of_for_many_tokens(
        self, builder: YaraRuleBuilder, sample_metadata: RuleMetadata
    ) -> None:
        """> 5 tokens → condition = '3 of ($s_*)'."""
        tokens: list[TokenScore] = [_make_token_score(f"token_{i}_xxxxx") for i in range(8)]
        rule: YaraRule = builder.build_rule(tokens, sample_metadata, "test_many")
        assert rule.condition == "3 of ($s_*)"

    def test_raw_yara_contains_rule_keyword(
        self, builder: YaraRuleBuilder, sample_metadata: RuleMetadata
    ) -> None:
        """raw_yara commence par 'rule ADMAP_M3_'."""
        tokens: list[TokenScore] = [_make_token_score("test_token_long")]
        rule: YaraRule = builder.build_rule(tokens, sample_metadata, "test_rule")
        assert rule.raw_yara.startswith("rule ADMAP_M3_")

    def test_confidence_score_is_mean(
        self, builder: YaraRuleBuilder, sample_metadata: RuleMetadata
    ) -> None:
        """confidence_score = moyenne des confidences des top_tokens."""
        tokens: list[TokenScore] = [
            _make_token_score("token_a_xxxxxx", confidence=60),
            _make_token_score("token_b_xxxxxx", confidence=80),
        ]
        rule: YaraRule = builder.build_rule(tokens, sample_metadata, "test_mean")
        expected_mean: int = int((60 + 80) / 2)
        assert rule.confidence_score == expected_mean
