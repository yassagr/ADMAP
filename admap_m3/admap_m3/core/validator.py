"""
Module   : admap_m3.core.validator
Version  : 1.0.0
Dépend   : [yara-python, structlog, admap_m3.models.rule]

Validation syntaxique des règles YARA via ``yara.compile()``.
Aucune exception n'est propagée en cas d'erreur de syntaxe : la règle
est simplement marquée ``compiled=False``.
"""
from __future__ import annotations

import structlog
import yara

from admap_m3.models.rule import YaraRule, YaraRuleSet

logger: structlog.stdlib.BoundLogger = structlog.get_logger()


class YaraValidator:
    """Valide des règles YARA via le compilateur ``yara-python``."""

    def __init__(self) -> None:
        pass

    def validate_rule(self, rule: YaraRule) -> YaraRule:
        """Tente de compiler une règle YARA.

        - Succès → retourne une copie avec ``compiled=True``.
        - ``yara.SyntaxError`` → log le warning, retourne avec
          ``compiled=False``.

        Aucune exception n'est jamais propagée.
        """
        try:
            yara.compile(source=rule.raw_yara)
            logger.debug(
                "yara_rule_compiled",
                rule_id=rule.rule_id,
                rule_name=rule.rule_name,
            )
            return rule.model_copy(update={"compiled": True})
        except yara.SyntaxError as exc:
            logger.warning(
                "yara_compile_syntax_error",
                rule_id=rule.rule_id,
                rule_name=rule.rule_name,
                error=str(exc),
            )
            return rule.model_copy(update={"compiled": False})
        except Exception as exc:
            logger.warning(
                "yara_compile_unexpected_error",
                rule_id=rule.rule_id,
                rule_name=rule.rule_name,
                error=str(exc),
            )
            return rule.model_copy(update={"compiled": False})

    def validate_ruleset(self, ruleset: YaraRuleSet) -> YaraRuleSet:
        """Valide toutes les règles d'un ruleset.

        Met à jour ``compiled_rules`` et ``failed_rules`` dans le
        ``YaraRuleSet`` retourné.
        """
        validated_rules: list[YaraRule] = []
        compiled_count: int = 0
        failed_count: int = 0

        for rule in ruleset.rules:
            validated: YaraRule = self.validate_rule(rule)
            validated_rules.append(validated)
            if validated.compiled:
                compiled_count += 1
            else:
                failed_count += 1

        logger.info(
            "ruleset_validation_complete",
            ruleset_id=ruleset.ruleset_id,
            total=len(validated_rules),
            compiled=compiled_count,
            failed=failed_count,
        )

        return ruleset.model_copy(
            update={
                "rules": validated_rules,
                "compiled_rules": compiled_count,
                "failed_rules": failed_count,
            }
        )
