"""
Module   : admap_m3.core.builder
Version  : 1.0.0
Dépend   : [admap_m3.config, admap_m3.models, structlog]

Construction de règles YARA syntaxiquement correctes depuis les tokens
sélectionnés par le scorer.
"""
from __future__ import annotations

import re
import uuid

import structlog

from admap_m3.config import Settings
from admap_m3.models.rule import RuleMetadata, YaraRule
from admap_m3.models.token import TokenScore

logger: structlog.stdlib.BoundLogger = structlog.get_logger()

# Regex pour nettoyer un nom de règle YARA
_INVALID_RULE_CHAR_RE: re.Pattern[str] = re.compile(r"[^a-zA-Z0-9_]")


class YaraRuleBuilder:
    """Construit des règles YARA compilables depuis les top tokens scorés."""

    def __init__(self, settings: Settings) -> None:
        self._settings: Settings = settings

    def build_rule(
        self,
        top_tokens: list[TokenScore],
        metadata: RuleMetadata,
        rule_name: str,
    ) -> YaraRule:
        """Construit une règle YARA syntaxiquement correcte.

        Format des strings selon ``token_type`` (inféré par préfixe/contenu) :
        - ``string``       → ``$s_N = "token_value" ascii wide nocase``
        - ``hex_pattern``  → ``$s_N = { AA BB CC ... }``
        - ``opcode_ngram`` → ``$s_N = { XX XX XX XX }``

        Condition :
        - ``any of ($s_*)`` si ``len(top_tokens)`` ≤ 5
        - ``3 of ($s_*)``   sinon

        Args:
            top_tokens: Tokens sélectionnés par le scorer.
            metadata: Métadonnées YARA.
            rule_name: Nom brut de la règle (sera sanitisé).

        Returns:
            ``YaraRule`` avec ``compiled=False`` (la validation est
            effectuée par ``YaraValidator``).
        """
        sanitized_name: str = self._sanitize_rule_name(rule_name)
        rule_id: str = f"ADMAP_M3_{uuid.uuid4().hex[:8]}"

        # Construire les lignes de strings
        string_lines: list[str] = []
        for idx, token_score in enumerate(top_tokens):
            line: str = self._format_string_line(idx, token_score)
            string_lines.append(line)

        # Condition
        condition: str
        if len(top_tokens) <= 5:
            condition = "any of ($s_*)"
        else:
            condition = "3 of ($s_*)"

        # Assembler les métadonnées YARA
        meta_lines: list[str] = [
            f'        author = "{metadata.author}"',
            f'        description = "{metadata.description}"',
            f'        date = "{metadata.date}"',
            f'        version = "{metadata.version}"',
            f'        tlp = "{metadata.tlp.value}"',
            f'        corpus_id = "{metadata.corpus_id}"',
            f'        hash_corpus = "{metadata.hash_corpus}"',
        ]
        if metadata.malware_family:
            meta_lines.append(f'        malware_family = "{metadata.malware_family}"')
        if metadata.mitre_attack:
            mitre_str: str = ", ".join(metadata.mitre_attack)
            meta_lines.append(f'        mitre_attack = "{mitre_str}"')

        # Assembler le texte YARA complet
        meta_block: str = "\n".join(meta_lines)
        strings_block: str = "\n".join(f"        {line}" for line in string_lines)
        raw_yara: str = (
            f"rule {sanitized_name} {{\n"
            f"    meta:\n"
            f"{meta_block}\n"
            f"    strings:\n"
            f"{strings_block}\n"
            f"    condition:\n"
            f"        {condition}\n"
            f"}}"
        )

        # Confidence score = moyenne des confidences
        confidence_score: int = (
            int(sum(t.confidence for t in top_tokens) / len(top_tokens))
            if top_tokens
            else 0
        )

        rule: YaraRule = YaraRule(
            rule_id=rule_id,
            rule_name=sanitized_name,
            metadata=metadata,
            strings=string_lines,
            condition=condition,
            raw_yara=raw_yara,
            compiled=False,
            token_count=len(top_tokens),
            confidence_score=confidence_score,
        )

        logger.info(
            "yara_rule_built",
            rule_id=rule_id,
            rule_name=sanitized_name,
            token_count=len(top_tokens),
            confidence_score=confidence_score,
        )

        return rule

    def _sanitize_rule_name(self, name: str) -> str:
        """Remplace tout caractère non ``[a-zA-Z0-9_]`` par ``_``.

        Préfixe automatique ``ADMAP_M3_``.
        """
        cleaned: str = _INVALID_RULE_CHAR_RE.sub("_", name)
        if not cleaned.startswith("ADMAP_M3_"):
            cleaned = f"ADMAP_M3_{cleaned}"
        return cleaned

    def _format_string_line(self, idx: int, token_score: TokenScore) -> str:
        """Formate une ligne de la section ``strings`` selon le type de token."""
        token: str = token_score.token

        # Déterminer le type heuristiquement
        hex_chars: set[str] = set("0123456789ABCDEFabcdef")
        is_pure_hex: bool = all(c in hex_chars for c in token) and len(token) >= 2

        if is_pure_hex:
            # Formater en hex pattern : { AA BB CC ... }
            hex_pairs: str = " ".join(
                token[i : i + 2].upper() for i in range(0, len(token), 2)
            )
            return f"$s_{idx} = {{ {hex_pairs} }}"

        # String classique : échapper les guillemets et backslashes
        escaped: str = token.replace("\\", "\\\\").replace('"', '\\"')
        return f'$s_{idx} = "{escaped}" ascii wide nocase'
