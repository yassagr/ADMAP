"""
Module   : admap_m3.models.rule
Version  : 1.0.0
Dépend   : [pydantic]

Modèles pour les règles YARA générées et les ensembles de règles.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class TLPLevel(str, Enum):
    """Niveaux TLP (Traffic Light Protocol) pour le partage d'informations."""

    WHITE = "TLP:WHITE"
    GREEN = "TLP:GREEN"
    AMBER = "TLP:AMBER"
    RED = "TLP:RED"


class RuleMetadata(BaseModel, frozen=True):
    """Métadonnées intégrées dans une règle YARA.

    Attributes:
        author: Auteur de la règle.
        description: Description lisible de la règle.
        date: Date de génération au format ``YYYY-MM-DD``.
        version: Version de la règle.
        tlp: Niveau TLP par défaut.
        corpus_id: Identifiant du corpus utilisé.
        malware_family: Famille de malware ciblée (optionnel).
        mitre_attack: Liste des identifiants MITRE ATT&CK associés.
        hash_corpus: SHA-256 du corpus utilisé pour la génération.
    """

    author: str = "ADMAP Platform M3"
    description: str
    date: str
    version: str = "1.0"
    tlp: TLPLevel = TLPLevel.AMBER
    corpus_id: str
    malware_family: str | None = None
    mitre_attack: list[str] = Field(default_factory=list)
    hash_corpus: str


class YaraRule(BaseModel, frozen=True):
    """Représentation complète d'une règle YARA générée.

    Attributes:
        rule_id: Identifiant unique (ex: ``ADMAP_M3_abc12345``).
        rule_name: Identifiant YARA valide (alphanum + ``_``).
        metadata: Métadonnées de la règle.
        strings: Lignes ``$s_N = ...`` de la section strings.
        condition: Expression de la section condition.
        raw_yara: Texte YARA complet et compilable.
        compiled: ``True`` si ``yara.compile()`` a réussi.
        token_count: Nombre de tokens/strings dans la règle.
        confidence_score: Score de confiance global (0-100).
    """

    rule_id: str
    rule_name: str
    metadata: RuleMetadata
    strings: list[str]
    condition: str
    raw_yara: str
    compiled: bool
    token_count: int
    confidence_score: int


class YaraRuleSet(BaseModel, frozen=True):
    """Ensemble de règles YARA produites pour un corpus donné.

    Attributes:
        ruleset_id: Identifiant unique de l'ensemble.
        corpus_id: Identifiant du corpus analysé.
        rules: Liste des règles générées.
        total_rules: Nombre total de règles.
        compiled_rules: Nombre de règles compilées avec succès.
        failed_rules: Nombre de règles dont la compilation a échoué.
        generation_duration_ms: Durée totale de la génération en ms.
        created_at: Horodatage de création.
    """

    ruleset_id: str
    corpus_id: str
    rules: list[YaraRule]
    total_rules: int
    compiled_rules: int
    failed_rules: int
    generation_duration_ms: float
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
