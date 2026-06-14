"""
Module   : admap_m3.models.corpus
Version  : 1.0.0
Dépend   : [pydantic]

Modèles décrivant les fichiers du corpus et leurs statistiques.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class FileLabel(str, Enum):
    """Étiquette d'un fichier dans le corpus."""

    MALWARE = "malware"
    BENIGN = "benign"


class FileType(str, Enum):
    """Type de fichier détecté par magic bytes."""

    PE = "pe"
    ELF = "elf"
    TEXT = "text"
    GENERIC = "generic"


class CorpusFile(BaseModel, frozen=True):
    """Représentation d'un fichier ajouté au corpus d'analyse."""

    file_path: str
    label: FileLabel
    file_type: FileType
    sha256: str
    size_bytes: int
    added_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CorpusStats(BaseModel, frozen=True):
    """Statistiques agrégées d'un corpus."""

    total_files: int
    malware_count: int
    benign_count: int
    pe_count: int
    elf_count: int
    text_count: int
    generic_count: int
    total_tokens_malware: int
    total_tokens_benign: int
    unique_tokens_malware: int
    unique_tokens_benign: int


class CorpusSummary(BaseModel, frozen=True):
    """Résumé complet d'un corpus incluant fichiers et statistiques."""

    corpus_id: str
    files: list[CorpusFile]
    stats: CorpusStats
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
