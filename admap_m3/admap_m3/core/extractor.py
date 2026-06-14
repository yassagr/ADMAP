"""
Module   : admap_m3.core.extractor
Version  : 1.0.0
Dépend   : [admap_m3.config, admap_m3.analyzers, structlog]

Façade d'extraction de features binaires.  Détecte le type de fichier
par magic bytes et délègue au bon ``BaseAnalyzer``.
"""
from __future__ import annotations

import hashlib
import os

import structlog

from admap_m3.analyzers.elf_analyzer import ELFAnalyzer
from admap_m3.analyzers.generic_analyzer import GenericBinaryAnalyzer
from admap_m3.analyzers.pe_analyzer import PEAnalyzer
from admap_m3.analyzers.text_analyzer import TextAnalyzer
from admap_m3.config import Settings
from admap_m3.models.corpus import CorpusFile, FileLabel, FileType

logger: structlog.stdlib.BoundLogger = structlog.get_logger()


class BinaryFeatureExtractor:
    """Détecte le type de fichier et extrait les features via l'analyzer adapté.

    Le fichier est **toujours** lu en mode ``rb``.  Aucune exécution du
    binaire n'est effectuée.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings: Settings = settings
        self._pe_analyzer: PEAnalyzer = PEAnalyzer(
            min_token_length=settings.min_token_length,
            ngram_size=settings.ngram_size,
        )
        self._elf_analyzer: ELFAnalyzer = ELFAnalyzer(
            min_token_length=settings.min_token_length,
            ngram_size=settings.ngram_size,
        )
        self._text_analyzer: TextAnalyzer = TextAnalyzer(
            min_token_length=settings.min_token_length,
        )
        self._generic_analyzer: GenericBinaryAnalyzer = GenericBinaryAnalyzer(
            min_token_length=settings.min_token_length,
            ngram_size=settings.ngram_size,
        )

    def extract(self, file_path: str, label: FileLabel) -> tuple[CorpusFile, list[str]]:
        """Détecte le type, extrait les features, retourne ``(CorpusFile, tokens)``.

        Raises:
            FileNotFoundError: Si le fichier n'existe pas.
            ValueError: Si la taille dépasse ``max_file_size_bytes``.
        """
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Fichier introuvable : {file_path}")

        file_size: int = os.path.getsize(file_path)
        if file_size > self._settings.max_file_size_bytes:
            raise ValueError(
                f"Fichier trop volumineux ({file_size} bytes > "
                f"{self._settings.max_file_size_bytes} bytes max) : {file_path}"
            )

        with open(file_path, "rb") as fh:
            data: bytes = fh.read()

        # Détection du type
        file_type: FileType = self._detect_type(data)

        # SHA-256
        sha256: str = hashlib.sha256(data).hexdigest()

        # Extraction via le bon analyzer
        tokens: list[str]
        if file_type == FileType.PE:
            tokens = self._pe_analyzer.extract_tokens(data, file_path)
        elif file_type == FileType.ELF:
            tokens = self._elf_analyzer.extract_tokens(data, file_path)
        elif file_type == FileType.TEXT:
            tokens = self._text_analyzer.extract_tokens(data, file_path)
        else:
            tokens = self._generic_analyzer.extract_tokens(data, file_path)

        corpus_file: CorpusFile = CorpusFile(
            file_path=file_path,
            label=label,
            file_type=file_type,
            sha256=sha256,
            size_bytes=file_size,
        )

        logger.info(
            "feature_extraction_complete",
            file_path=file_path,
            file_type=file_type.value,
            label=label.value,
            token_count=len(tokens),
            sha256=sha256,
        )

        return corpus_file, tokens

    def _detect_type(self, data: bytes) -> FileType:
        """Détection du type de fichier par magic bytes.

        - ``b"MZ"`` → PE
        - ``b"\\x7fELF"`` → ELF
        - Sinon, tente un décodage UTF-8 sur les 512 premiers bytes →
          si OK → TEXT
        - Sinon → GENERIC
        """
        if data[:2] == b"MZ":
            return FileType.PE
        if data[:4] == b"\x7fELF":
            return FileType.ELF

        # Heuristique texte : les 512 premiers bytes se décodent-ils en UTF-8 ?
        sample: bytes = data[:512]
        try:
            sample.decode("utf-8")
            return FileType.TEXT
        except UnicodeDecodeError:
            return FileType.GENERIC
