"""
Module   : admap_m1.core.exceptions
Version  : 3.0.0
Dépend   : []

Hiérarchie complète des exceptions pour le module M1 ADMAP.
Chaque exception porte un code snake_case MAJUSCULE identifiant l'erreur
et un dictionnaire optionnel de détails contextuels.
"""
from __future__ import annotations


class ADMAPM1Error(Exception):
    """Exception racine pour toutes les erreurs du module M1.

    Args:
        message: Description humainement lisible de l'erreur.
        code: Identifiant snake_case MAJUSCULE (ex: ``EXTRACTION_ERROR``).
        details: Dictionnaire optionnel de contexte supplémentaire.
    """

    def __init__(
        self,
        message: str,
        code: str = "ADMAP_M1_ERROR",
        details: dict[str, object] | None = None,
    ) -> None:
        self.message: str = message
        self.code: str = code
        self.details: dict[str, object] = details or {}
        super().__init__(self.message)

    def __str__(self) -> str:
        return f"[{self.code}] {self.message}"


# ── Extraction ─────────────────────────────────────────────────────────────


class ExtractionError(ADMAPM1Error):
    """Erreur bloquante d'extraction — le pipeline s'arrête."""

    def __init__(
        self,
        message: str,
        code: str = "EXTRACTION_ERROR",
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message, code, details)


class ExtractionWarning(ADMAPM1Error):
    """Avertissement non-bloquant — le pipeline continue."""

    def __init__(
        self,
        message: str,
        code: str = "EXTRACTION_WARNING",
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message, code, details)


class PEParsingError(ExtractionError):
    """Échec du parsing d'un fichier PE (Portable Executable)."""

    def __init__(
        self,
        message: str,
        code: str = "PE_PARSING_ERROR",
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message, code, details)


class ELFParsingError(ExtractionError):
    """Échec du parsing d'un fichier ELF."""

    def __init__(
        self,
        message: str,
        code: str = "ELF_PARSING_ERROR",
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message, code, details)


class OfficeMacroError(ExtractionError):
    """Échec de l'extraction de macros VBA depuis un document Office."""

    def __init__(
        self,
        message: str,
        code: str = "OFFICE_MACRO_ERROR",
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message, code, details)


# ── Archives ───────────────────────────────────────────────────────────────


class ArchiveExtractionError(ExtractionError):
    """Erreur lors de l'extraction d'une archive (ZIP, TAR, GZIP, 7z)."""

    def __init__(
        self,
        message: str,
        code: str = "ARCHIVE_EXTRACTION_ERROR",
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message, code, details)


class ZipBombError(ArchiveExtractionError):
    """Archive suspecte : taille décompressée excessive (zip-bomb)."""

    def __init__(
        self,
        message: str,
        code: str = "ZIP_BOMB_DETECTED",
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message, code, details)


# ── Déobfuscation ─────────────────────────────────────────────────────────


class DeobfuscationError(ADMAPM1Error):
    """Déobfuscation impossible — aucune technique applicable."""

    def __init__(
        self,
        message: str,
        code: str = "DEOBFUSCATION_ERROR",
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message, code, details)


# ── Validation ─────────────────────────────────────────────────────────────


class ValidationError(ADMAPM1Error):
    """Données d'entrée invalides."""

    def __init__(
        self,
        message: str,
        code: str = "VALIDATION_ERROR",
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message, code, details)


class FileTooLargeError(ValidationError):
    """Fichier dépassant la taille maximale autorisée."""

    def __init__(
        self,
        message: str,
        code: str = "FILE_TOO_LARGE",
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message, code, details)


class UnsupportedFileTypeError(ValidationError):
    """Extension de fichier non supportée par M1."""

    def __init__(
        self,
        message: str,
        code: str = "UNSUPPORTED_FILE_TYPE",
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message, code, details)


# ── VirusTotal ─────────────────────────────────────────────────────────────


class VTRateLimitError(ADMAPM1Error):
    """Limite de taux VirusTotal atteinte (HTTP 429)."""

    def __init__(
        self,
        message: str,
        code: str = "VT_RATE_LIMIT",
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message, code, details)


class VTAPIKeyError(ADMAPM1Error):
    """Clé API VirusTotal invalide (HTTP 401)."""

    def __init__(
        self,
        message: str,
        code: str = "VT_API_KEY_ERROR",
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message, code, details)


# ── Jobs ───────────────────────────────────────────────────────────────────


class JobNotFoundError(ADMAPM1Error):
    """Job d'analyse introuvable dans la queue."""

    def __init__(
        self,
        message: str,
        code: str = "JOB_NOT_FOUND",
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message, code, details)


class JobCancelledError(ADMAPM1Error):
    """Job d'analyse annulé."""

    def __init__(
        self,
        message: str,
        code: str = "JOB_CANCELLED",
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message, code, details)
