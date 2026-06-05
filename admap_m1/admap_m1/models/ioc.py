"""
Module   : admap_m1.models.ioc
Version  : 3.0.0
Dépend   : [pydantic]

Modèles Pydantic v2 pour les IOCs, métadonnées fichier, résultats VT
et bundle d'analyse complet. Contrat d'interface stable de M1.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class IOCType(str, Enum):
    """Types d'indicateurs de compromission supportés par M1."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    HASH_SSDEEP = "hash_ssdeep"
    HASH_IMPHASH = "hash_imphash"
    FILEPATH = "filepath"
    FILENAME = "filename"
    REGISTRY_KEY = "registry_key"
    MUTEX = "mutex"
    COMMAND = "command"
    # NE PAS AJOUTER YARA_MATCH — appartient à M3


class IOCConfidenceLevel(str, Enum):
    """Niveau de confiance dérivé du score numérique 0-100."""

    CONFIRMED = "confirmed"  # score 80-100
    HIGH = "high"            # score 60-79
    MEDIUM = "medium"        # score 40-59
    LOW = "low"              # score 20-39
    NOISE = "noise"          # score 0-19


class VTResult(BaseModel):
    """Résultat d'enrichissement VirusTotal pour un IOC."""

    value: str
    ioc_type: str
    found: bool
    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    harmless: int = 0
    confidence_score: int = 0
    verdict: str = "UNKNOWN"  # "MALVEILLANT"|"SUSPECT"|"BÉNIN"|"INCONNU"
    file_type: str | None = None
    country: str | None = None
    as_owner: str | None = None
    reputation: int | None = None
    vt_link: str | None = None
    error: str | None = None


class ExtractionContext(BaseModel):
    """Contexte d'extraction spécifique pour un extracteur (ex: VBA, PE)."""

    vba_autoexec_detected: bool = False
    vba_shell_detected: bool = False
    is_pe_import: bool = False
    in_high_entropy_section: bool = False
    near_suspicious_api: bool = False
    near_execution_verb: bool = False


class RawIOC(BaseModel):
    """IOC brut retourné par un extracteur, avant scoring et filtrage."""

    type: IOCType
    value: str
    context_snippet: str = ""          # 64 chars autour du match dans le texte
    source_offset: int | None = None   # Offset exact dans le fichier binaire
    extraction_method: str = ""        # "pe_imports"|"regex_text"|"vba_macro"|...
    section_name: str | None = None    # Section PE d'origine si applicable
    entropy_context: float | None = None
    in_decoded_layer: bool = False     # True si extrait après déobfuscation


class IOC(BaseModel):
    """IOC finalisé après scoring, filtrage et defanging."""

    model_config = ConfigDict(frozen=True)

    id: UUID = Field(default_factory=uuid4)
    type: IOCType
    value: str               # Valeur réelle, toujours refangée
    value_defanged: str      # Ex: hxxps[://]evil[.]com
    confidence_score: int    # 0-100
    confidence_level: IOCConfidenceLevel
    context_snippet: str
    source_offset: int | None = None
    entropy_context: float | None = None
    tags: list[str] = Field(default_factory=list)
    extraction_method: str
    scoring_reasons: list[str] = Field(default_factory=list)  # Audit trail
    vt_result: VTResult | None = None
    first_seen: datetime = Field(default_factory=datetime.utcnow)

    @field_validator("confidence_score")
    @classmethod
    def validate_score(cls, v: int) -> int:
        """Valide que le score est entre 0 et 100.

        Args:
            v: Score de confiance à valider.

        Returns:
            Le score validé.

        Raises:
            ValueError: Si le score est hors limites.
        """
        if not 0 <= v <= 100:
            raise ValueError("confidence_score must be between 0 and 100")
        return v


class FileHashes(BaseModel):
    """Empreintes cryptographiques d'un fichier analysé."""

    md5: str
    sha1: str
    sha256: str
    ssdeep: str | None = None


class PESection(BaseModel):
    """Informations sur une section PE."""

    name: str
    virtual_address: str
    raw_size: int
    entropy: float
    characteristics: list[str]
    is_suspicious: bool  # entropy > 7.0 ou nom anormal


class PEInfo(BaseModel):
    """Métadonnées détaillées d'un fichier Portable Executable."""

    compilation_timestamp: datetime | None = None
    entry_point: str
    sections: list[PESection] = Field(default_factory=list)
    imports: dict[str, list[str]] = Field(default_factory=dict)
    exports: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    is_dotnet: bool = False
    is_64bit: bool = False
    suspicious_imports: list[str] = Field(default_factory=list)
    import_suspicion_score: int = 0  # 0-100


class FileMetadata(BaseModel):
    """Métadonnées complètes d'un fichier analysé par M1."""

    filename: str
    filesize: int
    filetype: str  # "PE32"|"PE64"|"ELF64"|"Office/OLE"|"ZIP"|"text/plain"
    magic_bytes: str  # Hex des 16 premiers octets
    hashes: FileHashes
    entropy: float
    is_packed: bool = False
    packer_name: str | None = None  # "UPX"|"MPRESS"|"PyInstaller"|None
    pe_info: PEInfo | None = None
    extracted_from: str | None = None  # "archive.zip/inner/mal.exe"


class AnalysisStats(BaseModel):
    """Statistiques d'une analyse M1 complète."""

    total_iocs: int = 0
    by_type: dict[str, int] = Field(default_factory=dict)
    filtered_out: int = 0
    deobfuscation_layers: int = 0
    vt_enriched: int = 0
    duration_ms: int = 0


class IOCBundle(BaseModel):
    """Résultat complet d'une analyse M1 — contrat d'interface principal."""

    bundle_id: UUID = Field(default_factory=uuid4)
    metadata: FileMetadata
    iocs: list[IOC] = Field(default_factory=list)
    # PAS de yara_matches — appartient à M3
    analysis_stats: AnalysisStats = Field(default_factory=AnalysisStats)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    pipeline_version: str = "3.0.0"
