from __future__ import annotations
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class APTCandidate(BaseModel):
    """Un acteur APT candidat avec son score de confiance."""
    model_config = ConfigDict(frozen=True)
    rank: int                               # 1 = plus probable
    apt_name: str                           # ex: "APT28", "Lazarus Group"
    apt_id: str                             # ex: "G0007"
    confidence_score: float                 # 0-100, calculé dynamiquement
    xgb_probability: float                  # Probabilité brute XGBoost (0-1)
    cosine_similarity: float                # Similarité cosinus TTP (0-1)
    matched_techniques: list[str]           # Techniques MITRE en commun
    matched_tactics: list[str]              # Tactiques en commun
    matched_yara_tags: list[str]            # Tags YARA matchés
    matched_ips: list[str]                  # IPs communes avec KB
    evidence_summary: str                   # Résumé textuel des preuves
    mitre_group_url: str                    # URL MITRE ATT&CK du groupe


class AttributionResult(BaseModel):
    """Résultat d'attribution pour un cluster."""
    model_config = ConfigDict(frozen=True)
    cluster_id: str
    cluster_label: int
    candidates: list[APTCandidate]          # top-k candidats triés par score
    feature_vector_size: int                # Taille du vecteur de features utilisé
    analysis_method: str                    # "xgboost+cosine" | "cosine_only" | "fallback"


class AttributionReport(BaseModel):
    """Rapport final M5 — sortie principale du module."""
    model_config = ConfigDict(frozen=True)
    report_id: str
    source_report_id: str                   # report_id de l'APTMapReport M4
    results: list[AttributionResult]        # Un résultat par cluster analysé
    top_global_candidate: APTCandidate | None  # Candidat le plus probable globalement
    total_clusters_analyzed: int
    noise_clusters_skipped: int
    analysis_duration_seconds: float
    options_used: dict[str, object]
    created_at: datetime = Field(default_factory=datetime.utcnow)
    version: str = "1.0.0"
    module: str = "M5-Attribution"
