from __future__ import annotations
from pydantic import BaseModel, ConfigDict, Field
from datetime import datetime

class TTPProfile(BaseModel):
    """TTP extrait d'une C2Alert unique."""
    model_config = ConfigDict(frozen=True)

    alert_id: str = Field(description="ID unique de l'alerte source")
    alert_type: str = Field(description="Type d'alerte M2 (beaconing, dga, etc.)")
    techniques: list[str] = Field(description="Liste de techniques MITRE (T1071, T1048...)")
    tactics: list[str] = Field(description="Tactiques déduites des techniques")
    confidence_score: int = Field(ge=0, le=100)
    src_ip: str
    dst_ip: str
    timestamp: datetime
    yara_tags: list[str] = Field(default_factory=list, description="Tags YARA si M3 fourni")
    metadata: dict[str, object] = Field(default_factory=dict)

class TTPVector(BaseModel):
    """Vecteur TF-IDF d'un TTPProfile."""
    model_config = ConfigDict(frozen=True)

    profile_id: str
    vector: dict[str, float] = Field(description="TTP -> score TF-IDF")
    norm: float = Field(description="Norme L2 du vecteur")
