from __future__ import annotations
from pydantic import BaseModel, ConfigDict, Field, field_validator
import json


class AttributionOptions(BaseModel):
    model_config = ConfigDict(frozen=True)
    top_k: int = Field(default=3, ge=1, le=10)
    min_confidence: float = Field(default=10.0, ge=0.0, le=100.0)
    use_cosine_similarity: bool = True
    use_xgboost: bool = True
    include_noise_clusters: bool = False  # Exclure clusters label=-1 par défaut


class AttributionRequest(BaseModel):
    model_config = ConfigDict(frozen=True)
    # Entrée principale — APTMapReport JSON de M4
    apt_map_report_json: str = Field(..., description="APTMapReport JSON de M4 (obligatoire)")
    # Entrées optionnelles
    ioc_bundle_json: str | None = Field(default=None, description="IOCBundle JSON de M1 (optionnel)")
    alert_bundle_json: str | None = Field(default=None, description="AlertBundle JSON de M2 (optionnel)")
    options: AttributionOptions = Field(default_factory=AttributionOptions)

    @field_validator("apt_map_report_json")
    @classmethod
    def validate_apt_map_report_json(cls, v: str) -> str:
        try:
            data = json.loads(v)
            if "cluster_bundle" not in data:
                raise ValueError("apt_map_report_json must contain 'cluster_bundle'")
        except json.JSONDecodeError as e:
            raise ValueError(f"apt_map_report_json is not valid JSON: {e}")
        return v
