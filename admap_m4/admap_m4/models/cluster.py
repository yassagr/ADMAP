from __future__ import annotations
from pydantic import BaseModel, ConfigDict, Field
from datetime import datetime

class CampaignCluster(BaseModel):
    """Cluster de campagnes APT détectées."""
    model_config = ConfigDict(frozen=True)

    cluster_id: str = Field(description="Identifiant unique du cluster (uuid4)")
    cluster_label: int = Field(description="Label DBSCAN (-1 = bruit/outlier)")
    member_profile_ids: list[str] = Field(description="IDs des TTPProfiles membres")
    dominant_techniques: list[str] = Field(description="Techniques les plus fréquentes (top 5)")
    dominant_tactics: list[str] = Field(description="Tactiques couvrant le cluster")
    confidence_score: float = Field(ge=0.0, le=100.0, description="Score calculé dynamiquement")
    involved_ips: list[str] = Field(description="IPs source et destination uniques du cluster")
    yara_tags: list[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    metadata: dict[str, object] = Field(default_factory=dict)

class ClusterBundle(BaseModel):
    """Ensemble de tous les clusters produits par M4."""
    model_config = ConfigDict(frozen=True)

    bundle_id: str
    source_bundle_id: str = Field(description="bundle_id de l'AlertBundle M2 source")
    clusters: list[CampaignCluster]
    noise_profile_ids: list[str] = Field(description="Profils DBSCAN label=-1")
    total_profiles: int
    total_clusters: int
    noise_count: int
    created_at: datetime
