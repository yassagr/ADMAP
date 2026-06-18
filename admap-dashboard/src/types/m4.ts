/**
 * Contrats M4 — APT Mapper / Clustering (FastAPI port 8003).
 * Source de vérité : `admap_m4/admap_m4/models/cluster.py` + `report.py`.
 */

/** Cluster de campagnes APT (`CampaignCluster`, frozen). */
export interface CampaignCluster {
  cluster_id: string;
  /** Label DBSCAN ; -1 = bruit/outlier. */
  cluster_label: number;
  member_profile_ids: string[];
  dominant_techniques: string[];
  dominant_tactics: string[];
  confidence_score: number;
  involved_ips: string[];
  yara_tags: string[];
  first_seen: string;
  last_seen: string;
  metadata: Record<string, unknown>;
}

/** Ensemble de tous les clusters produits par M4 (`ClusterBundle`, frozen). */
export interface ClusterBundle {
  bundle_id: string;
  source_bundle_id: string;
  clusters: CampaignCluster[];
  noise_profile_ids: string[];
  total_profiles: number;
  total_clusters: number;
  noise_count: number;
  created_at: string;
}

/** Options d'analyse M4 (`AnalysisOptions`). */
export interface AnalysisOptions {
  dbscan_epsilon: number;
  dbscan_min_samples: number;
  min_confidence_score: number;
  min_techniques_per_profile: number;
  include_yara_tags: boolean;
  include_ioc_enrichment: boolean;
  export_format: string[];
}

/** Couverture MITRE : tactique -> liste de techniques couvertes. */
export type MitreCoverage = Record<string, string[]>;

/**
 * Contrat de sortie principal de M4 (`APTMapReport`, frozen).
 * `top_techniques` / `top_tactics` sont des tuples Python `(label, count)`,
 * sérialisés en JSON comme des paires `[string, number]`.
 */
export interface APTMapReport {
  report_id: string;
  source_bundle_id: string;
  cluster_bundle: ClusterBundle;
  mitre_coverage: MitreCoverage;
  top_techniques: Array<[string, number]>;
  top_tactics: Array<[string, number]>;
  campaign_count: number;
  noise_count: number;
  analysis_duration_seconds: number;
  options_used: AnalysisOptions;
  created_at: string;
  version: string;
}
