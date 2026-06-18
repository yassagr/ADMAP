/**
 * Contrats M5 — Attribution (FastAPI port 8004).
 * Source de vérité : `admap_m5/admap_m5/models/output.py` (AttributionReport v1.0.0).
 */

/** Acteur APT candidat avec son score de confiance (`APTCandidate`, frozen). */
export interface APTCandidate {
  /** 1 = plus probable. */
  rank: number;
  apt_name: string;
  apt_id: string;
  confidence_score: number;
  /** Probabilité brute XGBoost (0-1). */
  xgb_probability: number;
  /** Similarité cosinus TTP (0-1). */
  cosine_similarity: number;
  matched_techniques: string[];
  matched_tactics: string[];
  matched_yara_tags: string[];
  matched_ips: string[];
  evidence_summary: string;
  mitre_group_url: string;
}

/** Résultat d'attribution pour un cluster (`AttributionResult`, frozen). */
export interface AttributionResult {
  cluster_id: string;
  cluster_label: number;
  candidates: APTCandidate[];
  feature_vector_size: number;
  /** "xgboost+cosine" | "cosine_only" | "fallback". */
  analysis_method: string;
}

/** Contrat de sortie principal de M5 (`AttributionReport`, frozen). */
export interface AttributionReport {
  report_id: string;
  source_report_id: string;
  results: AttributionResult[];
  top_global_candidate: APTCandidate | null;
  total_clusters_analyzed: number;
  noise_clusters_skipped: number;
  analysis_duration_seconds: number;
  options_used: Record<string, unknown>;
  created_at: string;
  version: string;
  module: string;
}
