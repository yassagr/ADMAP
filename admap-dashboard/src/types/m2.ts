/**
 * Contrats M2 — C2 Detector (FastAPI port 8001).
 * Source de vérité : `admap_m2/admap_m2/models/alert.py` (AlertBundle v1.0.0).
 */

/** Sévérité d'une alerte, dérivée du score 0-100 (`AlertSeverity`). */
export type AlertSeverity = "critical" | "high" | "medium" | "low" | "info";

/** Type d'alerte C2 détectée (`AlertType`). */
export type AlertType =
  | "beaconing"
  | "dns_tunnel"
  | "dga"
  | "http_c2"
  | "tls_suspect"
  | "irc_c2"
  | "port_scan"
  | "ioc_match"
  | "large_upload"
  | "custom_protocol";

/** Alerte C2 détectée — résultat unitaire de M2 (`C2Alert`, frozen). */
export interface C2Alert {
  id: string;
  alert_type: AlertType;
  severity: AlertSeverity;
  confidence_score: number;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  first_seen: string;
  last_seen: string;
  packet_count: number;
  byte_count: number;
  description: string;
  evidence: string[];
  ioc_matches: string[];
  metadata: Record<string, unknown>;
}

/** Contrat de sortie principal de M2 (`AlertBundle`). */
export interface AlertBundle {
  bundle_id: string;
  pcap_filename: string;
  pcap_sha256: string;
  pcap_size_bytes: number;
  analysis_duration_ms: number;
  total_packets: number;
  total_flows: number;
  alerts: C2Alert[];
  alerts_by_type: Record<string, number>;
  alerts_by_severity: Record<string, number>;
  top_suspicious_ips: string[];
  m1_bundle_id: string | null;
  ioc_hits: number;
  created_at: string;
  pipeline_version: string;
}
