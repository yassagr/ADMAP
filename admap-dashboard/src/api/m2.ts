/**
 * Couche API M2 — C2 Detector (via Gateway `/api/m2/...`, microservice port 8001).
 *
 * Analyse de PCAP : champ fichier `file` + nombreux toggles de détecteurs et un
 * chemin optionnel vers un IOCBundle M1 pour la corrélation. Export = pattern
 * commun `/export/{id}/{json|csv|stix|all}`.
 */
import { apiClient } from "./client";
import type {
  AlertBundle,
  ExportFormat,
  JobAcceptedResponse,
  JobInfo,
} from "@/types";

/** Toggles de détecteurs + paramètres de corrélation (champs `Form` du endpoint). */
export interface M2AnalyzeOptions {
  enableBeaconing?: boolean;
  enableDga?: boolean;
  enableDnsTunnel?: boolean;
  enableHttpC2?: boolean;
  enableTls?: boolean;
  enableIrc?: boolean;
  enablePortScan?: boolean;
  /** Chemin serveur d'un IOCBundle M1 pour corrélation (vide = pas de corrélation). */
  m1BundlePath?: string;
  minConfidence?: number;
}

/** Soumet un PCAP à analyser (`POST /api/m2/api/v1/analyze`). */
export async function analyzeM2(
  file: File,
  options: M2AnalyzeOptions = {},
): Promise<JobAcceptedResponse> {
  const form = new FormData();
  form.append("file", file);
  form.append("enable_beaconing", String(options.enableBeaconing ?? true));
  form.append("enable_dga", String(options.enableDga ?? true));
  form.append("enable_dns_tunnel", String(options.enableDnsTunnel ?? true));
  form.append("enable_http_c2", String(options.enableHttpC2 ?? true));
  form.append("enable_tls", String(options.enableTls ?? true));
  form.append("enable_irc", String(options.enableIrc ?? true));
  form.append("enable_port_scan", String(options.enablePortScan ?? true));
  form.append("m1_bundle_path", options.m1BundlePath ?? "");
  form.append("min_confidence", String(options.minConfidence ?? 20));

  const { data } = await apiClient.post<JobAcceptedResponse>(
    "/m2/api/v1/analyze",
    form,
  );
  return data;
}

/** Statut d'un job M2. */
export async function getM2Job(jobId: string): Promise<JobInfo> {
  const { data } = await apiClient.get<JobInfo>(`/m2/api/v1/jobs/${jobId}`);
  return data;
}

/** Résultat (`AlertBundle`) d'un job M2 terminé. */
export async function getM2JobResult(jobId: string): Promise<AlertBundle> {
  const { data } = await apiClient.get<AlertBundle>(
    `/m2/api/v1/jobs/${jobId}/result`,
  );
  return data;
}

/** Annule / supprime un job M2. */
export async function deleteM2Job(jobId: string): Promise<void> {
  await apiClient.delete(`/m2/api/v1/jobs/${jobId}`);
}

/** Exporte le résultat M2 (format en segment de path) — renvoie un Blob. */
export async function exportM2(
  jobId: string,
  format: ExportFormat,
): Promise<Blob> {
  const { data } = await apiClient.get(`/m2/api/v1/export/${jobId}/${format}`, {
    responseType: "blob",
  });
  return data;
}
