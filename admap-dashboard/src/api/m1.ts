/**
 * Couche API M1 — IOC Extractor (via Gateway `/api/m1/...`, microservice port 8000).
 *
 * DIVERGENCE notable : l'export M1 n'utilise PAS le pattern commun
 * `/export/{id}/{fmt}`. C'est `GET /export/{id}?format=...` (format en QUERY
 * PARAM) avec des noms de formats propres (`stix21`, `openioc`, `misp`,
 * `cytomic`) — pas de `json`/`csv`/`all`.
 */
import { apiClient } from "./client";
import type { IOCBundle, JobAcceptedResponse, JobInfo } from "@/types";

/** Formats d'export CTI réellement supportés par M1. */
export type M1ExportFormat = "stix21" | "openioc" | "misp" | "cytomic";

/** Options de l'analyse M1 (champs `Form` du endpoint). */
export interface M1AnalyzeOptions {
  enableVt?: boolean;
  enableDeobfuscation?: boolean;
}

/** Soumet un fichier binaire à analyser (`POST /api/m1/api/v1/analyze`). */
export async function analyzeM1(
  file: File,
  options: M1AnalyzeOptions = {},
): Promise<JobAcceptedResponse> {
  const form = new FormData();
  form.append("file", file);
  form.append("enable_vt", String(options.enableVt ?? false));
  form.append("enable_deobfuscation", String(options.enableDeobfuscation ?? true));

  const { data } = await apiClient.post<JobAcceptedResponse>(
    "/m1/api/v1/analyze",
    form,
  );
  return data;
}

/** Statut d'un job M1. */
export async function getM1Job(jobId: string): Promise<JobInfo> {
  const { data } = await apiClient.get<JobInfo>(`/m1/api/v1/jobs/${jobId}`);
  return data;
}

/** Résultat (`IOCBundle`) d'un job M1 terminé. */
export async function getM1JobResult(jobId: string): Promise<IOCBundle> {
  const { data } = await apiClient.get<IOCBundle>(
    `/m1/api/v1/jobs/${jobId}/result`,
  );
  return data;
}

/** Annule / supprime un job M1. */
export async function deleteM1Job(jobId: string): Promise<void> {
  await apiClient.delete(`/m1/api/v1/jobs/${jobId}`);
}

/** Exporte le résultat M1 (format en query param) — renvoie un Blob téléchargeable. */
export async function exportM1(
  jobId: string,
  format: M1ExportFormat,
): Promise<Blob> {
  const { data } = await apiClient.get(`/m1/api/v1/export/${jobId}`, {
    params: { format },
    responseType: "blob",
  });
  return data;
}
