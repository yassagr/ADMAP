/**
 * Couche API M3 — YARA Signature Generator (via Gateway `/api/m3/...`, port 8002).
 *
 * DIVERGENCE notable : pas de `analyze`. M3 expose `POST /api/v1/generate` qui
 * prend DEUX listes de fichiers (corpus malware + corpus bénin) et un IOCBundle
 * M1 optionnel. L'export ajoute le format `yar` (règles YARA brutes) au pattern
 * commun.
 */
import { apiClient } from "./client";
import type { JobAcceptedResponse, JobInfo, YaraRuleSet } from "@/types";

/** Formats d'export réellement supportés par M3 (`yar` en plus du commun). */
export type M3ExportFormat = "yar" | "json" | "stix" | "csv" | "all";

/**
 * Lance la génération de règles YARA (`POST /api/m3/api/v1/generate`).
 * `malwareFiles` et `benignFiles` sont obligatoires (corpus discriminant).
 */
export async function generateM3(
  malwareFiles: File[],
  benignFiles: File[],
  m1Bundle?: File,
): Promise<JobAcceptedResponse> {
  const form = new FormData();
  malwareFiles.forEach((f) => form.append("malware_files", f));
  benignFiles.forEach((f) => form.append("benign_files", f));
  if (m1Bundle) form.append("m1_bundle", m1Bundle);

  const { data } = await apiClient.post<JobAcceptedResponse>(
    "/m3/api/v1/generate",
    form,
  );
  return data;
}

/** Statut d'un job M3. */
export async function getM3Job(jobId: string): Promise<JobInfo> {
  const { data } = await apiClient.get<JobInfo>(`/m3/api/v1/jobs/${jobId}`);
  return data;
}

/** Résultat (`YaraRuleSet`) d'un job M3 terminé. */
export async function getM3JobResult(jobId: string): Promise<YaraRuleSet> {
  const { data } = await apiClient.get<YaraRuleSet>(
    `/m3/api/v1/jobs/${jobId}/result`,
  );
  return data;
}

/** Annule / supprime un job M3. */
export async function deleteM3Job(jobId: string): Promise<void> {
  await apiClient.delete(`/m3/api/v1/jobs/${jobId}`);
}

/** Exporte le résultat M3 (format en segment de path) — renvoie un Blob. */
export async function exportM3(
  jobId: string,
  format: M3ExportFormat,
): Promise<Blob> {
  const { data } = await apiClient.get(`/m3/api/v1/export/${jobId}/${format}`, {
    responseType: "blob",
  });
  return data;
}
