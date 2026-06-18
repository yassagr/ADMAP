/**
 * Couche API M5 — Attribution (via Gateway `/api/m5/...`, port 8004).
 *
 * Consomme un `APTMapReport` M4 (obligatoire) + IOCBundle M1 / AlertBundle M2
 * (optionnels) + options JSON sérialisées. Export = pattern commun.
 */
import { apiClient } from "./client";
import type {
  AttributionReport,
  ExportFormat,
  JobAcceptedResponse,
  JobInfo,
} from "@/types";

/** Entrées optionnelles de l'analyse M5. */
export interface M5AnalyzeExtras {
  iocBundle?: File;
  alertBundle?: File;
  /** `AttributionOptions` sérialisé en JSON (champ `Form` `options`). */
  options?: string;
}

/** Soumet un APTMapReport M4 pour attribution (`POST /api/m5/api/v1/analyze`). */
export async function analyzeM5(
  aptMapReport: File,
  extras: M5AnalyzeExtras = {},
): Promise<JobAcceptedResponse> {
  const form = new FormData();
  form.append("apt_map_report", aptMapReport);
  if (extras.iocBundle) form.append("ioc_bundle", extras.iocBundle);
  if (extras.alertBundle) form.append("alert_bundle", extras.alertBundle);
  if (extras.options) form.append("options", extras.options);

  const { data } = await apiClient.post<JobAcceptedResponse>(
    "/m5/api/v1/analyze",
    form,
  );
  return data;
}

/** Statut d'un job M5. */
export async function getM5Job(jobId: string): Promise<JobInfo> {
  const { data } = await apiClient.get<JobInfo>(`/m5/api/v1/jobs/${jobId}`);
  return data;
}

/** Résultat (`AttributionReport`) d'un job M5 terminé. */
export async function getM5JobResult(jobId: string): Promise<AttributionReport> {
  const { data } = await apiClient.get<AttributionReport>(
    `/m5/api/v1/jobs/${jobId}/result`,
  );
  return data;
}

/** Annule / supprime un job M5. */
export async function deleteM5Job(jobId: string): Promise<void> {
  await apiClient.delete(`/m5/api/v1/jobs/${jobId}`);
}

/** Exporte le résultat M5 (format en segment de path) — renvoie un Blob. */
export async function exportM5(
  jobId: string,
  format: ExportFormat,
): Promise<Blob> {
  const { data } = await apiClient.get(`/m5/api/v1/export/${jobId}/${format}`, {
    responseType: "blob",
  });
  return data;
}
