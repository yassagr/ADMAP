/**
 * Couche API M4 — APT Mapper / Clustering (via Gateway `/api/m4/...`, port 8003).
 *
 * Consomme un `AlertBundle` M2 (obligatoire) + IOCBundle M1 / YaraRuleSet M3
 * (optionnels) + options JSON sérialisées. Export = pattern commun.
 */
import { apiClient } from "./client";
import type {
  APTMapReport,
  ExportFormat,
  JobAcceptedResponse,
  JobInfo,
} from "@/types";

/** Entrées optionnelles de l'analyse M4. */
export interface M4AnalyzeExtras {
  iocBundle?: File;
  yaraRuleset?: File;
  /** `AnalysisOptions` sérialisé en JSON (champ `Form` `options`). */
  options?: string;
}

/** Soumet un AlertBundle M2 pour clustering APT (`POST /api/m4/api/v1/analyze`). */
export async function analyzeM4(
  alertBundle: File,
  extras: M4AnalyzeExtras = {},
): Promise<JobAcceptedResponse> {
  const form = new FormData();
  form.append("alert_bundle", alertBundle);
  if (extras.iocBundle) form.append("ioc_bundle", extras.iocBundle);
  if (extras.yaraRuleset) form.append("yara_ruleset", extras.yaraRuleset);
  if (extras.options) form.append("options", extras.options);

  const { data } = await apiClient.post<JobAcceptedResponse>(
    "/m4/api/v1/analyze",
    form,
  );
  return data;
}

/** Statut d'un job M4. */
export async function getM4Job(jobId: string): Promise<JobInfo> {
  const { data } = await apiClient.get<JobInfo>(`/m4/api/v1/jobs/${jobId}`);
  return data;
}

/** Résultat (`APTMapReport`) d'un job M4 terminé. */
export async function getM4JobResult(jobId: string): Promise<APTMapReport> {
  const { data } = await apiClient.get<APTMapReport>(
    `/m4/api/v1/jobs/${jobId}/result`,
  );
  return data;
}

/** Annule / supprime un job M4. */
export async function deleteM4Job(jobId: string): Promise<void> {
  await apiClient.delete(`/m4/api/v1/jobs/${jobId}`);
}

/** Exporte le résultat M4 (format en segment de path) — renvoie un Blob. */
export async function exportM4(
  jobId: string,
  format: ExportFormat,
): Promise<Blob> {
  const { data } = await apiClient.get(`/m4/api/v1/export/${jobId}/${format}`, {
    responseType: "blob",
  });
  return data;
}
