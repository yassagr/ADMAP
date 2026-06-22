/**
 * Couche API Gateway (BFF, port 9000).
 *
 * Endpoints transverses non liés à un module précis : agrégation de santé et
 * orchestration du pipeline complet. Le client Axios (`./client`) a pour
 * baseURL `http://localhost:9000/api` — les chemins ici sont donc relatifs.
 */
import { apiClient } from "./client";
import type { ModuleId, StatusResponse } from "@/types";

/** Santé agrégée des 5 modules (`GET /api/status`). */
export async function getStatus(): Promise<StatusResponse> {
  const { data } = await apiClient.get<StatusResponse>("/status");
  return data;
}

/** Paramètres du pipeline complet M1 -> M2 -> (M3) -> M4 -> M5. */
export interface FullPipelineParams {
  m1File: File;
  m2Pcap: File;
  enableM3?: boolean;
  m3Malware?: File[];
  m3Benign?: File[];
  topK?: number;
}

/** Réponse (actuellement stub) de `POST /api/pipeline/full`. */
export interface FullPipelineResponse {
  status: string;
  message: string;
  jobs: Record<string, unknown>;
}

/**
 * Lance le pipeline complet côté Gateway.
 *
 * ATTENTION — `POST /api/pipeline/full` est aujourd'hui un STUB
 * (`admap_gateway/routers/pipeline.py`) : il ne déclenche aucune orchestration
 * réelle et renvoie `{ status, message, jobs: {} }`. L'orchestration
 * step-by-step sera pilotée par le front dans le lot Pipeline. Cette fonction
 * fige le contrat d'appel multipart attendu par le Gateway.
 */
export async function runFullPipeline(
  params: FullPipelineParams,
): Promise<FullPipelineResponse> {
  const form = new FormData();
  form.append("m1_file", params.m1File);
  form.append("m2_pcap", params.m2Pcap);
  form.append("enable_m3", String(params.enableM3 ?? false));
  (params.m3Malware ?? []).forEach((f) => form.append("m3_malware", f));
  (params.m3Benign ?? []).forEach((f) => form.append("m3_benign", f));
  form.append("top_k", String(params.topK ?? 3));

  const { data } = await apiClient.post<FullPipelineResponse>(
    "/pipeline/full",
    form,
  );
  return data;
}

/**
 * Construit l'URL WebSocket du Gateway pour suivre un job.
 *
 * Le WS est servi hors `/api` (donc hors baseURL Axios) :
 * `ws://<gateway>/ws/jobs/{id}?module=m{n}`. `gatewayBaseUrl` provient du store
 * (`settings.moduleUrls.gateway`), alimenté par la config statique `GATEWAY_URL`
 * (`@/lib/config`, ex. `http://localhost:9000`).
 */
export function gatewayWsUrl(
  jobId: string,
  module: ModuleId,
  gatewayBaseUrl: string,
): string {
  const wsBase = gatewayBaseUrl.replace(/^http/, "ws").replace(/\/$/, "");
  return `${wsBase}/ws/jobs/${encodeURIComponent(jobId)}?module=${module}`;
}
