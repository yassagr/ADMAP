/**
 * Types transverses partagés par tous les modules ADMAP.
 *
 * Dérivés des contrats réels exposés par le Gateway (port 9000) et les
 * microservices M1-M5. Les dates sont sérialisées en JSON comme des chaînes
 * IS-8601 côté Pydantic, donc typées `string` ici.
 */

/** Identifiant canonique d'un microservice ADMAP. */
export type ModuleId = "m1" | "m2" | "m3" | "m4" | "m5";

export const MODULE_IDS: readonly ModuleId[] = ["m1", "m2", "m3", "m4", "m5"];

/**
 * Statut d'un job asynchrone.
 *
 * ATTENTION — incohérence amont assumée : M1 expose `queued`, tandis que
 * M4/M5 exposent `pending` pour le même état initial. Cette union couvre les
 * deux afin que le front consomme n'importe quel module sans casser.
 */
export type JobStatus =
  | "queued"
  | "pending"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

/** États terminaux d'un job (plus aucune transition attendue). */
export const TERMINAL_JOB_STATUSES: readonly JobStatus[] = [
  "completed",
  "failed",
  "cancelled",
];

/** État de santé agrégé d'un module, tel que renvoyé par `GET /api/status`. */
export type ModuleHealthStatus = "ok" | "error" | "unknown";

/**
 * Santé d'un module renvoyée par le Gateway (`routers/status.py`).
 * `last_checked` est un timestamp epoch en millisecondes.
 */
export interface ModuleHealth {
  name?: ModuleId;
  status: ModuleHealthStatus;
  version?: string;
  queue_size?: number;
  last_checked: number;
}

/** Réponse de `GET /api/status` : un `ModuleHealth` par module, clé = ModuleId. */
export type StatusResponse = Record<ModuleId, ModuleHealth>;

/** Formats d'export CTI supportés par tous les endpoints `/export/{job_id}/{fmt}`. */
export type ExportFormat = "json" | "csv" | "stix" | "all";

/** Réponse 202 commune au lancement d'une analyse (`POST .../analyze`). */
export interface JobAcceptedResponse {
  job_id: string;
  status: JobStatus;
  status_url: string;
}

/** Enveloppe d'erreur structurée renvoyée par l'API (FastAPI `detail`). */
export interface ApiError {
  detail: string;
  code?: string;
  context?: Record<string, unknown>;
}
