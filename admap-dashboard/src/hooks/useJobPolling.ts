/**
 * Hook de suivi d'un job asynchrone.
 *
 * Stratégie : ouvre le WebSocket du Gateway (`ws://<gw>/ws/jobs/{id}?module=`)
 * qui relaie le statut du microservice. Si le WS échoue ou se ferme avant un
 * état terminal, bascule en POLLING HTTP (`getM{n}Job`) toutes les 2 s. À l'état
 * `completed`, récupère le résultat via `getM{n}JobResult` et le stocke.
 *
 * Passer `jobId`/`module` à `null` désactive le suivi (et réinitialise l'état).
 */
import { useEffect, useRef, useState } from "react";

import { gatewayWsUrl } from "@/api/gateway";
import { getM1Job, getM1JobResult } from "@/api/m1";
import { getM2Job, getM2JobResult } from "@/api/m2";
import { getM3Job, getM3JobResult } from "@/api/m3";
import { getM4Job, getM4JobResult } from "@/api/m4";
import { getM5Job, getM5JobResult } from "@/api/m5";
import { useAdmapStore } from "@/store";
import { TERMINAL_JOB_STATUSES } from "@/types";
import type { JobInfo, JobStatus, ModuleId } from "@/types";

const JOB_FETCHERS: Record<ModuleId, (id: string) => Promise<JobInfo>> = {
  m1: getM1Job,
  m2: getM2Job,
  m3: getM3Job,
  m4: getM4Job,
  m5: getM5Job,
};

const RESULT_FETCHERS: Record<ModuleId, (id: string) => Promise<unknown>> = {
  m1: getM1JobResult,
  m2: getM2JobResult,
  m3: getM3JobResult,
  m4: getM4JobResult,
  m5: getM5JobResult,
};

const HTTP_POLL_INTERVAL_MS = 2000;

function isTerminal(status: JobStatus): boolean {
  return TERMINAL_JOB_STATUSES.includes(status);
}

export interface UseJobPollingResult {
  status: JobStatus | null;
  progress: number;
  job: JobInfo | null;
  result: unknown;
  error: string | null;
  isPolling: boolean;
}

export function useJobPolling(
  jobId: string | null,
  module: ModuleId | null,
): UseJobPollingResult {
  const gatewayBaseUrl = useAdmapStore((s) => s.settings.moduleUrls.gateway);
  const upsertJob = useAdmapStore((s) => s.upsertJob);
  const setJobResult = useAdmapStore((s) => s.setJobResult);

  const [job, setJob] = useState<JobInfo | null>(null);
  const [result, setResult] = useState<unknown>(null);
  const [error, setError] = useState<string | null>(null);

  // Refs mutables, lues dans les closures WS/timer (évite les closures périmées).
  const doneRef = useRef(false);
  const resultFetchedRef = useRef(false);

  useEffect(() => {
    if (!jobId || !module) {
      // Inactif : aucune configuration. Le cleanup du run précédent a déjà
      // réinitialisé l'état (setState en cleanup, hors corps de l'effet).
      return;
    }

    let cancelled = false;
    let ws: WebSocket | null = null;
    let httpTimer: number | null = null;
    doneRef.current = false;
    resultFetchedRef.current = false;

    const stop = (): void => {
      doneRef.current = true;
      if (ws) {
        ws.onmessage = null;
        ws.onerror = null;
        ws.onclose = null;
        ws.close();
        ws = null;
      }
      if (httpTimer !== null) {
        window.clearInterval(httpTimer);
        httpTimer = null;
      }
    };

    const fetchResult = (): void => {
      if (cancelled || resultFetchedRef.current) return;
      resultFetchedRef.current = true;
      RESULT_FETCHERS[module](jobId)
        .then((r) => {
          if (cancelled) return;
          setResult(r);
          setJobResult(jobId, r);
        })
        .catch(() => {
          /* résultat indisponible : non bloquant */
        });
    };

    const ingest = (data: JobInfo): void => {
      if (cancelled) return;
      setError(null);
      setJob(data);
      upsertJob({
        job_id: jobId,
        status: data.status,
        module,
        created_at: data.created_at ?? new Date().toISOString(),
        completed_at: data.completed_at ?? undefined,
        error: data.error ?? data.error_message ?? undefined,
      });
      if (data.status === "completed") fetchResult();
      if (isTerminal(data.status)) stop();
    };

    const startHttpFallback = (): void => {
      if (cancelled || doneRef.current || httpTimer !== null) return;
      const fetcher = JOB_FETCHERS[module];
      const tick = async (): Promise<void> => {
        try {
          ingest(await fetcher(jobId));
        } catch (e) {
          if (!cancelled) {
            setError(e instanceof Error ? e.message : "Polling HTTP échoué");
          }
        }
      };
      void tick();
      httpTimer = window.setInterval(() => void tick(), HTTP_POLL_INTERVAL_MS);
    };

    try {
      ws = new WebSocket(gatewayWsUrl(jobId, module, gatewayBaseUrl));
      ws.onmessage = (ev: MessageEvent) => {
        try {
          const parsed: unknown = JSON.parse(ev.data as string);
          if (
            parsed &&
            typeof parsed === "object" &&
            "error" in parsed &&
            !("status" in parsed)
          ) {
            // Trame d'erreur du Gateway -> bascule HTTP.
            startHttpFallback();
            return;
          }
          ingest(parsed as JobInfo);
        } catch {
          /* trame non-JSON ignorée */
        }
      };
      ws.onerror = () => startHttpFallback();
      ws.onclose = () => {
        // Fermeture sans état terminal connu -> fallback HTTP.
        if (!cancelled && !doneRef.current) startHttpFallback();
      };
    } catch {
      startHttpFallback();
    }

    return () => {
      cancelled = true;
      stop();
      // Réinitialise l'état au changement d'entrées / au démontage. setState en
      // cleanup : hors du corps de l'effet, donc non concerné par la règle
      // react-hooks/set-state-in-effect.
      setJob(null);
      setResult(null);
      setError(null);
    };
  }, [jobId, module, gatewayBaseUrl, upsertJob, setJobResult]);

  const active = Boolean(jobId && module);
  const isPolling = active && (job === null || !isTerminal(job.status));

  return {
    status: active ? job?.status ?? null : null,
    progress: active ? job?.progress ?? 0 : 0,
    job: active ? job : null,
    result: active ? result : null,
    error: active ? error : null,
    isPolling,
  };
}
