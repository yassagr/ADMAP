/**
 * Orchestrateur du pipeline ADMAP complet (M1 → M2 → M3 → M4 → M5).
 *
 * Enchaîne séquentiellement les analyses des 5 microservices en RÉUTILISANT les
 * clients API existants (`analyzeM*`, `getM*Job`, `getM*JobResult`) — aucune
 * logique HTTP/job réécrite, juste une boucle de polling d'orchestration. La
 * sortie JSON de chaque module est re-sérialisée en `File` et injectée en entrée
 * du module suivant via la même couche API.
 *
 * Dépendances de données :
 *   M1 (opt) → IOCBundle
 *   M2 (obl) → AlertBundle            [échec ⇒ on stoppe tout]
 *   M3 (opt) → YaraRuleSet            [indépendant de M1/M2]
 *   M4 (obl) → APTMapReport           (AlertBundle obl + IOCBundle/YaraRuleSet opt)
 *   M5       → AttributionReport      (APTMapReport obl + IOCBundle/AlertBundle opt)
 *
 * Robustesse : entrée optionnelle absente ⇒ étape `skipped` ; échec d'une étape
 * optionnelle (M1/M3) ⇒ `failed` mais le pipeline continue sans l'enrichissement ;
 * échec d'une étape obligatoire (M2/M4) ⇒ `failed` et on stoppe ce qui en dépend
 * en conservant les résultats déjà obtenus.
 */
import { useCallback, useEffect, useRef, useState } from "react";

import { analyzeM1, getM1Job, getM1JobResult } from "@/api/m1";
import { analyzeM2, getM2Job, getM2JobResult } from "@/api/m2";
import { generateM3, getM3Job, getM3JobResult } from "@/api/m3";
import { analyzeM4, getM4Job, getM4JobResult } from "@/api/m4";
import { analyzeM5, getM5Job, getM5JobResult } from "@/api/m5";
import { MODULE_IDS, TERMINAL_JOB_STATUSES } from "@/types";
import type {
  AlertBundle,
  APTMapReport,
  AttributionReport,
  IOCBundle,
  JobAcceptedResponse,
  JobInfo,
  ModuleId,
  YaraRuleSet,
} from "@/types";

/** État d'une étape du pipeline tel qu'affiché par le diagramme de flux. */
export type PipelineStepStatus =
  | "idle"
  | "running"
  | "done"
  | "skipped"
  | "failed";

/** Vue UI d'une étape (un microservice). */
export interface PipelineStep {
  status: PipelineStepStatus;
  jobId: string | null;
  progress: number;
  stage?: string;
  error?: string;
}

/** Résultats agrégés produits par le pipeline (présents si l'étape a réussi). */
export interface PipelineResults {
  m1?: IOCBundle;
  m2?: AlertBundle;
  m3?: YaraRuleSet;
  m4?: APTMapReport;
  m5?: AttributionReport;
}

/** Entrées utilisateur du pipeline. */
export interface PipelineInputs {
  /** PCAP — obligatoire (alimente M2). */
  pcap: File;
  /** Fichier suspect PE/ELF/texte — optionnel (alimente M1). */
  suspectFile?: File;
  /** Corpus malveillant — optionnel (alimente M3, requis avec le corpus bénin). */
  corpusMalware?: File[];
  /** Corpus bénin — optionnel (alimente M3, requis avec le corpus malveillant). */
  corpusBenign?: File[];
}

export type PipelineStepMap = Record<ModuleId, PipelineStep>;

export interface UsePipelineResult {
  steps: PipelineStepMap;
  results: PipelineResults;
  isRunning: boolean;
  error: string | null;
  /** Lance le pipeline (réinitialise l'état précédent). */
  run: (inputs: PipelineInputs) => Promise<void>;
  /** Annule un run en cours et réinitialise l'état. */
  reset: () => void;
}

const POLL_INTERVAL_MS = 1500;
/** Tolérance aux erreurs réseau transitoires pendant le polling d'un job. */
const MAX_POLL_ERRORS = 4;

/** Sentinelle d'annulation (nouveau run / démontage) — distincte d'un échec métier. */
class PipelineCancelled extends Error {
  constructor() {
    super("Pipeline annulé");
    this.name = "PipelineCancelled";
  }
}

/** Échec métier d'une étape — interrompt la branche dépendante. */
class StepError extends Error {
  readonly module: ModuleId;
  constructor(module: ModuleId, message: string) {
    super(message);
    this.name = "StepError";
    this.module = module;
  }
}

function makeInitialSteps(): PipelineStepMap {
  return MODULE_IDS.reduce((acc, id) => {
    acc[id] = { status: "idle", jobId: null, progress: 0 };
    return acc;
  }, {} as PipelineStepMap);
}

/** Re-sérialise une sortie de module en `File` JSON consommable par le suivant. */
function jsonToFile(data: unknown, filename: string): File {
  return new File([JSON.stringify(data)], filename, {
    type: "application/json",
  });
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

export function usePipeline(): UsePipelineResult {
  const [steps, setSteps] = useState<PipelineStepMap>(makeInitialSteps);
  const [results, setResults] = useState<PipelineResults>({});
  const [isRunning, setIsRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Identifiant du run courant : invalide les boucles async des runs précédents.
  const runIdRef = useRef(0);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      runIdRef.current += 1; // stoppe toute boucle async en vol
    };
  }, []);

  const patchStep = useCallback(
    (module: ModuleId, partial: Partial<PipelineStep>): void => {
      if (!mountedRef.current) return;
      setSteps((prev) => ({ ...prev, [module]: { ...prev[module], ...partial } }));
    },
    [],
  );

  const reset = useCallback((): void => {
    runIdRef.current += 1;
    if (!mountedRef.current) return;
    setSteps(makeInitialSteps());
    setResults({});
    setError(null);
    setIsRunning(false);
  }, []);

  const run = useCallback(
    async (inputs: PipelineInputs): Promise<void> => {
      const runId = ++runIdRef.current;
      const cancelled = (): boolean =>
        runIdRef.current !== runId || !mountedRef.current;

      setSteps(makeInitialSteps());
      setResults({});
      setError(null);
      setIsRunning(true);

      /** Soumet un job, suit sa progression jusqu'à l'état terminal, renvoie le résultat. */
      const execStep = async <R>(
        module: ModuleId,
        submit: () => Promise<JobAcceptedResponse>,
        getJob: (id: string) => Promise<JobInfo>,
        getResult: (id: string) => Promise<R>,
      ): Promise<R> => {
        patchStep(module, {
          status: "running",
          progress: 0,
          stage: undefined,
          error: undefined,
        });

        let accepted: JobAcceptedResponse;
        try {
          accepted = await submit();
        } catch (e) {
          const msg = e instanceof Error ? e.message : "Soumission échouée";
          patchStep(module, { status: "failed", error: msg });
          throw new StepError(module, msg);
        }
        if (cancelled()) throw new PipelineCancelled();

        const jobId = accepted.job_id;
        patchStep(module, { jobId });

        let pollErrors = 0;
        for (;;) {
          if (cancelled()) throw new PipelineCancelled();

          let info: JobInfo;
          try {
            info = await getJob(jobId);
            pollErrors = 0;
          } catch (e) {
            if (cancelled()) throw new PipelineCancelled();
            if (++pollErrors > MAX_POLL_ERRORS) {
              const msg = e instanceof Error ? e.message : "Suivi du job échoué";
              patchStep(module, { status: "failed", error: msg });
              throw new StepError(module, msg);
            }
            await delay(POLL_INTERVAL_MS);
            continue;
          }
          if (cancelled()) throw new PipelineCancelled();

          patchStep(module, {
            progress: info.progress ?? 0,
            stage: info.current_stage,
          });

          if (info.status === "completed") {
            const result = await getResult(jobId);
            if (cancelled()) throw new PipelineCancelled();
            patchStep(module, { status: "done", progress: 100, stage: undefined });
            return result;
          }
          if (info.status === "failed" || info.status === "cancelled") {
            const msg = (info.error ??
              info.error_message ??
              "Le job a échoué") as string;
            patchStep(module, { status: "failed", error: msg });
            throw new StepError(module, msg);
          }
          if (!TERMINAL_JOB_STATUSES.includes(info.status)) {
            await delay(POLL_INTERVAL_MS);
          }
        }
      };

      // Fichiers chaînés entre étapes (sortie JSON N → entrée N+1).
      let iocFile: File | undefined;
      let alertFile: File | undefined;
      let yaraFile: File | undefined;
      let reportFile: File | undefined;

      const runM1 = Boolean(inputs.suspectFile);
      const runM3 = Boolean(
        inputs.corpusMalware?.length && inputs.corpusBenign?.length,
      );
      if (!runM1) patchStep("m1", { status: "skipped" });
      if (!runM3) patchStep("m3", { status: "skipped" });

      try {
        // 1. M1 (optionnel) — un échec n'interrompt pas le pipeline.
        if (runM1) {
          try {
            const bundle = await execStep<IOCBundle>(
              "m1",
              () => analyzeM1(inputs.suspectFile as File),
              getM1Job,
              getM1JobResult,
            );
            setResults((r) => ({ ...r, m1: bundle }));
            iocFile = jsonToFile(bundle, "ioc_bundle.json");
          } catch (e) {
            if (e instanceof PipelineCancelled) throw e;
            /* M1 optionnel : on continue sans enrichissement IOC. */
          }
        }

        // 2. M2 (obligatoire) — un échec stoppe tout le pipeline.
        const alertBundle = await execStep<AlertBundle>(
          "m2",
          () => analyzeM2(inputs.pcap),
          getM2Job,
          getM2JobResult,
        );
        setResults((r) => ({ ...r, m2: alertBundle }));
        alertFile = jsonToFile(alertBundle, "alert_bundle.json");

        // 3. M3 (optionnel, indépendant) — un échec n'interrompt pas M4/M5.
        if (runM3) {
          try {
            const ruleset = await execStep<YaraRuleSet>(
              "m3",
              () =>
                generateM3(
                  inputs.corpusMalware as File[],
                  inputs.corpusBenign as File[],
                  iocFile,
                ),
              getM3Job,
              getM3JobResult,
            );
            setResults((r) => ({ ...r, m3: ruleset }));
            yaraFile = jsonToFile(ruleset, "yara_ruleset.json");
          } catch (e) {
            if (e instanceof PipelineCancelled) throw e;
            /* M3 optionnel : on continue sans règles YARA. */
          }
        }

        // 4. M4 (obligatoire) — un échec stoppe M5.
        const report = await execStep<APTMapReport>(
          "m4",
          () =>
            analyzeM4(alertFile as File, {
              iocBundle: iocFile,
              yaraRuleset: yaraFile,
            }),
          getM4Job,
          getM4JobResult,
        );
        setResults((r) => ({ ...r, m4: report }));
        reportFile = jsonToFile(report, "apt_map_report.json");

        // 5. M5 — verdict d'attribution APT.
        const attribution = await execStep<AttributionReport>(
          "m5",
          () =>
            analyzeM5(reportFile as File, {
              iocBundle: iocFile,
              alertBundle: alertFile,
            }),
          getM5Job,
          getM5JobResult,
        );
        setResults((r) => ({ ...r, m5: attribution }));
      } catch (e) {
        if (e instanceof PipelineCancelled) return;
        if (mountedRef.current && runIdRef.current === runId) {
          setError(
            e instanceof StepError
              ? `Étape ${e.module.toUpperCase()} : ${e.message}`
              : e instanceof Error
                ? e.message
                : "Échec du pipeline",
          );
        }
      } finally {
        if (mountedRef.current && runIdRef.current === runId) {
          setIsRunning(false);
        }
      }
    },
    [patchStep],
  );

  return { steps, results, isRunning, error, run, reset };
}
