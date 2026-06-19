import { create } from "zustand";
import type {
  AlertBundle,
  APTMapReport,
  AttributionReport,
  IOCBundle,
  JobStatus,
  ModuleHealth,
  ModuleId,
  YaraRuleSet,
} from "@/types";

/**
 * Job suivi côté UI — vue allégée de l'`AnalysisJob` backend.
 * Réutilise le `JobStatus` canonique de `@/types` (inclut `queued` exposé par M1).
 */
export interface JobState {
  job_id: string;
  status: JobStatus;
  module: ModuleId;
  created_at: string;
  completed_at?: string;
  error?: string;
}

/** Sorties agrégées d'un run de pipeline (présentes si l'étape a réussi). */
export interface PipelineRunResults {
  m1?: IOCBundle;
  m2?: AlertBundle;
  m3?: YaraRuleSet;
  m4?: APTMapReport;
  m5?: AttributionReport;
}

/** Métadonnées d'un run (entrées analysées, identifiant, horodatage). */
export interface PipelineRunMeta {
  pcapName: string;
  suspectFileName?: string;
  corpusMalwareCount: number;
  corpusBenignCount: number;
}

/**
 * Dernier run de pipeline persisté pour la page Rapport (/report).
 * Indépendant de l'état local éphémère de `usePipeline` : survit à la navigation.
 */
export interface PipelineRun {
  runId: string;
  createdAt: string;
  meta: PipelineRunMeta;
  results: PipelineRunResults;
}

/** Préférences UI locales (non issues du backend). */
export interface Settings {
  moduleUrls: Record<string, string>;
  animationsEnabled: boolean;
  autoRefresh: boolean;
  pollInterval: number;
}

interface AdmapStore {
  moduleStatus: Record<ModuleId, ModuleHealth>;
  activeJobs: Record<string, JobState>;
  jobResults: Record<string, unknown>;
  lastPipelineRun: PipelineRun | null;
  settings: Settings;

  updateModuleStatus: (module: ModuleId, health: ModuleHealth) => void;
  upsertJob: (job: JobState) => void;
  setJobResult: (jobId: string, result: unknown) => void;
  setLastPipelineRun: (run: PipelineRun | null) => void;
  updateSettings: (partial: Partial<Settings>) => void;
}

export const useAdmapStore = create<AdmapStore>((set) => ({
  moduleStatus: {
    m1: { status: "unknown", last_checked: 0 },
    m2: { status: "unknown", last_checked: 0 },
    m3: { status: "unknown", last_checked: 0 },
    m4: { status: "unknown", last_checked: 0 },
    m5: { status: "unknown", last_checked: 0 },
  },
  activeJobs: {},
  jobResults: {},
  lastPipelineRun: null,
  settings: {
    moduleUrls: {
      gateway: "http://localhost:9000",
    },
    animationsEnabled: true,
    autoRefresh: true,
    pollInterval: 30000, // 30 secondes
  },

  updateModuleStatus: (module, health) =>
    set((state) => ({
      moduleStatus: { ...state.moduleStatus, [module]: health },
    })),

  upsertJob: (job) =>
    set((state) => ({
      activeJobs: { ...state.activeJobs, [job.job_id]: job },
    })),

  setJobResult: (jobId, result) =>
    set((state) => ({
      jobResults: { ...state.jobResults, [jobId]: result },
    })),

  setLastPipelineRun: (run) => set({ lastPipelineRun: run }),

  updateSettings: (partial) =>
    set((state) => ({
      settings: { ...state.settings, ...partial },
    })),
}));
