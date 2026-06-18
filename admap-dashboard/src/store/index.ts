import { create } from "zustand";
import type { JobStatus, ModuleHealth, ModuleId } from "@/types";

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
  settings: Settings;

  updateModuleStatus: (module: ModuleId, health: ModuleHealth) => void;
  upsertJob: (job: JobState) => void;
  setJobResult: (jobId: string, result: unknown) => void;
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

  updateSettings: (partial) =>
    set((state) => ({
      settings: { ...state.settings, ...partial },
    })),
}));
