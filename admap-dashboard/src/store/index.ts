import { create } from 'zustand'

export type JobStatus = "pending" | "running" | "completed" | "failed" | "cancelled";

export interface JobState {
  job_id: string;
  status: JobStatus;
  module: "m1" | "m2" | "m3" | "m4" | "m5";
  created_at: string;
  completed_at?: string;
  error?: string;
}

export interface ModuleHealth {
  status: "ok" | "error" | "unknown";
  version?: string;
  queue_size?: number;
  last_checked: number;
}

export interface Settings {
  moduleUrls: Record<string, string>;
  animationsEnabled: boolean;
  autoRefresh: boolean;
  pollInterval: number;
}

interface AdmapStore {
  moduleStatus: Record<"m1" | "m2" | "m3" | "m4" | "m5", ModuleHealth>;
  activeJobs: Record<string, JobState>;
  jobResults: Record<string, unknown>;
  settings: Settings;

  updateModuleStatus: (module: "m1" | "m2" | "m3" | "m4" | "m5", health: ModuleHealth) => void;
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
    pollInterval: 30000, // 30 seconds
  },

  updateModuleStatus: (module, health) => 
    set((state) => ({
      moduleStatus: { ...state.moduleStatus, [module]: health }
    })),
    
  upsertJob: (job) =>
    set((state) => ({
      activeJobs: { ...state.activeJobs, [job.job_id]: job }
    })),
    
  setJobResult: (jobId, result) =>
    set((state) => ({
      jobResults: { ...state.jobResults, [jobId]: result }
    })),
    
  updateSettings: (partial) =>
    set((state) => ({
      settings: { ...state.settings, ...partial }
    })),
}))
