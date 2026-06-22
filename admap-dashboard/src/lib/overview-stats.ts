/**
 * Agrégation de l'historique d'analyses pour le tableau de bord Overview.
 * Fonctions pures, sans état : prennent `AnalysisRecord[]` et produisent les KPI
 * et les jeux de données des graphes recharts. Les entrées PIPELINE exposent
 * leurs sous-résultats (m1..m5) au même titre que les analyses module isolées.
 */
import type {
  AlertBundle,
  AnalysisModule,
  AnalysisRecord,
  APTMapReport,
  AttributionReport,
  IOCBundle,
} from "@/types";
import type { PipelineRunResults } from "@/store";

/** Couleur par module (cohérente avec la sidebar / le thème). */
export const MODULE_COLOR: Record<AnalysisModule, string> = {
  M1: "#00d4ff",
  M2: "#ff6b35",
  M3: "#6ee7b7",
  M4: "#a78bfa",
  M5: "#f59e0b",
  PIPELINE: "#7dd3fc",
};

const SEVERITY_COLOR: Record<string, string> = {
  critical: "#ff2d55",
  high: "#ff6b35",
  medium: "#f59e0b",
  low: "#00d4ff",
  info: "#94a3b8",
};

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

const ALL_MODULES: AnalysisModule[] = ["M1", "M2", "M3", "M4", "M5", "PIPELINE"];

function pipelineOf(r: AnalysisRecord): PipelineRunResults | undefined {
  return r.module === "PIPELINE" ? (r.result as PipelineRunResults) : undefined;
}
function m1Of(r: AnalysisRecord): IOCBundle | undefined {
  return r.module === "M1" ? (r.result as IOCBundle) : pipelineOf(r)?.m1;
}
function m2Of(r: AnalysisRecord): AlertBundle | undefined {
  return r.module === "M2" ? (r.result as AlertBundle) : pipelineOf(r)?.m2;
}
function m4Of(r: AnalysisRecord): APTMapReport | undefined {
  return r.module === "M4" ? (r.result as APTMapReport) : pipelineOf(r)?.m4;
}
function m5Of(r: AnalysisRecord): AttributionReport | undefined {
  return r.module === "M5" ? (r.result as AttributionReport) : pipelineOf(r)?.m5;
}

export interface OverviewKpis {
  totalAnalyses: number;
  perModule: Record<AnalysisModule, number>;
  lastAnalysisAt: string | null;
  totalIocs: number;
  totalAlerts: number;
  totalCampaigns: number;
  aptActors: number;
}

export interface NamedCount {
  name: string;
  value: number;
}
export interface ColoredCount extends NamedCount {
  color: string;
}
export interface TimelinePoint {
  date: string;
  count: number;
}

export interface OverviewData {
  kpis: OverviewKpis;
  moduleBars: ColoredCount[];
  severity: ColoredCount[];
  iocTypes: NamedCount[];
  mitre: NamedCount[];
  apt: NamedCount[];
  timeline: TimelinePoint[];
}

function increment(map: Map<string, number>, key: string, by = 1): void {
  map.set(key, (map.get(key) ?? 0) + by);
}

export function buildOverviewData(records: AnalysisRecord[]): OverviewData {
  const perModule: Record<AnalysisModule, number> = {
    M1: 0,
    M2: 0,
    M3: 0,
    M4: 0,
    M5: 0,
    PIPELINE: 0,
  };

  let totalIocs = 0;
  let totalAlerts = 0;
  let totalCampaigns = 0;
  const aptActorSet = new Set<string>();

  const severityMap = new Map<string, number>();
  const iocTypeMap = new Map<string, number>();
  const mitreMap = new Map<string, number>();
  const aptScore = new Map<string, number>();
  const dayMap = new Map<string, number>();

  for (const r of records) {
    perModule[r.module] += 1;

    const day = r.createdAt.slice(0, 10);
    increment(dayMap, day);

    const m1 = m1Of(r);
    if (m1) {
      totalIocs += m1.analysis_stats?.total_iocs ?? m1.iocs.length;
      for (const [type, n] of Object.entries(m1.analysis_stats?.by_type ?? {})) {
        if (n > 0) increment(iocTypeMap, type, n);
      }
    }

    const m2 = m2Of(r);
    if (m2) {
      totalAlerts += m2.alerts.length;
      for (const [sev, n] of Object.entries(m2.alerts_by_severity ?? {})) {
        if (n > 0) increment(severityMap, sev, n);
      }
    }

    const m4 = m4Of(r);
    if (m4) {
      totalCampaigns += m4.campaign_count;
      for (const [tech, n] of m4.top_techniques) {
        if (n > 0) increment(mitreMap, tech, n);
      }
    }

    const m5 = m5Of(r);
    if (m5) {
      const candidates = m5.results.flatMap((res) => res.candidates);
      for (const c of candidates) {
        aptScore.set(
          c.apt_name,
          Math.max(aptScore.get(c.apt_name) ?? 0, c.confidence_score),
        );
      }
      if (m5.top_global_candidate) aptActorSet.add(m5.top_global_candidate.apt_name);
    }
  }

  const moduleBars: ColoredCount[] = ALL_MODULES.filter(
    (m) => perModule[m] > 0,
  ).map((m) => ({ name: m, value: perModule[m], color: MODULE_COLOR[m] }));

  const severity: ColoredCount[] = SEVERITY_ORDER.filter(
    (s) => (severityMap.get(s) ?? 0) > 0,
  ).map((s) => ({
    name: s,
    value: severityMap.get(s) ?? 0,
    color: SEVERITY_COLOR[s] ?? "#94a3b8",
  }));

  const iocTypes: NamedCount[] = [...iocTypeMap.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([name, value]) => ({ name, value }));

  const mitre: NamedCount[] = [...mitreMap.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([name, value]) => ({ name, value }));

  const apt: NamedCount[] = [...aptScore.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([name, value]) => ({ name, value: Math.round(value) }));

  const timeline: TimelinePoint[] = [...dayMap.entries()]
    .sort((a, b) => (a[0] < b[0] ? -1 : 1))
    .map(([date, count]) => ({ date, count }));

  return {
    kpis: {
      totalAnalyses: records.length,
      perModule,
      lastAnalysisAt: records[0]?.createdAt ?? null,
      totalIocs,
      totalAlerts,
      totalCampaigns,
      aptActors: aptActorSet.size,
    },
    moduleBars,
    severity,
    iocTypes,
    mitre,
    apt,
    timeline,
  };
}
