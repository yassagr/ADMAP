/**
 * Construction des `AnalysisSummary` (métriques compactes) par module, à partir
 * du résultat complet d'un run. Utilisé à l'enregistrement d'une analyse dans
 * l'historique ({@link useAnalysisRecorder}) et pour l'affichage en table.
 */
import type {
  AlertBundle,
  AnalysisSummary,
  APTMapReport,
  AttributionReport,
  IOCBundle,
  YaraRuleSet,
} from "@/types";
import type { PipelineRunResults } from "@/store";

function topEntries(
  record: Record<string, number> | undefined,
  limit: number,
): string[] {
  return Object.entries(record ?? {})
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([key, n]) => `${key}: ${n}`);
}

export function summarizeM1(bundle: IOCBundle): AnalysisSummary {
  const total = bundle.analysis_stats?.total_iocs ?? bundle.iocs.length;
  return {
    headline: `${total} IOC`,
    details: topEntries(bundle.analysis_stats?.by_type, 4),
  };
}

export function summarizeM2(bundle: AlertBundle): AnalysisSummary {
  return {
    headline: `${bundle.alerts.length} alerte(s)`,
    details: topEntries(bundle.alerts_by_severity, 5),
  };
}

export function summarizeM3(ruleset: YaraRuleSet): AnalysisSummary {
  return {
    headline: `${ruleset.total_rules} règle(s)`,
    details: [
      `${ruleset.compiled_rules} compilée(s)`,
      `${ruleset.failed_rules} échec(s)`,
    ],
  };
}

export function summarizeM4(report: APTMapReport): AnalysisSummary {
  return {
    headline: `${report.campaign_count} campagne(s)`,
    details: [
      `${report.noise_count} bruit`,
      `${report.cluster_bundle.total_profiles} profil(s)`,
    ],
  };
}

export function summarizeM5(report: AttributionReport): AnalysisSummary {
  const top = report.top_global_candidate;
  return {
    headline: top ? top.apt_name : "Aucun acteur",
    details: top ? [`${Math.round(top.confidence_score)}/100`, top.apt_id] : [],
  };
}

export function summarizePipeline(results: PipelineRunResults): AnalysisSummary {
  const top = results.m5?.top_global_candidate ?? null;
  const details: string[] = [];
  if (results.m1) {
    details.push(`${results.m1.analysis_stats?.total_iocs ?? results.m1.iocs.length} IOC`);
  }
  if (results.m2) details.push(`${results.m2.alerts.length} alerte(s)`);
  if (results.m4) details.push(`${results.m4.campaign_count} campagne(s)`);
  return {
    headline: top
      ? `${top.apt_name} (${Math.round(top.confidence_score)}/100)`
      : "Pipeline complet",
    details,
  };
}
