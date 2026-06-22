/**
 * Historique d'analyses — couche persistée (localStorage) transverse à tous les
 * modules. Une entrée `AnalysisRecord` capture le résultat complet d'un run
 * (module unique M1-M5 ou pipeline complet) afin de réafficher des statistiques
 * agrégées (Overview), lister l'historique (History) et régénérer un rapport.
 */

/** Origine d'une entrée d'historique : un module isolé ou le pipeline complet. */
export type AnalysisModule = "M1" | "M2" | "M3" | "M4" | "M5" | "PIPELINE";

/** Métriques compactes d'un run, prêtes pour l'affichage en table/cartes. */
export interface AnalysisSummary {
  /** Métrique clé mise en évidence (ex. "12 IOC", "VANGUARD PANDA"). */
  headline: string;
  /** Détails secondaires affichés en puces/chips (ex. ["critical: 3", ...]). */
  details: string[];
}

/**
 * Une analyse enregistrée. `result` conserve la sortie complète du module
 * (`IOCBundle` | `AlertBundle` | `YaraRuleSet` | `APTMapReport` |
 * `AttributionReport` | `PipelineRunResults`) pour régénérer le rapport.
 */
export interface AnalysisRecord {
  id: string;
  module: AnalysisModule;
  createdAt: string;
  inputName: string;
  summary: AnalysisSummary;
  result: unknown;
}
