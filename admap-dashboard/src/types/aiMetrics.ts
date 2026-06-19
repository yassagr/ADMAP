/**
 * Contrat du fichier `public/model_metrics.json` consommé par la page IA / Modèle.
 *
 * Fichier statique remplaçable sans rebuild (lu via `fetch`). Décrit les
 * performances d'un modèle de classification binaire (bénin / malveillant) :
 * métriques agrégées, matrice de confusion, courbe ROC et importance des
 * features. Lorsque `is_trained` est `false` (ou que les tableaux sont vides),
 * la page affiche un état vide.
 */

/** Métriques agrégées d'évaluation (valeurs normalisées 0-1). */
export interface AIMetricsScores {
  accuracy: number;
  precision: number;
  recall: number;
  f1: number;
  /** Aire sous la courbe ROC. */
  auc: number;
}

/** Point de la courbe ROC. */
export interface RocPoint {
  /** Taux de faux positifs (0-1). */
  fpr: number;
  /** Taux de vrais positifs (0-1). */
  tpr: number;
  /** Seuil de décision associé (optionnel). */
  threshold?: number;
}

/** Importance d'une feature pour le modèle. */
export interface FeatureImportanceEntry {
  feature: string;
  /** Poids relatif (0-1 ou échelle arbitraire ≥ 0). */
  importance: number;
}

/** Contrat complet de `model_metrics.json`. */
export interface ModelMetrics {
  is_trained: boolean;
  model_name: string;
  dataset: string;
  /** Horodatage ISO-8601 de l'entraînement, ou `null` si non entraîné. */
  trained_at: string | null;
  metrics: AIMetricsScores;
  /** Libellés des classes, dans l'ordre des lignes/colonnes de la matrice. */
  labels: string[];
  /** Matrice de confusion carrée `[réel][prédit]`. */
  confusion_matrix: number[][];
  roc: RocPoint[];
  feature_importance: FeatureImportanceEntry[];
}

/**
 * Vrai si le modèle est entraîné ET possède des données exploitables.
 * Tolère un `is_trained=true` accompagné de tableaux vides (placeholder partiel).
 */
export function isModelReady(data: ModelMetrics): boolean {
  if (!data.is_trained) return false;
  const hasConfusion = data.confusion_matrix.some((row) =>
    row.some((v) => v > 0),
  );
  return (
    hasConfusion ||
    data.roc.length > 0 ||
    data.feature_importance.length > 0
  );
}
