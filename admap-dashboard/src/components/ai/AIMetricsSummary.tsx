/**
 * Cartes récapitulatives des métriques d'évaluation (accuracy / precision /
 * recall / f1 / auc), formatées en pourcentage.
 */
import { Card, CardContent } from "@/components/ui/card";
import type { AIMetricsScores } from "@/types/aiMetrics";

interface MetricMeta {
  key: keyof AIMetricsScores;
  label: string;
  color: string;
}

const METRICS: readonly MetricMeta[] = [
  { key: "accuracy", label: "Accuracy", color: "#00d4ff" },
  { key: "precision", label: "Precision", color: "#22d3ee" },
  { key: "recall", label: "Recall", color: "#38bdf8" },
  { key: "f1", label: "F1-score", color: "#a3e635" },
  { key: "auc", label: "AUC", color: "#facc15" },
];

/** Formate une valeur normalisée 0-1 en pourcentage à une décimale. */
function asPercent(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

export interface AIMetricsSummaryProps {
  metrics: AIMetricsScores;
}

export function AIMetricsSummary({ metrics }: AIMetricsSummaryProps) {
  return (
    <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
      {METRICS.map(({ key, label, color }) => (
        <Card key={key}>
          <CardContent className="flex flex-col gap-1 p-4">
            <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              {label}
            </span>
            <span className="text-2xl font-bold" style={{ color }}>
              {asPercent(metrics[key])}
            </span>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
