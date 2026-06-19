/**
 * Résultats d'attribution par cluster : une section par `AttributionResult`
 * exposant la méthode d'analyse, la taille du vecteur de features et le top-k
 * de candidats APT (via `M5CandidateCard`).
 */
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { AttributionResult } from "@/types";

import { M5CandidateCard } from "./M5CandidateCard";

export interface M5ClusterResultsProps {
  results: AttributionResult[];
}

/** Libellé lisible de la méthode d'analyse d'un cluster. */
const METHOD_LABEL: Record<string, string> = {
  "xgboost+cosine": "XGBoost + cosinus",
  cosine_only: "Cosinus seul",
  fallback: "Repli (fallback)",
};

export function M5ClusterResults({ results }: M5ClusterResultsProps) {
  if (results.length === 0) {
    return (
      <Card>
        <CardContent className="py-8 text-center text-sm text-muted-foreground">
          Aucun cluster attribué (clusters insuffisants ou bruit).
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      {results.map((res) => (
        <Card key={res.cluster_id}>
          <CardHeader className="flex-row items-center justify-between space-y-0">
            <CardTitle className="text-base">
              Cluster{" "}
              <span className="font-mono">
                {res.cluster_label < 0 ? "Bruit (-1)" : `#${res.cluster_label}`}
              </span>{" "}
              <span className="font-mono text-xs text-muted-foreground">
                {res.cluster_id}
              </span>
            </CardTitle>
            <div className="flex items-center gap-3 text-xs text-muted-foreground">
              <span>{METHOD_LABEL[res.analysis_method] ?? res.analysis_method}</span>
              <span>
                features :{" "}
                <span className="font-mono">{res.feature_vector_size}</span>
              </span>
            </div>
          </CardHeader>
          <CardContent>
            {res.candidates.length > 0 ? (
              <div className="grid gap-3 md:grid-cols-2">
                {res.candidates.map((c) => (
                  <M5CandidateCard key={`${c.apt_id}-${c.rank}`} candidate={c} />
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">
                Aucun candidat retenu pour ce cluster.
              </p>
            )}
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
