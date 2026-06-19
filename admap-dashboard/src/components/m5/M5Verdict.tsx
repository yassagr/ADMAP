/**
 * Verdict d'attribution APT (M5) : met en avant `top_global_candidate` avec une
 * jauge de confiance, puis le top-k des candidats classés. Composant partagé —
 * point culminant de la page Pipeline ET en-tête de la page M5.
 */
import { Trophy } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScoreGauge } from "@/components/shared";
import type { AttributionReport } from "@/types";

import { M5CandidateCard } from "./M5CandidateCard";

export interface M5VerdictProps {
  report: AttributionReport;
  /** Nombre de candidats classés affichés (défaut 5). */
  topK?: number;
}

export function M5Verdict({ report, topK = 5 }: M5VerdictProps) {
  const top = report.top_global_candidate;
  const ranked = report.results
    .flatMap((r) => r.candidates)
    .sort((a, b) => b.confidence_score - a.confidence_score)
    .slice(0, topK);

  return (
    <Card
      style={{
        borderColor: "rgba(0, 212, 255, 0.55)",
        backgroundColor: "rgba(0, 212, 255, 0.05)",
      }}
    >
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-lg">
          <Trophy className="h-5 w-5 text-primary" />
          Verdict d'attribution APT (M5)
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-6">
        {top ? (
          <div className="flex flex-col items-center gap-4 sm:flex-row sm:items-center">
            <ScoreGauge value={top.confidence_score} label="confiance" size={132} />
            <div className="flex flex-1 flex-col gap-2 text-center sm:text-left">
              <div>
                <p className="text-xs uppercase tracking-wide text-muted-foreground">
                  Acteur le plus probable
                </p>
                <a
                  href={top.mitre_group_url}
                  target="_blank"
                  rel="noreferrer"
                  className="text-2xl font-bold text-white hover:text-primary hover:underline"
                >
                  {top.apt_name}
                </a>
                <span className="ml-2 font-mono text-sm text-muted-foreground">
                  {top.apt_id}
                </span>
              </div>
              <div className="flex flex-wrap justify-center gap-4 text-sm sm:justify-start">
                <span className="text-muted-foreground">
                  XGBoost :{" "}
                  <span className="font-mono text-foreground">
                    {(top.xgb_probability * 100).toFixed(1)}%
                  </span>
                </span>
                <span className="text-muted-foreground">
                  Cosine :{" "}
                  <span className="font-mono text-foreground">
                    {(top.cosine_similarity * 100).toFixed(1)}%
                  </span>
                </span>
                <span className="text-muted-foreground">
                  Techniques :{" "}
                  <span className="font-mono text-foreground">
                    {top.matched_techniques.length}
                  </span>
                </span>
              </div>
              {top.evidence_summary && (
                <p className="text-sm text-slate-400">{top.evidence_summary}</p>
              )}
            </div>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">
            Aucun candidat global retenu (clusters insuffisants ou bruit).
          </p>
        )}

        {ranked.length > 0 && (
          <div className="flex flex-col gap-3">
            <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Top {ranked.length} candidats
            </p>
            <div className="grid gap-3 md:grid-cols-2">
              {ranked.map((c) => (
                <M5CandidateCard key={`${c.apt_id}-${c.rank}`} candidate={c} />
              ))}
            </div>
          </div>
        )}

        <p className="text-xs text-muted-foreground">
          {report.total_clusters_analyzed} cluster(s) analysé(s),{" "}
          {report.noise_clusters_skipped} ignoré(s) (bruit).
        </p>
      </CardContent>
    </Card>
  );
}
