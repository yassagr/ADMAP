/**
 * Verdict d'attribution (M5) — mis en évidence comme conclusion du rapport.
 * Acteur principal détaillé + tableau imprimable des top-k candidats APT
 * (score, probabilité XGBoost, similarité cosinus, techniques/tactiques).
 */
import type { APTCandidate, AttributionReport } from "@/types";

export interface ReportVerdictProps {
  report: AttributionReport;
  /** Nombre de candidats classés à présenter. */
  topK?: number;
}

function rankedCandidates(report: AttributionReport, topK: number): APTCandidate[] {
  return report.results
    .flatMap((r) => r.candidates)
    .sort((a, b) => b.confidence_score - a.confidence_score)
    .slice(0, topK);
}

export function ReportVerdict({ report, topK = 5 }: ReportVerdictProps) {
  const top = report.top_global_candidate;
  const ranked = rankedCandidates(report, topK);

  return (
    <section
      className="report-section report-card rounded-lg border p-6"
      style={{
        borderColor: "rgba(0, 212, 255, 0.55)",
        backgroundColor: "rgba(0, 212, 255, 0.05)",
      }}
    >
      <div className="flex items-baseline justify-between gap-3">
        <h2 className="text-lg font-bold text-white">Verdict d'attribution APT</h2>
        <span className="rounded border border-border px-2 py-0.5 font-mono text-xs text-muted-foreground">
          M5
        </span>
      </div>

      {top ? (
        <div className="mt-4 rounded-md border border-border p-4">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <div>
              <p className="text-xs uppercase tracking-wide text-muted-foreground">
                Acteur le plus probable
              </p>
              <p className="text-xl font-bold text-white">
                {top.apt_name}{" "}
                <span className="font-mono text-sm text-muted-foreground">
                  {top.apt_id}
                </span>
              </p>
            </div>
            <p className="font-mono text-2xl font-bold text-primary">
              {Math.round(top.confidence_score)}
              <span className="text-sm text-muted-foreground"> / 100</span>
            </p>
          </div>
          {top.evidence_summary && (
            <p className="mt-2 text-sm text-slate-300">{top.evidence_summary}</p>
          )}
        </div>
      ) : (
        <p className="mt-4 text-sm text-muted-foreground">
          Aucun candidat global retenu (clusters insuffisants ou bruit).
        </p>
      )}

      {ranked.length > 0 && (
        <div className="mt-5 overflow-x-auto">
          <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            Top {ranked.length} candidats
          </p>
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
                <th className="px-2 py-2">#</th>
                <th className="px-2 py-2">Acteur</th>
                <th className="px-2 py-2 text-right">Confiance</th>
                <th className="px-2 py-2 text-right">XGBoost</th>
                <th className="px-2 py-2 text-right">Cosine</th>
                <th className="px-2 py-2 text-right">Tech.</th>
                <th className="px-2 py-2">Tactiques</th>
              </tr>
            </thead>
            <tbody>
              {ranked.map((c) => (
                <tr key={`${c.apt_id}-${c.rank}`} className="border-b border-border">
                  <td className="px-2 py-2 font-mono">{c.rank}</td>
                  <td className="px-2 py-2">
                    <span className="font-semibold text-foreground">
                      {c.apt_name}
                    </span>{" "}
                    <span className="font-mono text-xs text-muted-foreground">
                      {c.apt_id}
                    </span>
                  </td>
                  <td className="px-2 py-2 text-right font-mono font-bold text-primary">
                    {Math.round(c.confidence_score)}
                  </td>
                  <td className="px-2 py-2 text-right font-mono">
                    {(c.xgb_probability * 100).toFixed(1)}%
                  </td>
                  <td className="px-2 py-2 text-right font-mono">
                    {(c.cosine_similarity * 100).toFixed(1)}%
                  </td>
                  <td className="px-2 py-2 text-right font-mono">
                    {c.matched_techniques.length}
                  </td>
                  <td className="px-2 py-2 text-xs text-muted-foreground">
                    {c.matched_tactics.join(", ") || "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <p className="mt-3 text-xs text-muted-foreground">
        {report.total_clusters_analyzed} cluster(s) analysé(s),{" "}
        {report.noise_clusters_skipped} ignoré(s) (bruit).
      </p>
    </section>
  );
}
