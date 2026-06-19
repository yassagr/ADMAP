/**
 * Résumé exécutif : synthèse chiffrée du run (alertes C2, campagnes APT,
 * principal acteur suspecté + score de confiance).
 */
import type { PipelineRunResults } from "@/store";

export interface ReportSummaryProps {
  results: PipelineRunResults;
}

interface Metric {
  label: string;
  value: string;
}

export function ReportSummary({ results }: ReportSummaryProps) {
  const alertCount = results.m2?.alerts.length ?? 0;
  const criticalCount =
    results.m2?.alerts.filter((a) => a.severity === "critical").length ?? 0;
  const campaignCount = results.m4?.campaign_count ?? 0;
  const top = results.m5?.top_global_candidate ?? null;

  const metrics: Metric[] = [
    { label: "Alertes C2 (M2)", value: String(alertCount) },
    { label: "dont critiques", value: String(criticalCount) },
    { label: "Campagnes APT (M4)", value: String(campaignCount) },
    {
      label: "Confiance attribution",
      value: top ? `${Math.round(top.confidence_score)} / 100` : "—",
    },
  ];

  return (
    <section className="report-section report-card rounded-lg border border-border bg-card p-6">
      <h2 className="text-lg font-bold text-white">Résumé exécutif</h2>

      <p className="mt-3 text-sm leading-relaxed text-slate-300">
        L'analyse du trafic réseau a produit{" "}
        <strong className="text-foreground">{alertCount}</strong> alerte(s) de
        commande-et-contrôle ({criticalCount} critique(s)), regroupée(s) en{" "}
        <strong className="text-foreground">{campaignCount}</strong> campagne(s)
        APT.{" "}
        {top ? (
          <>
            L'acteur le plus probable est{" "}
            <strong className="text-primary">{top.apt_name}</strong> ({top.apt_id}
            ), avec un score de confiance de{" "}
            <strong className="text-foreground">
              {Math.round(top.confidence_score)}/100
            </strong>
            .
          </>
        ) : (
          <>Aucun acteur APT n'a pu être retenu avec un niveau de confiance suffisant.</>
        )}
      </p>

      <dl className="mt-5 grid grid-cols-2 gap-4 sm:grid-cols-4">
        {metrics.map((m) => (
          <div
            key={m.label}
            className="rounded-md border border-border p-3 text-center"
          >
            <dd className="font-mono text-2xl font-bold text-primary">
              {m.value}
            </dd>
            <dt className="mt-1 text-xs text-muted-foreground">{m.label}</dt>
          </div>
        ))}
      </dl>
    </section>
  );
}
