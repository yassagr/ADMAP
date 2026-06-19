/**
 * Section générique d'un rapport imprimable.
 *
 * Carte titrée, neutre pour l'écran (thème sombre) comme pour l'impression
 * (classes `report-section`/`report-card` ciblées par `@media print` dans
 * index.css : fond blanc, encre noire, `page-break-inside: avoid`).
 */
import type { ReactNode } from "react";

export interface ReportSectionProps {
  title: string;
  subtitle?: string;
  /** Pastille de module affichée à droite du titre (ex. "M4"). */
  badge?: string;
  children: ReactNode;
}

export function ReportSection({
  title,
  subtitle,
  badge,
  children,
}: ReportSectionProps) {
  return (
    <section className="report-section report-card rounded-lg border border-border bg-card p-6">
      <div className="flex items-baseline justify-between gap-3">
        <h2 className="text-lg font-bold text-white">{title}</h2>
        {badge && (
          <span className="rounded border border-border px-2 py-0.5 font-mono text-xs text-muted-foreground">
            {badge}
          </span>
        )}
      </div>
      {subtitle && <p className="mt-1 text-sm text-muted-foreground">{subtitle}</p>}
      <div className="mt-4">{children}</div>
    </section>
  );
}
