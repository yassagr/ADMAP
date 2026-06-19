/**
 * Bandeau récapitulatif des alertes par sévérité. Chaque compteur est un bouton
 * filtrant la table (clic sur la sévérité active = retrait du filtre).
 */
import { SeverityBadge } from "@/components/shared";
import { cn } from "@/lib/utils";
import type { AlertBundle, AlertSeverity } from "@/types";

const SEVERITY_ORDER: readonly AlertSeverity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

export interface M2AlertSummaryProps {
  bundle: AlertBundle;
  activeSeverity: AlertSeverity | null;
  onSelectSeverity: (severity: AlertSeverity | null) => void;
}

/** Compte les alertes par sévérité (bundle agrégé, fallback recalcul). */
function severityCounts(bundle: AlertBundle): Record<AlertSeverity, number> {
  const base: Record<AlertSeverity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  const agg = bundle.alerts_by_severity ?? {};
  const hasAgg = Object.keys(agg).length > 0;
  if (hasAgg) {
    for (const sev of SEVERITY_ORDER) base[sev] = agg[sev] ?? 0;
    return base;
  }
  for (const alert of bundle.alerts) base[alert.severity] += 1;
  return base;
}

export function M2AlertSummary({
  bundle,
  activeSeverity,
  onSelectSeverity,
}: M2AlertSummaryProps) {
  const counts = severityCounts(bundle);

  return (
    <div className="flex flex-wrap gap-3">
      {SEVERITY_ORDER.map((severity) => {
        const active = activeSeverity === severity;
        return (
          <button
            key={severity}
            type="button"
            onClick={() => onSelectSeverity(active ? null : severity)}
            className={cn(
              "flex items-center gap-2 rounded-lg border px-3 py-2 transition-colors",
              active ? "border-primary" : "border-border hover:border-primary",
            )}
            style={{
              backgroundColor: active
                ? "rgba(0, 212, 255, 0.08)"
                : "var(--bg-secondary)",
            }}
          >
            <SeverityBadge severity={severity} />
            <span className="text-lg font-bold text-foreground">
              {counts[severity]}
            </span>
          </button>
        );
      })}
    </div>
  );
}
