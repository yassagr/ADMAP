/**
 * Bandeau récapitulatif M4 : campagnes détectées, profils de bruit, profils
 * totaux. Chaque carte est un bouton ; cliquer réinitialise le filtre de cluster
 * actif (vue d'ensemble), à l'image du bandeau de sévérité de M2.
 */
import { GitBranch, Layers, Workflow } from "lucide-react";
import type { LucideIcon } from "lucide-react";

import { cn } from "@/lib/utils";
import type { APTMapReport } from "@/types";

export interface M4CampaignSummaryProps {
  report: APTMapReport;
  /** Cluster actuellement filtré (null = vue globale). */
  selectedClusterId: string | null;
  /** Réinitialise le filtre de cluster. */
  onClear: () => void;
}

interface StatCard {
  key: string;
  label: string;
  value: number;
  icon: LucideIcon;
  color: string;
}

export function M4CampaignSummary({
  report,
  selectedClusterId,
  onClear,
}: M4CampaignSummaryProps) {
  const cards: StatCard[] = [
    {
      key: "campaigns",
      label: "Campagnes",
      value: report.campaign_count,
      icon: GitBranch,
      color: "#00d4ff",
    },
    {
      key: "noise",
      label: "Bruit",
      value: report.noise_count,
      icon: Workflow,
      color: "#64748b",
    },
    {
      key: "profiles",
      label: "Profils",
      value: report.cluster_bundle.total_profiles,
      icon: Layers,
      color: "#a3e635",
    },
  ];

  return (
    <div className="flex flex-wrap items-center gap-3">
      {cards.map((card) => {
        const Icon = card.icon;
        return (
          <button
            key={card.key}
            type="button"
            onClick={onClear}
            className={cn(
              "flex items-center gap-3 rounded-lg border px-4 py-2 transition-colors",
              "border-border hover:border-primary",
            )}
            style={{ backgroundColor: "var(--bg-secondary)" }}
          >
            <Icon className="h-5 w-5" style={{ color: card.color }} />
            <div className="flex flex-col items-start leading-tight">
              <span className="text-xs uppercase tracking-wide text-muted-foreground">
                {card.label}
              </span>
              <span className="text-lg font-bold text-foreground">
                {card.value}
              </span>
            </div>
          </button>
        );
      })}
      {selectedClusterId && (
        <button
          type="button"
          onClick={onClear}
          className="text-xs text-primary hover:underline"
        >
          Filtre actif : cluster {selectedClusterId} · réinitialiser
        </button>
      )}
    </div>
  );
}
