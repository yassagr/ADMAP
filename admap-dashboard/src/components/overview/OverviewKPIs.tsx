/**
 * Cartes KPI du tableau de bord Overview : totaux agrégés de l'historique
 * (analyses, IOC, alertes, campagnes, acteurs APT, dernière analyse).
 */
import {
  Activity,
  AlertTriangle,
  Fingerprint,
  Network,
  ScanSearch,
  Clock,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

import { Card, CardContent } from "@/components/ui/card";
import type { OverviewKpis } from "@/lib/overview-stats";

export interface OverviewKPIsProps {
  kpis: OverviewKpis;
}

interface Kpi {
  label: string;
  value: string;
  icon: LucideIcon;
  color: string;
}

function formatDate(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("fr-FR", {
    dateStyle: "short",
    timeStyle: "short",
  });
}

export function OverviewKPIs({ kpis }: OverviewKPIsProps) {
  const cards: Kpi[] = [
    { label: "Analyses", value: String(kpis.totalAnalyses), icon: Activity, color: "#00d4ff" },
    { label: "IOC extraits", value: String(kpis.totalIocs), icon: ScanSearch, color: "#6ee7b7" },
    { label: "Alertes C2", value: String(kpis.totalAlerts), icon: AlertTriangle, color: "#ff6b35" },
    { label: "Campagnes", value: String(kpis.totalCampaigns), icon: Network, color: "#a78bfa" },
    { label: "Acteurs APT", value: String(kpis.aptActors), icon: Fingerprint, color: "#f59e0b" },
    { label: "Dernière analyse", value: formatDate(kpis.lastAnalysisAt), icon: Clock, color: "#7dd3fc" },
  ];

  return (
    <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
      {cards.map((c) => {
        const Icon = c.icon;
        return (
          <Card key={c.label}>
            <CardContent className="flex flex-col gap-1 p-4">
              <Icon className="h-5 w-5" style={{ color: c.color }} />
              <span className="mt-1 truncate text-xl font-bold text-foreground">
                {c.value}
              </span>
              <span className="text-xs text-muted-foreground">{c.label}</span>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}
