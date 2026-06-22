/**
 * Tableau des dernières analyses de l'historique, avec lien vers la page
 * Historique complète (/history).
 */
import { Link } from "react-router-dom";
import { ArrowRight } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ModuleBadge } from "@/components/shared";
import type { AnalysisRecord } from "@/types";

export interface OverviewRecentProps {
  records: AnalysisRecord[];
  /** Nombre d'entrées affichées (par défaut 5). */
  limit?: number;
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString("fr-FR", {
    dateStyle: "short",
    timeStyle: "short",
  });
}

export function OverviewRecent({ records, limit = 5 }: OverviewRecentProps) {
  const recent = records.slice(0, limit);

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between space-y-0">
        <CardTitle className="text-base">Dernières analyses</CardTitle>
        <Link
          to="/history"
          className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
        >
          Tout l'historique
          <ArrowRight className="h-3 w-3" />
        </Link>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
                <th className="px-2 py-2">Date</th>
                <th className="px-2 py-2">Module</th>
                <th className="px-2 py-2">Entrée</th>
                <th className="px-2 py-2">Métrique</th>
              </tr>
            </thead>
            <tbody>
              {recent.map((r) => (
                <tr key={r.id} className="border-b border-border">
                  <td className="px-2 py-2 text-xs text-muted-foreground">
                    {formatDate(r.createdAt)}
                  </td>
                  <td className="px-2 py-2">
                    <ModuleBadge module={r.module} />
                  </td>
                  <td className="px-2 py-2 font-mono text-xs">{r.inputName}</td>
                  <td className="px-2 py-2 font-semibold text-foreground">
                    {r.summary.headline}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}
