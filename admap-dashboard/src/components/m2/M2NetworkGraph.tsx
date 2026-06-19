/**
 * Graphe réseau M2 : adaptateur de l'AlertBundle vers le `NetworkGraph`
 * générique. Nœuds = IPs (taille ∝ nombre d'alertes, couleur = sévérité max),
 * arêtes = flux src→dst. Clic sur un nœud → sélection de l'IP (filtre amont).
 */
import { useMemo } from "react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { NetworkGraph } from "@/components/shared";
import type { GraphLink, GraphNode } from "@/components/shared";
import type { AlertBundle, AlertSeverity, C2Alert } from "@/types";

const SEVERITY_RANK: Record<AlertSeverity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

const SEVERITY_COLOR: Record<AlertSeverity, string> = {
  critical: "#ff2d55",
  high: "#ff6b35",
  medium: "#f59e0b",
  low: "#00d4ff",
  info: "#94a3b8",
};

function buildGraph(alerts: C2Alert[]): { nodes: GraphNode[]; links: GraphLink[] } {
  const counts = new Map<string, number>();
  const maxSeverity = new Map<string, AlertSeverity>();
  const linkSeverity = new Map<string, { link: GraphLink; sev: AlertSeverity }>();

  const bump = (ip: string, sev: AlertSeverity): void => {
    if (!ip) return;
    counts.set(ip, (counts.get(ip) ?? 0) + 1);
    const cur = maxSeverity.get(ip);
    if (!cur || SEVERITY_RANK[sev] > SEVERITY_RANK[cur]) maxSeverity.set(ip, sev);
  };

  for (const alert of alerts) {
    bump(alert.src_ip, alert.severity);
    bump(alert.dst_ip, alert.severity);
    if (alert.src_ip && alert.dst_ip) {
      const key = `${alert.src_ip}->${alert.dst_ip}`;
      const prev = linkSeverity.get(key);
      if (!prev || SEVERITY_RANK[alert.severity] > SEVERITY_RANK[prev.sev]) {
        linkSeverity.set(key, {
          link: { source: alert.src_ip, target: alert.dst_ip },
          sev: alert.severity,
        });
      }
    }
  }

  const nodes: GraphNode[] = [...counts.entries()].map(([ip, count]) => {
    const sev = maxSeverity.get(ip) ?? "info";
    return {
      id: ip,
      label: ip,
      color: SEVERITY_COLOR[sev],
      size: 7 + Math.min(18, count * 2),
    };
  });

  const links: GraphLink[] = [...linkSeverity.values()].map(({ link, sev }) => ({
    ...link,
    color:
      sev === "critical" || sev === "high"
        ? "rgba(255, 107, 53, 0.45)"
        : "rgba(148, 163, 184, 0.3)",
  }));

  return { nodes, links };
}

export interface M2NetworkGraphProps {
  bundle: AlertBundle;
  selectedIp: string | null;
  onSelectIp: (ip: string | null) => void;
}

export function M2NetworkGraph({
  bundle,
  selectedIp,
  onSelectIp,
}: M2NetworkGraphProps) {
  const { nodes, links } = useMemo(() => buildGraph(bundle.alerts), [bundle.alerts]);

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between space-y-0">
        <CardTitle className="text-base">Graphe réseau ({nodes.length} IPs)</CardTitle>
        {selectedIp && (
          <button
            type="button"
            onClick={() => onSelectIp(null)}
            className="text-xs text-primary hover:underline"
          >
            Effacer la sélection ({selectedIp})
          </button>
        )}
      </CardHeader>
      <CardContent>
        <NetworkGraph
          nodes={nodes}
          links={links}
          height={460}
          selectedId={selectedIp}
          onNodeClick={(node) =>
            onSelectIp(node.id === selectedIp ? null : node.id)
          }
          emptyMessage="Aucun flux réseau à visualiser."
        />
        <p className="mt-2 text-xs text-muted-foreground">
          Molette : zoom · glisser le fond : déplacer · glisser un nœud :
          repositionner · clic : filtrer par IP.
        </p>
      </CardContent>
    </Card>
  );
}
