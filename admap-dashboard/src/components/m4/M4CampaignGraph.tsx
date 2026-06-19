/**
 * Graphe de campagnes M4 : adaptateur du `ClusterBundle` vers le `NetworkGraph`
 * générique. Un nœud par profil ; couleur = cluster (label DBSCAN), bruit (-1)
 * en gris distinct. Arêtes en étoile reliant les membres d'un même cluster.
 * Clic sur un nœud → sélection du cluster (filtre amont) ; clic sur un nœud de
 * bruit → réinitialisation.
 */
import { useMemo } from "react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { NetworkGraph } from "@/components/shared";
import type { GraphLink, GraphNode } from "@/components/shared";
import type { APTMapReport } from "@/types";

/** Palette de clusters (thème ADMAP, purple réservé à l'IA → exclu). */
const CLUSTER_PALETTE: readonly string[] = [
  "#00d4ff",
  "#ff6b35",
  "#a3e635",
  "#facc15",
  "#22d3ee",
  "#fb7185",
  "#38bdf8",
  "#f59e0b",
  "#34d399",
  "#60a5fa",
];
const NOISE_COLOR = "#64748b";
/** Couleur des nœuds hors du cluster sélectionné. */
const DIM_COLOR = "rgba(100, 116, 139, 0.3)";

/** Couleur d'un cluster d'après son label DBSCAN (-1 = bruit). */
function clusterColor(label: number): string {
  if (label < 0) return NOISE_COLOR;
  return CLUSTER_PALETTE[label % CLUSTER_PALETTE.length];
}

/** Raccourcit un identifiant de profil long pour le label du nœud. */
function shortLabel(id: string): string {
  return id.length > 12 ? `${id.slice(0, 10)}…` : id;
}

interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
  /** profileId → cluster_id (pour le clic). */
  clusterByProfile: Map<string, string>;
}

function buildGraph(report: APTMapReport, selectedClusterId: string | null): GraphData {
  const nodes: GraphNode[] = [];
  const links: GraphLink[] = [];
  const clusterByProfile = new Map<string, string>();

  for (const cluster of report.cluster_bundle.clusters) {
    const base = clusterColor(cluster.cluster_label);
    const active = !selectedClusterId || selectedClusterId === cluster.cluster_id;
    const color = active ? base : DIM_COLOR;
    const linkColor = active
      ? "rgba(0, 212, 255, 0.35)"
      : "rgba(100, 116, 139, 0.15)";

    cluster.member_profile_ids.forEach((pid, i) => {
      clusterByProfile.set(pid, cluster.cluster_id);
      nodes.push({
        id: pid,
        label: shortLabel(pid),
        color,
        size: 8 + Math.min(10, cluster.member_profile_ids.length),
      });
      // Étoile : chaque membre relié au premier du cluster.
      if (i > 0) {
        links.push({
          source: cluster.member_profile_ids[0],
          target: pid,
          color: linkColor,
        });
      }
    });
  }

  for (const pid of report.cluster_bundle.noise_profile_ids) {
    nodes.push({
      id: pid,
      label: shortLabel(pid),
      color: selectedClusterId ? DIM_COLOR : NOISE_COLOR,
      size: 6,
    });
  }

  return { nodes, links, clusterByProfile };
}

export interface M4CampaignGraphProps {
  report: APTMapReport;
  selectedClusterId: string | null;
  onSelectCluster: (clusterId: string | null) => void;
}

export function M4CampaignGraph({
  report,
  selectedClusterId,
  onSelectCluster,
}: M4CampaignGraphProps) {
  const { nodes, links, clusterByProfile } = useMemo(
    () => buildGraph(report, selectedClusterId),
    [report, selectedClusterId],
  );

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between space-y-0">
        <CardTitle className="text-base">
          Graphe de campagnes ({nodes.length} profils)
        </CardTitle>
        {selectedClusterId && (
          <button
            type="button"
            onClick={() => onSelectCluster(null)}
            className="text-xs text-primary hover:underline"
          >
            Effacer la sélection ({selectedClusterId})
          </button>
        )}
      </CardHeader>
      <CardContent>
        <NetworkGraph
          nodes={nodes}
          links={links}
          height={460}
          onNodeClick={(node) => {
            const clusterId = clusterByProfile.get(node.id) ?? null;
            onSelectCluster(clusterId === selectedClusterId ? null : clusterId);
          }}
          emptyMessage="Aucun profil à visualiser."
        />
        <p className="mt-2 text-xs text-muted-foreground">
          Couleur = campagne · gris = bruit (label -1) · molette : zoom ·
          glisser : déplacer · clic sur un profil : filtrer par campagne.
        </p>
      </CardContent>
    </Card>
  );
}
