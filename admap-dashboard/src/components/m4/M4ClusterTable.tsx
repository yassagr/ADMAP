/**
 * Table des `CampaignCluster` : tri, recherche (DataTable) et lignes dépliables
 * exposant member_profile_ids, dominant_techniques, dominant_tactics,
 * involved_ips, yara_tags et metadata. Filtrage par cluster piloté en amont.
 */
import { DataTable, JsonViewer } from "@/components/shared";
import type { DataTableColumn } from "@/components/shared";
import type { CampaignCluster } from "@/types";

export interface M4ClusterTableProps {
  /** Clusters déjà filtrés en amont. */
  clusters: CampaignCluster[];
}

/** Bloc de listing pour une section dépliée (puces ou tirets). */
function ChipList({ label, items }: { label: string; items: string[] }) {
  return (
    <div>
      <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        {label} ({items.length})
      </p>
      {items.length > 0 ? (
        <ul className="flex flex-wrap gap-1">
          {items.map((item, i) => (
            <li
              key={`${item}-${i}`}
              className="rounded border border-border px-1.5 py-0.5 font-mono text-xs text-foreground"
            >
              {item}
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-xs text-muted-foreground">—</p>
      )}
    </div>
  );
}

export function M4ClusterTable({ clusters }: M4ClusterTableProps) {
  const columns: DataTableColumn<CampaignCluster>[] = [
    {
      key: "cluster_id",
      header: "ID",
      accessor: (r) => r.cluster_id,
      sortable: true,
      render: (r) => <span className="font-mono text-xs">{r.cluster_id}</span>,
    },
    {
      key: "cluster_label",
      header: "Label",
      accessor: (r) => r.cluster_label,
      sortable: true,
      render: (r) =>
        r.cluster_label < 0 ? (
          <span className="text-muted-foreground">Bruit (-1)</span>
        ) : (
          <span className="font-mono">#{r.cluster_label}</span>
        ),
    },
    {
      key: "members",
      header: "Membres",
      accessor: (r) => r.member_profile_ids.length,
      sortable: true,
    },
    {
      key: "confidence",
      header: "Confiance",
      accessor: (r) => r.confidence_score,
      sortable: true,
      render: (r) => (
        <span className="font-mono">{Math.round(r.confidence_score)}</span>
      ),
    },
    {
      key: "first_seen",
      header: "First Seen",
      accessor: (r) => r.first_seen,
      sortable: true,
      render: (r) => (
        <span className="text-xs text-muted-foreground">{r.first_seen}</span>
      ),
    },
  ];

  const renderExpanded = (cluster: CampaignCluster) => (
    <div className="flex flex-col gap-3 p-2 text-sm">
      <div className="grid gap-3 md:grid-cols-2">
        <ChipList label="Profils membres" items={cluster.member_profile_ids} />
        <ChipList label="IPs impliquées" items={cluster.involved_ips} />
        <ChipList label="Techniques dominantes" items={cluster.dominant_techniques} />
        <ChipList label="Tactiques dominantes" items={cluster.dominant_tactics} />
        <ChipList label="Tags YARA" items={cluster.yara_tags} />
      </div>
      <div>
        <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          Metadata
        </p>
        <JsonViewer data={cluster.metadata} defaultExpandedDepth={1} />
      </div>
    </div>
  );

  return (
    <DataTable
      columns={columns}
      data={clusters}
      pageSize={10}
      emptyMessage="Aucun cluster pour ce filtre."
      renderExpanded={renderExpanded}
    />
  );
}
