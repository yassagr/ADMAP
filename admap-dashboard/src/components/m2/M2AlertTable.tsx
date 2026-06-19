/**
 * Table des C2Alert : tri, recherche (DataTable), filtre par type (local) et
 * lignes dépliables exposant evidence / ioc_matches / metadata via JsonViewer.
 * Le filtre par sévérité est piloté en amont (bandeau récapitulatif).
 */
import { useMemo, useState } from "react";

import { cn } from "@/lib/utils";
import { DataTable, JsonViewer, SeverityBadge } from "@/components/shared";
import type { DataTableColumn } from "@/components/shared";
import type { AlertSeverity, AlertType, C2Alert } from "@/types";

const SEVERITY_RANK: Record<AlertSeverity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

export interface M2AlertTableProps {
  /** Alertes déjà filtrées par sévérité / IP en amont. */
  alerts: C2Alert[];
}

export function M2AlertTable({ alerts }: M2AlertTableProps) {
  const [typeFilter, setTypeFilter] = useState<AlertType | null>(null);

  const availableTypes = useMemo(() => {
    const set = new Set<AlertType>();
    for (const a of alerts) set.add(a.alert_type);
    return [...set].sort();
  }, [alerts]);

  const rows = useMemo(
    () => (typeFilter ? alerts.filter((a) => a.alert_type === typeFilter) : alerts),
    [alerts, typeFilter],
  );

  const columns: DataTableColumn<C2Alert>[] = [
    {
      key: "id",
      header: "ID",
      accessor: (r) => r.id,
      sortable: true,
      render: (r) => <span className="font-mono text-xs">{r.id}</span>,
    },
    {
      key: "alert_type",
      header: "Type",
      accessor: (r) => r.alert_type,
      sortable: true,
    },
    {
      key: "severity",
      header: "Sévérité",
      accessor: (r) => SEVERITY_RANK[r.severity],
      sortable: true,
      render: (r) => <SeverityBadge severity={r.severity} />,
    },
    {
      key: "score",
      header: "Score",
      accessor: (r) => r.confidence_score,
      sortable: true,
      render: (r) => <span className="font-mono">{r.confidence_score}</span>,
    },
    { key: "src_ip", header: "Src IP", accessor: (r) => r.src_ip },
    { key: "dst_ip", header: "Dst IP", accessor: (r) => r.dst_ip },
    { key: "protocol", header: "Proto", accessor: (r) => r.protocol },
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

  const renderExpanded = (alert: C2Alert) => (
    <div className="flex flex-col gap-3 p-2 text-sm">
      {alert.description && (
        <p className="text-muted-foreground">{alert.description}</p>
      )}
      <div className="grid gap-3 md:grid-cols-2">
        <div>
          <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            Evidence ({alert.evidence.length})
          </p>
          {alert.evidence.length > 0 ? (
            <ul className="list-inside list-disc space-y-0.5 text-xs">
              {alert.evidence.map((e, i) => (
                <li key={i}>{e}</li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-muted-foreground">—</p>
          )}
        </div>
        <div>
          <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            IOC matches ({alert.ioc_matches.length})
          </p>
          {alert.ioc_matches.length > 0 ? (
            <ul className="list-inside list-disc space-y-0.5 font-mono text-xs">
              {alert.ioc_matches.map((m, i) => (
                <li key={i}>{m}</li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-muted-foreground">—</p>
          )}
        </div>
      </div>
      <div>
        <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          Metadata
        </p>
        <JsonViewer data={alert.metadata} defaultExpandedDepth={1} />
      </div>
    </div>
  );

  return (
    <div className="flex flex-col gap-3">
      {availableTypes.length > 1 && (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs uppercase tracking-wide text-muted-foreground">
            Type :
          </span>
          <TypeChip
            label="Tous"
            active={typeFilter === null}
            onClick={() => setTypeFilter(null)}
          />
          {availableTypes.map((type) => (
            <TypeChip
              key={type}
              label={type}
              active={typeFilter === type}
              onClick={() => setTypeFilter(type)}
            />
          ))}
        </div>
      )}
      <DataTable
        columns={columns}
        data={rows}
        pageSize={10}
        emptyMessage="Aucune alerte pour ces filtres."
        renderExpanded={renderExpanded}
      />
    </div>
  );
}

function TypeChip({
  label,
  active,
  onClick,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "rounded-md border px-2 py-0.5 text-xs transition-colors",
        active
          ? "border-primary text-primary"
          : "border-border text-muted-foreground hover:border-primary",
      )}
      style={{
        backgroundColor: active ? "rgba(0, 212, 255, 0.08)" : "transparent",
      }}
    >
      {label}
    </button>
  );
}
