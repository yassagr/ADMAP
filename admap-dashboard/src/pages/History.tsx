/**
 * Page Historique (/history) — table centralisée de toutes les analyses
 * persistées (modules M1-M5 + pipeline). Filtres module / plage de dates /
 * recherche texte, lignes dépliables (détail JSON), génération de rapport par
 * analyse et suppression. Aucun tableau dupliqué ailleurs.
 */
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { FileText, History as HistoryIcon, Trash2 } from "lucide-react";

import { useAdmapStore } from "@/store";
import { fadeInUp } from "@/lib/motion";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  DataTable,
  JsonViewer,
  ModuleBadge,
  type DataTableColumn,
} from "@/components/shared";
import { HistoryFilters, type HistoryFilterState } from "@/components/history";
import type { AnalysisRecord } from "@/types";

const INITIAL_FILTER: HistoryFilterState = {
  module: "ALL",
  from: "",
  to: "",
  query: "",
};

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString("fr-FR", {
    dateStyle: "short",
    timeStyle: "short",
  });
}

function EmptyState() {
  return (
    <section className="flex flex-col items-center justify-center gap-4 py-24 text-center">
      <HistoryIcon className="h-12 w-12 text-muted-foreground" />
      <div>
        <h1 className="text-xl font-bold text-white">Historique vide</h1>
        <p className="mt-1 text-slate-400">
          Aucune analyse enregistrée pour le moment.
        </p>
      </div>
      <div className="flex flex-wrap justify-center gap-2">
        <Button asChild>
          <Link to="/pipeline">Lancer le pipeline</Link>
        </Button>
        <Button asChild variant="outline">
          <Link to="/m1">Analyser un fichier (M1)</Link>
        </Button>
      </div>
    </section>
  );
}

export function History() {
  const history = useAdmapStore((s) => s.analysisHistory);
  const removeRecord = useAdmapStore((s) => s.removeRecord);
  const clearHistory = useAdmapStore((s) => s.clearHistory);

  const [filters, setFilters] = useState<HistoryFilterState>(INITIAL_FILTER);

  const filtered = useMemo(() => {
    const q = filters.query.trim().toLowerCase();
    // Bornes de dates incluses (du début du jour `from` à la fin du jour `to`).
    const fromTs = filters.from ? new Date(`${filters.from}T00:00:00`).getTime() : null;
    const toTs = filters.to ? new Date(`${filters.to}T23:59:59`).getTime() : null;

    return history.filter((r) => {
      if (filters.module !== "ALL" && r.module !== filters.module) return false;
      if (q && !r.inputName.toLowerCase().includes(q)) return false;
      const ts = new Date(r.createdAt).getTime();
      if (fromTs !== null && ts < fromTs) return false;
      if (toTs !== null && ts > toTs) return false;
      return true;
    });
  }, [history, filters]);

  const columns: DataTableColumn<AnalysisRecord>[] = [
    {
      key: "date",
      header: "Date",
      sortable: true,
      accessor: (r) => r.createdAt,
      render: (r) => (
        <span className="text-xs text-muted-foreground">{formatDate(r.createdAt)}</span>
      ),
    },
    {
      key: "module",
      header: "Module",
      accessor: (r) => r.module,
      sortable: true,
      render: (r) => <ModuleBadge module={r.module} />,
    },
    {
      key: "input",
      header: "Entrée",
      accessor: (r) => r.inputName,
      sortable: true,
      render: (r) => <span className="font-mono text-xs">{r.inputName}</span>,
    },
    {
      key: "metric",
      header: "Métrique clé",
      accessor: (r) => r.summary.headline,
      render: (r) => (
        <div className="flex flex-col gap-0.5">
          <span className="font-semibold text-foreground">{r.summary.headline}</span>
          {r.summary.details.length > 0 && (
            <span className="text-xs text-muted-foreground">
              {r.summary.details.join(" · ")}
            </span>
          )}
        </div>
      ),
    },
    {
      key: "actions",
      header: "Actions",
      render: (r) => (
        <div
          className="flex gap-2"
          onClick={(e) => e.stopPropagation()}
          role="presentation"
        >
          <Button asChild variant="outline" size="sm">
            <Link to="/report" state={{ recordId: r.id }}>
              <FileText className="h-4 w-4" />
              Rapport
            </Link>
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => removeRecord(r.id)}
            title="Supprimer"
          >
            <Trash2 className="h-4 w-4 text-destructive" />
          </Button>
        </div>
      ),
    },
  ];

  if (history.length === 0) return <EmptyState />;

  return (
    <motion.section
      className="flex flex-col gap-6"
      variants={fadeInUp}
      initial="hidden"
      animate="visible"
    >
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white">Historique</h1>
          <p className="mt-1 text-slate-400">
            {history.length} analyse(s) enregistrée(s) · 25 max conservées.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={clearHistory}>
          <Trash2 className="h-4 w-4" />
          Vider l'historique
        </Button>
      </header>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Filtres</CardTitle>
        </CardHeader>
        <CardContent>
          <HistoryFilters value={filters} onChange={setFilters} />
        </CardContent>
      </Card>

      <DataTable
        columns={columns}
        data={filtered}
        searchable={false}
        pageSize={10}
        emptyMessage="Aucune analyse ne correspond aux filtres."
        renderExpanded={(r) => (
          <div className="flex flex-col gap-2">
            <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Détail du résultat
            </span>
            <JsonViewer data={r.result} defaultExpandedDepth={1} />
          </div>
        )}
      />
    </motion.section>
  );
}
