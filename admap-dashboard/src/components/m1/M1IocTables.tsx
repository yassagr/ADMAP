/**
 * Tables d'IOC groupées par catégorie (IPs, domaines, URLs, hashes, registre,
 * mutex, commandes, …). Une `DataTable` triable/recherchable par catégorie non
 * vide ; chaque ligne se déplie pour exposer contexte, raisons de scoring et
 * résultat VirusTotal.
 */
import { DataTable, JsonViewer } from "@/components/shared";
import type { DataTableColumn } from "@/components/shared";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { IOC, IOCBundle, IOCType } from "@/types";

import { CONFIDENCE_COLOR, IOC_CATEGORIES, IOC_TYPE_LABEL } from "./ioc-taxonomy";

export interface M1IocTablesProps {
  bundle: IOCBundle;
}

/** Badge de niveau de confiance (couleur dérivée de la taxonomie). */
function ConfidenceBadge({ ioc }: { ioc: IOC }) {
  const color = CONFIDENCE_COLOR[ioc.confidence_level] ?? "#64748b";
  return (
    <span className="inline-flex items-center gap-2">
      <span className="font-mono text-foreground">
        {Math.round(ioc.confidence_score)}
      </span>
      <span
        className="rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase"
        style={{
          color,
          border: `1px solid ${color}`,
          backgroundColor: `${color}1a`,
        }}
      >
        {ioc.confidence_level}
      </span>
    </span>
  );
}

const COLUMNS: DataTableColumn<IOC>[] = [
  {
    key: "type",
    header: "Type",
    accessor: (r) => IOC_TYPE_LABEL[r.type] ?? r.type,
    sortable: true,
    render: (r) => (
      <span className="text-xs text-muted-foreground">
        {IOC_TYPE_LABEL[r.type] ?? r.type}
      </span>
    ),
  },
  {
    key: "value",
    header: "Valeur",
    accessor: (r) => r.value,
    sortable: true,
    render: (r) => (
      <span className="font-mono text-xs text-foreground">{r.value_defanged}</span>
    ),
  },
  {
    key: "confidence",
    header: "Confiance",
    accessor: (r) => r.confidence_score,
    sortable: true,
    render: (r) => <ConfidenceBadge ioc={r} />,
  },
  {
    key: "method",
    header: "Méthode",
    accessor: (r) => r.extraction_method,
    sortable: true,
    render: (r) => (
      <span className="text-xs text-muted-foreground">{r.extraction_method}</span>
    ),
  },
];

function renderExpanded(ioc: IOC) {
  return (
    <div className="flex flex-col gap-3 p-2 text-sm">
      {ioc.context_snippet && (
        <div>
          <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            Contexte
          </p>
          <code className="block whitespace-pre-wrap break-all rounded bg-black/30 px-2 py-1 text-xs text-foreground">
            {ioc.context_snippet}
          </code>
        </div>
      )}
      {ioc.scoring_reasons.length > 0 && (
        <div>
          <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            Raisons de scoring
          </p>
          <ul className="flex flex-wrap gap-1">
            {ioc.scoring_reasons.map((reason, i) => (
              <li
                key={`${reason}-${i}`}
                className="rounded border border-border px-1.5 py-0.5 text-xs text-foreground"
              >
                {reason}
              </li>
            ))}
          </ul>
        </div>
      )}
      {ioc.tags.length > 0 && (
        <div>
          <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            Tags
          </p>
          <ul className="flex flex-wrap gap-1">
            {ioc.tags.map((tag, i) => (
              <li
                key={`${tag}-${i}`}
                className="rounded border border-border px-1.5 py-0.5 font-mono text-[10px] text-foreground"
              >
                {tag}
              </li>
            ))}
          </ul>
        </div>
      )}
      {ioc.vt_result && (
        <div>
          <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            VirusTotal
          </p>
          <JsonViewer data={ioc.vt_result} defaultExpandedDepth={1} />
        </div>
      )}
    </div>
  );
}

export function M1IocTables({ bundle }: M1IocTablesProps) {
  const byType = new Map<IOCType, IOC[]>();
  for (const ioc of bundle.iocs) {
    const list = byType.get(ioc.type) ?? [];
    list.push(ioc);
    byType.set(ioc.type, list);
  }

  const sections = IOC_CATEGORIES.map((cat) => {
    const iocs = cat.types.flatMap((t) => byType.get(t as IOCType) ?? []);
    return { ...cat, iocs };
  }).filter((s) => s.iocs.length > 0);

  if (sections.length === 0) {
    return (
      <Card>
        <CardContent className="py-8 text-center text-sm text-muted-foreground">
          Aucun IOC extrait de ce fichier.
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      {sections.map((section) => (
        <Card key={section.key}>
          <CardHeader>
            <CardTitle className="text-base">
              {section.label} ({section.iocs.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={COLUMNS}
              data={section.iocs}
              pageSize={10}
              emptyMessage="Aucun IOC."
              renderExpanded={renderExpanded}
            />
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
