/**
 * Liste des règles YARA générées : table triable (nom, statut de compilation
 * `yara.compile()`, score, tokens) dont chaque ligne se déplie pour afficher le
 * texte `.yar` brut, les chaînes, la condition et les métadonnées.
 */
import { CheckCircle2, XCircle } from "lucide-react";

import { DataTable, JsonViewer } from "@/components/shared";
import type { DataTableColumn } from "@/components/shared";
import type { YaraRule } from "@/types";

export interface M3RulesListProps {
  rules: YaraRule[];
}

/** Badge du statut de compilation `yara.compile()`. */
function CompileBadge({ compiled }: { compiled: boolean }) {
  const color = compiled ? "#6ee7b7" : "#ff8aa0";
  const Icon = compiled ? CheckCircle2 : XCircle;
  return (
    <span
      className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase"
      style={{ color, border: `1px solid ${color}`, backgroundColor: `${color}1a` }}
    >
      <Icon className="h-3 w-3" />
      {compiled ? "OK" : "Échec"}
    </span>
  );
}

const COLUMNS: DataTableColumn<YaraRule>[] = [
  {
    key: "rule_name",
    header: "Règle",
    accessor: (r) => r.rule_name,
    sortable: true,
    render: (r) => (
      <span className="font-mono text-xs text-foreground">{r.rule_name}</span>
    ),
  },
  {
    key: "compiled",
    header: "Compilation",
    accessor: (r) => (r.compiled ? 1 : 0),
    sortable: true,
    render: (r) => <CompileBadge compiled={r.compiled} />,
  },
  {
    key: "confidence",
    header: "Score",
    accessor: (r) => r.confidence_score,
    sortable: true,
    render: (r) => (
      <span className="font-mono">{Math.round(r.confidence_score)}</span>
    ),
  },
  {
    key: "tokens",
    header: "Tokens",
    accessor: (r) => r.token_count,
    sortable: true,
    render: (r) => (
      <span className="font-mono text-xs text-muted-foreground">
        {r.token_count}
      </span>
    ),
  },
];

function renderExpanded(rule: YaraRule) {
  return (
    <div className="flex flex-col gap-3 p-2 text-sm">
      <div>
        <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          Règle YARA brute
        </p>
        <pre className="overflow-x-auto rounded bg-black/40 px-3 py-2 text-xs leading-relaxed text-foreground">
          <code>{rule.raw_yara}</code>
        </pre>
      </div>
      {rule.strings.length > 0 && (
        <div>
          <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            Chaînes ({rule.strings.length})
          </p>
          <ul className="flex flex-col gap-0.5">
            {rule.strings.map((s, i) => (
              <li
                key={`${i}-${s}`}
                className="break-all font-mono text-xs text-foreground"
              >
                {s}
              </li>
            ))}
          </ul>
        </div>
      )}
      <div>
        <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          Condition
        </p>
        <code className="block break-all rounded bg-black/30 px-2 py-1 text-xs text-foreground">
          {rule.condition}
        </code>
      </div>
      <div>
        <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          Métadonnées
        </p>
        <JsonViewer data={rule.metadata} defaultExpandedDepth={1} />
      </div>
    </div>
  );
}

export function M3RulesList({ rules }: M3RulesListProps) {
  return (
    <DataTable
      columns={COLUMNS}
      data={rules}
      pageSize={10}
      emptyMessage="Aucune règle générée."
      renderExpanded={renderExpanded}
    />
  );
}
