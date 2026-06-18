/**
 * Viewer JSON repliable avec coloration syntaxique.
 * Récursif et autonome : objets/tableaux pliables via état local par nœud.
 */
import { useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";

import { cn } from "@/lib/utils";

export interface JsonViewerProps {
  data: unknown;
  /** Profondeur jusqu'à laquelle les nœuds sont dépliés par défaut. */
  defaultExpandedDepth?: number;
  className?: string;
}

const COLORS = {
  key: "#7dd3fc",
  string: "#6ee7b7",
  number: "#fcd34d",
  boolean: "#c4b5fd",
  null: "#64748b",
  punctuation: "#94a3b8",
} as const;

function Primitive({ value }: { value: string | number | boolean | null }) {
  if (value === null) return <span style={{ color: COLORS.null }}>null</span>;
  switch (typeof value) {
    case "string":
      return <span style={{ color: COLORS.string }}>&quot;{value}&quot;</span>;
    case "number":
      return <span style={{ color: COLORS.number }}>{value}</span>;
    case "boolean":
      return <span style={{ color: COLORS.boolean }}>{String(value)}</span>;
    default:
      return <span>{String(value)}</span>;
  }
}

interface NodeProps {
  name?: string;
  value: unknown;
  depth: number;
  defaultExpandedDepth: number;
  isLast: boolean;
}

function JsonNode({ name, value, depth, defaultExpandedDepth, isLast }: NodeProps) {
  const isObject = value !== null && typeof value === "object";
  const [expanded, setExpanded] = useState(depth < defaultExpandedDepth);

  const keyLabel = name !== undefined && (
    <span style={{ color: COLORS.key }}>&quot;{name}&quot;: </span>
  );

  if (!isObject) {
    return (
      <div style={{ paddingLeft: depth * 14 }}>
        {keyLabel}
        <Primitive value={value as string | number | boolean | null} />
        {!isLast && <span style={{ color: COLORS.punctuation }}>,</span>}
      </div>
    );
  }

  const isArray = Array.isArray(value);
  const entries: [string, unknown][] = isArray
    ? (value as unknown[]).map((v, i): [string, unknown] => [String(i), v])
    : Object.entries(value as Record<string, unknown>);
  const open = isArray ? "[" : "{";
  const close = isArray ? "]" : "}";

  return (
    <div style={{ paddingLeft: depth * 14 }}>
      <button
        type="button"
        onClick={() => setExpanded((e) => !e)}
        className="inline-flex items-center gap-1 hover:opacity-80"
      >
        {expanded ? (
          <ChevronDown className="h-3 w-3" style={{ color: COLORS.punctuation }} />
        ) : (
          <ChevronRight className="h-3 w-3" style={{ color: COLORS.punctuation }} />
        )}
        {keyLabel}
        <span style={{ color: COLORS.punctuation }}>{open}</span>
        {!expanded && (
          <span style={{ color: COLORS.null }}>
            {entries.length} {isArray ? "éléments" : "clés"}
            {close}
          </span>
        )}
      </button>
      {expanded && (
        <div>
          {entries.map(([k, v], i) => (
            <JsonNode
              key={k}
              name={isArray ? undefined : k}
              value={v}
              depth={depth + 1}
              defaultExpandedDepth={defaultExpandedDepth}
              isLast={i === entries.length - 1}
            />
          ))}
          <div style={{ paddingLeft: depth * 14, color: COLORS.punctuation }}>
            {close}
            {!isLast && ","}
          </div>
        </div>
      )}
    </div>
  );
}

export function JsonViewer({
  data,
  defaultExpandedDepth = 1,
  className,
}: JsonViewerProps) {
  return (
    <div
      className={cn(
        "overflow-auto rounded-lg border border-border p-3 font-mono text-xs leading-relaxed",
        className,
      )}
      style={{ backgroundColor: "var(--bg-tertiary)" }}
    >
      <JsonNode
        value={data}
        depth={0}
        defaultExpandedDepth={defaultExpandedDepth}
        isLast
      />
    </div>
  );
}
