/**
 * Barre de filtres de l'historique : module, plage de dates (du / au) et
 * recherche texte sur le nom d'entrée. Contrôlé par la page History.
 */
import { Search } from "lucide-react";

import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import type { AnalysisModule } from "@/types";

const MODULE_OPTIONS: { value: "ALL" | AnalysisModule; label: string }[] = [
  { value: "ALL", label: "Tous les modules" },
  { value: "M1", label: "M1 · IOC" },
  { value: "M2", label: "M2 · C2" },
  { value: "M3", label: "M3 · YARA" },
  { value: "M4", label: "M4 · APT" },
  { value: "M5", label: "M5 · Attribution" },
  { value: "PIPELINE", label: "Pipeline" },
];

export interface HistoryFilterState {
  module: "ALL" | AnalysisModule;
  from: string;
  to: string;
  query: string;
}

export interface HistoryFiltersProps {
  value: HistoryFilterState;
  onChange: (next: HistoryFilterState) => void;
}

const SELECT_CLASS =
  "h-9 rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring";

export function HistoryFilters({ value, onChange }: HistoryFiltersProps) {
  return (
    <div className="flex flex-wrap items-end gap-3">
      <label className="flex flex-col gap-1 text-xs text-muted-foreground">
        Module
        <select
          className={SELECT_CLASS}
          value={value.module}
          onChange={(e) =>
            onChange({ ...value, module: e.target.value as HistoryFilterState["module"] })
          }
        >
          {MODULE_OPTIONS.map((o) => (
            <option key={o.value} value={o.value} className="bg-slate-900">
              {o.label}
            </option>
          ))}
        </select>
      </label>

      <label className="flex flex-col gap-1 text-xs text-muted-foreground">
        Du
        <Input
          type="date"
          value={value.from}
          onChange={(e) => onChange({ ...value, from: e.target.value })}
          className="w-40"
        />
      </label>

      <label className="flex flex-col gap-1 text-xs text-muted-foreground">
        Au
        <Input
          type="date"
          value={value.to}
          onChange={(e) => onChange({ ...value, to: e.target.value })}
          className="w-40"
        />
      </label>

      <label className="flex flex-1 flex-col gap-1 text-xs text-muted-foreground">
        Recherche
        <div className="relative min-w-[12rem]">
          <Search className="absolute left-2 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={value.query}
            onChange={(e) => onChange({ ...value, query: e.target.value })}
            placeholder="Nom d'entrée..."
            className={cn("pl-8")}
          />
        </div>
      </label>
    </div>
  );
}
