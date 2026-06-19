/**
 * Table de données générique : colonnes typées, recherche, tri par colonne et
 * pagination. Bâtie sur les primitives `ui/table` + `ui/input` + `ui/button`.
 */
import { Fragment, useMemo, useState, type ReactNode } from "react";
import {
  ArrowDown,
  ArrowUp,
  ChevronDown,
  ChevronRight,
  ChevronsUpDown,
  Search,
} from "lucide-react";

import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export interface DataTableColumn<T> {
  /** Clé unique de la colonne. */
  key: string;
  /** En-tête affiché. */
  header: string;
  /** Rendu de la cellule (par défaut : valeur de `accessor`). */
  render?: (row: T) => ReactNode;
  /** Valeur primitive utilisée pour le tri et la recherche. */
  accessor?: (row: T) => string | number;
  /** Active le tri sur cette colonne (nécessite `accessor`). */
  sortable?: boolean;
  className?: string;
}

export interface DataTableProps<T> {
  columns: DataTableColumn<T>[];
  data: T[];
  /** Active la barre de recherche (filtre sur les `accessor`). */
  searchable?: boolean;
  /** Lignes par page (0 = pas de pagination). */
  pageSize?: number;
  /** Message affiché quand il n'y a aucune ligne. */
  emptyMessage?: string;
  /**
   * Rendu du contenu déplié d'une ligne. Si fourni, chaque ligne devient
   * cliquable et reçoit un chevron ; un clic affiche `renderExpanded(row)` sur
   * une ligne pleine largeur. Absent ⇒ table classique inchangée.
   */
  renderExpanded?: (row: T) => ReactNode;
  className?: string;
}

type SortDir = "asc" | "desc";

export function DataTable<T>({
  columns,
  data,
  searchable = true,
  pageSize = 10,
  emptyMessage = "Aucune donnée.",
  renderExpanded,
  className,
}: DataTableProps<T>) {
  const [query, setQuery] = useState("");
  const [sortKey, setSortKey] = useState<string | null>(null);
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const [page, setPage] = useState(0);
  const [expanded, setExpanded] = useState<ReadonlySet<T>>(() => new Set());

  const expandable = Boolean(renderExpanded);
  const toggleRow = (row: T): void => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(row)) next.delete(row);
      else next.add(row);
      return next;
    });
  };
  const colCount = columns.length + (expandable ? 1 : 0);

  const filtered = useMemo(() => {
    if (!query.trim()) return data;
    const q = query.toLowerCase();
    return data.filter((row) =>
      columns.some((col) => {
        if (!col.accessor) return false;
        return String(col.accessor(row)).toLowerCase().includes(q);
      }),
    );
  }, [data, columns, query]);

  const sorted = useMemo(() => {
    if (!sortKey) return filtered;
    const col = columns.find((c) => c.key === sortKey);
    if (!col?.accessor) return filtered;
    const accessor = col.accessor;
    return [...filtered].sort((a, b) => {
      const va = accessor(a);
      const vb = accessor(b);
      if (va < vb) return sortDir === "asc" ? -1 : 1;
      if (va > vb) return sortDir === "asc" ? 1 : -1;
      return 0;
    });
  }, [filtered, columns, sortKey, sortDir]);

  const totalPages = pageSize > 0 ? Math.max(1, Math.ceil(sorted.length / pageSize)) : 1;
  const currentPage = Math.min(page, totalPages - 1);
  const paged = useMemo(() => {
    if (pageSize <= 0) return sorted;
    const start = currentPage * pageSize;
    return sorted.slice(start, start + pageSize);
  }, [sorted, pageSize, currentPage]);

  const toggleSort = (col: DataTableColumn<T>): void => {
    if (!col.sortable || !col.accessor) return;
    if (sortKey === col.key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(col.key);
      setSortDir("asc");
    }
  };

  return (
    <div className={cn("flex flex-col gap-3", className)}>
      {searchable && (
        <div className="relative max-w-xs">
          <Search className="absolute left-2 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setPage(0);
            }}
            placeholder="Rechercher..."
            className="pl-8"
          />
        </div>
      )}

      <div className="rounded-lg border border-border">
        <Table>
          <TableHeader>
            <TableRow>
              {expandable && <TableHead className="w-8" />}
              {columns.map((col) => {
                const active = sortKey === col.key;
                return (
                  <TableHead
                    key={col.key}
                    className={cn(
                      col.sortable && col.accessor && "cursor-pointer select-none",
                      col.className,
                    )}
                    onClick={() => toggleSort(col)}
                  >
                    <span className="inline-flex items-center gap-1">
                      {col.header}
                      {col.sortable && col.accessor && (
                        active ? (
                          sortDir === "asc" ? (
                            <ArrowUp className="h-3 w-3" />
                          ) : (
                            <ArrowDown className="h-3 w-3" />
                          )
                        ) : (
                          <ChevronsUpDown className="h-3 w-3 opacity-50" />
                        )
                      )}
                    </span>
                  </TableHead>
                );
              })}
            </TableRow>
          </TableHeader>
          <TableBody>
            {paged.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={colCount}
                  className="py-8 text-center text-muted-foreground"
                >
                  {emptyMessage}
                </TableCell>
              </TableRow>
            ) : (
              paged.map((row, ri) => {
                const isOpen = expandable && expanded.has(row);
                return (
                  <Fragment key={ri}>
                    <TableRow
                      className={cn(expandable && "cursor-pointer")}
                      onClick={expandable ? () => toggleRow(row) : undefined}
                    >
                      {expandable && (
                        <TableCell className="w-8 text-muted-foreground">
                          {isOpen ? (
                            <ChevronDown className="h-4 w-4" />
                          ) : (
                            <ChevronRight className="h-4 w-4" />
                          )}
                        </TableCell>
                      )}
                      {columns.map((col) => (
                        <TableCell key={col.key} className={col.className}>
                          {col.render
                            ? col.render(row)
                            : col.accessor
                              ? col.accessor(row)
                              : null}
                        </TableCell>
                      ))}
                    </TableRow>
                    {isOpen && renderExpanded && (
                      <TableRow>
                        <TableCell
                          colSpan={colCount}
                          style={{ backgroundColor: "rgba(17, 29, 53, 0.5)" }}
                        >
                          {renderExpanded(row)}
                        </TableCell>
                      </TableRow>
                    )}
                  </Fragment>
                );
              })
            )}
          </TableBody>
        </Table>
      </div>

      {pageSize > 0 && totalPages > 1 && (
        <div className="flex items-center justify-between text-sm text-muted-foreground">
          <span>
            Page {currentPage + 1} / {totalPages} · {sorted.length} lignes
          </span>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={currentPage === 0}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
            >
              Précédent
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={currentPage >= totalPages - 1}
              onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
            >
              Suivant
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
