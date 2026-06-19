/**
 * Matrice de confusion — grille colorée custom (pas de heatmap recharts natif,
 * aucune dépendance ajoutée). Intensité de la couleur proportionnelle à la
 * valeur de la cellule. Axes « Réel » (lignes) / « Prédit » (colonnes),
 * libellés issus de `labels`.
 */
import { Fragment } from "react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export interface ConfusionMatrixProps {
  labels: string[];
  /** Matrice carrée `[réel][prédit]`. */
  matrix: number[][];
}

/** Couleur de fond d'une cellule selon son ratio à la valeur max. */
function cellColor(ratio: number): string {
  return `rgba(0, 212, 255, ${0.06 + 0.85 * ratio})`;
}

export function ConfusionMatrix({ labels, matrix }: ConfusionMatrixProps) {
  const n = labels.length;
  const max = Math.max(1, ...matrix.flat());

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Matrice de confusion</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex gap-3">
          {/* Axe « Réel » (vertical) */}
          <div className="flex items-center">
            <span
              className="text-xs font-semibold uppercase tracking-wide text-muted-foreground"
              style={{ writingMode: "vertical-rl", transform: "rotate(180deg)" }}
            >
              Réel
            </span>
          </div>

          <div className="flex flex-1 flex-col gap-2">
            {/* Axe « Prédit » (horizontal) */}
            <span className="text-center text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Prédit
            </span>

            <div
              className="grid gap-1"
              style={{
                gridTemplateColumns: `minmax(72px, auto) repeat(${n}, minmax(64px, 1fr))`,
              }}
            >
              {/* En-tête : coin vide + libellés prédits */}
              <div />
              {labels.map((label) => (
                <div
                  key={`col-${label}`}
                  className="truncate px-2 py-1 text-center text-xs font-medium text-foreground"
                  title={label}
                >
                  {label}
                </div>
              ))}

              {/* Lignes : libellé réel + cellules */}
              {matrix.map((row, i) => (
                <Fragment key={`row-${labels[i] ?? i}`}>
                  <div
                    className="flex items-center truncate px-2 text-xs font-medium text-foreground"
                    title={labels[i]}
                  >
                    {labels[i] ?? `#${i}`}
                  </div>
                  {row.map((value, j) => {
                    const ratio = value / max;
                    return (
                      <div
                        key={`cell-${i}-${j}`}
                        className="flex aspect-square items-center justify-center rounded-md border text-sm font-mono font-semibold"
                        style={{
                          backgroundColor: cellColor(ratio),
                          borderColor: "var(--border)",
                          color: ratio > 0.55 ? "#0b1220" : "var(--text-primary)",
                        }}
                        title={`${labels[i]} → ${labels[j]} : ${value}`}
                      >
                        {value}
                      </div>
                    );
                  })}
                </Fragment>
              ))}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
