/**
 * Courbe ROC (recharts) : axe X = taux de faux positifs (fpr), axe Y = taux de
 * vrais positifs (tpr). Une ligne diagonale de référence figure le classifieur
 * aléatoire (AUC = 0.5). L'AUC du modèle est rappelée dans l'en-tête.
 */
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { RocPoint } from "@/types/aiMetrics";

export interface RocCurveProps {
  roc: RocPoint[];
  /** Aire sous la courbe, affichée dans l'en-tête si fournie. */
  auc?: number;
}

interface Row {
  fpr: number;
  tpr: number;
  /** Diagonale de référence (classifieur aléatoire) : tpr = fpr. */
  baseline: number;
}

export function RocCurve({ roc, auc }: RocCurveProps) {
  const rows: Row[] = [...roc]
    .sort((a, b) => a.fpr - b.fpr)
    .map((p) => ({ fpr: p.fpr, tpr: p.tpr, baseline: p.fpr }));

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between space-y-0">
        <CardTitle className="text-base">Courbe ROC</CardTitle>
        {typeof auc === "number" && (
          <span className="text-xs font-semibold text-muted-foreground">
            AUC {auc.toFixed(3)}
          </span>
        )}
      </CardHeader>
      <CardContent>
        {rows.length === 0 ? (
          <p className="py-12 text-center text-sm text-muted-foreground">
            Aucun point ROC à représenter.
          </p>
        ) : (
          <ResponsiveContainer width="100%" height={300}>
            <LineChart
              data={rows}
              margin={{ top: 8, right: 16, bottom: 16, left: 0 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis
                type="number"
                dataKey="fpr"
                domain={[0, 1]}
                tickCount={6}
                tick={{ fill: "var(--text-secondary)", fontSize: 11 }}
                label={{
                  value: "Taux de faux positifs",
                  position: "insideBottom",
                  offset: -8,
                  fill: "var(--text-secondary)",
                  fontSize: 11,
                }}
              />
              <YAxis
                type="number"
                domain={[0, 1]}
                tickCount={6}
                tick={{ fill: "var(--text-secondary)", fontSize: 11 }}
                label={{
                  value: "Taux de vrais positifs",
                  angle: -90,
                  position: "insideLeft",
                  offset: 16,
                  fill: "var(--text-secondary)",
                  fontSize: 11,
                }}
              />
              <Tooltip
                formatter={(value, name) => [
                  Number(value).toFixed(3),
                  name === "tpr" ? "TPR" : "Aléatoire",
                ]}
                labelFormatter={(label) => `FPR ${Number(label).toFixed(3)}`}
                contentStyle={{
                  backgroundColor: "var(--bg-tertiary)",
                  border: "1px solid var(--border)",
                  borderRadius: 8,
                  color: "var(--text-primary)",
                }}
              />
              <Line
                type="monotone"
                dataKey="baseline"
                stroke="var(--text-secondary)"
                strokeDasharray="5 5"
                strokeWidth={1}
                dot={false}
                isAnimationActive={false}
              />
              <Line
                type="monotone"
                dataKey="tpr"
                stroke="#a855f7"
                strokeWidth={2}
                dot={false}
              />
            </LineChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
}
