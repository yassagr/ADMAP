/**
 * Importance des features (recharts) : barres horizontales, top 15 features
 * triées par importance décroissante.
 */
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { FeatureImportanceEntry } from "@/types/aiMetrics";

export interface FeatureImportanceProps {
  features: FeatureImportanceEntry[];
  /** Nombre maximum de features affichées. */
  limit?: number;
}

export function FeatureImportance({ features, limit = 15 }: FeatureImportanceProps) {
  const rows = [...features]
    .sort((a, b) => b.importance - a.importance)
    .slice(0, limit);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Importance des features</CardTitle>
      </CardHeader>
      <CardContent>
        {rows.length === 0 ? (
          <p className="py-12 text-center text-sm text-muted-foreground">
            Aucune feature à représenter.
          </p>
        ) : (
          <ResponsiveContainer width="100%" height={Math.max(240, rows.length * 28)}>
            <BarChart
              data={rows}
              layout="vertical"
              margin={{ top: 8, right: 16, bottom: 8, left: 8 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis
                type="number"
                tick={{ fill: "var(--text-secondary)", fontSize: 11 }}
              />
              <YAxis
                type="category"
                dataKey="feature"
                width={140}
                tick={{ fill: "var(--text-secondary)", fontSize: 11 }}
              />
              <Tooltip
                cursor={{ fill: "rgba(168, 85, 247, 0.08)" }}
                formatter={(value) => [Number(value).toFixed(4), "Importance"]}
                contentStyle={{
                  backgroundColor: "var(--bg-tertiary)",
                  border: "1px solid var(--border)",
                  borderRadius: 8,
                  color: "var(--text-primary)",
                }}
              />
              <Bar dataKey="importance" fill="#a855f7" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
}
