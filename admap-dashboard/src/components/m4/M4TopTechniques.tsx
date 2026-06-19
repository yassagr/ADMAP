/**
 * Top techniques MITRE (recharts) : barres horizontales depuis `top_techniques`
 * (paires `[technique, count]` sérialisées des tuples Python).
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
import type { APTMapReport } from "@/types";

export interface M4TopTechniquesProps {
  report: APTMapReport;
  /** Nombre maximum de techniques affichées. */
  limit?: number;
}

interface Row {
  technique: string;
  count: number;
}

export function M4TopTechniques({ report, limit = 10 }: M4TopTechniquesProps) {
  const rows: Row[] = report.top_techniques
    .slice(0, limit)
    .map(([technique, count]) => ({ technique, count }));

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Top techniques</CardTitle>
      </CardHeader>
      <CardContent>
        {rows.length === 0 ? (
          <p className="py-12 text-center text-sm text-muted-foreground">
            Aucune technique dominante.
          </p>
        ) : (
          <ResponsiveContainer width="100%" height={Math.max(220, rows.length * 30)}>
            <BarChart
              data={rows}
              layout="vertical"
              margin={{ top: 8, right: 16, bottom: 8, left: 8 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis
                type="number"
                allowDecimals={false}
                tick={{ fill: "var(--text-secondary)", fontSize: 11 }}
              />
              <YAxis
                type="category"
                dataKey="technique"
                width={96}
                tick={{ fill: "var(--text-secondary)", fontSize: 11 }}
              />
              <Tooltip
                cursor={{ fill: "rgba(255, 107, 53, 0.08)" }}
                contentStyle={{
                  backgroundColor: "var(--bg-tertiary)",
                  border: "1px solid var(--border)",
                  borderRadius: 8,
                  color: "var(--text-primary)",
                }}
              />
              <Bar dataKey="count" fill="#ff6b35" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
}
