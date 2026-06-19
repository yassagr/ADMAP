/**
 * Donut (recharts) de la distribution des tactiques MITRE dominantes, depuis
 * `top_tactics` (paires `[tactic, count]` sérialisées des tuples Python).
 */
import { Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { APTMapReport } from "@/types";

/** Palette tactiques (thème ADMAP, purple réservé à l'IA → exclu). */
const PALETTE: readonly string[] = [
  "#00d4ff",
  "#ff6b35",
  "#a3e635",
  "#facc15",
  "#22d3ee",
  "#fb7185",
  "#38bdf8",
  "#f59e0b",
  "#34d399",
  "#60a5fa",
];

export interface M4TacticDonutProps {
  report: APTMapReport;
}

interface Slice {
  name: string;
  value: number;
  color: string;
}

export function M4TacticDonut({ report }: M4TacticDonutProps) {
  const slices: Slice[] = report.top_tactics
    .filter(([, count]) => count > 0)
    .map(([tactic, count], i) => ({
      name: tactic,
      value: count,
      color: PALETTE[i % PALETTE.length],
    }));

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Top tactiques</CardTitle>
      </CardHeader>
      <CardContent>
        {slices.length === 0 ? (
          <p className="py-12 text-center text-sm text-muted-foreground">
            Aucune tactique à représenter.
          </p>
        ) : (
          <ResponsiveContainer width="100%" height={280}>
            <PieChart>
              <Pie
                data={slices}
                dataKey="value"
                nameKey="name"
                innerRadius={64}
                outerRadius={100}
                paddingAngle={2}
                stroke="var(--bg-secondary)"
              >
                {slices.map((slice) => (
                  <Cell key={slice.name} fill={slice.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: "var(--bg-tertiary)",
                  border: "1px solid var(--border)",
                  borderRadius: 8,
                  color: "var(--text-primary)",
                }}
              />
              <Legend
                wrapperStyle={{ fontSize: 12, color: "var(--text-secondary)" }}
              />
            </PieChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
}
