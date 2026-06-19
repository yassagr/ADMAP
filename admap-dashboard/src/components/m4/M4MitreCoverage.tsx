/**
 * Couverture MITRE ATT&CK (recharts) : nombre de techniques distinctes couvertes
 * par tactique, depuis `mitre_coverage` (Record<tactic, technique[]>).
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

export interface M4MitreCoverageProps {
  report: APTMapReport;
}

interface Bucket {
  tactic: string;
  techniques: number;
}

function buildBuckets(report: APTMapReport): Bucket[] {
  return Object.entries(report.mitre_coverage)
    .map(([tactic, techniques]) => ({ tactic, techniques: techniques.length }))
    .filter((b) => b.techniques > 0)
    .sort((a, b) => b.techniques - a.techniques);
}

export function M4MitreCoverage({ report }: M4MitreCoverageProps) {
  const buckets = buildBuckets(report);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Couverture MITRE par tactique</CardTitle>
      </CardHeader>
      <CardContent>
        {buckets.length === 0 ? (
          <p className="py-12 text-center text-sm text-muted-foreground">
            Aucune tactique couverte.
          </p>
        ) : (
          <ResponsiveContainer width="100%" height={280}>
            <BarChart
              data={buckets}
              margin={{ top: 8, right: 8, bottom: 40, left: 0 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis
                dataKey="tactic"
                angle={-30}
                textAnchor="end"
                interval={0}
                height={60}
                tick={{ fill: "var(--text-secondary)", fontSize: 11 }}
              />
              <YAxis
                allowDecimals={false}
                tick={{ fill: "var(--text-secondary)", fontSize: 11 }}
              />
              <Tooltip
                cursor={{ fill: "rgba(0, 212, 255, 0.08)" }}
                contentStyle={{
                  backgroundColor: "var(--bg-tertiary)",
                  border: "1px solid var(--border)",
                  borderRadius: 8,
                  color: "var(--text-primary)",
                }}
              />
              <Bar dataKey="techniques" fill="#00d4ff" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
}
