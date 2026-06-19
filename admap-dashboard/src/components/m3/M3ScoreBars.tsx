/**
 * Barres (recharts) des scores discriminants par règle YARA générée.
 * Couleur dérivée du statut de compilation (compilée = cyan, échec = rouge).
 */
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { YaraRuleSet } from "@/types";

export interface M3ScoreBarsProps {
  ruleset: YaraRuleSet;
}

interface RuleBar {
  name: string;
  score: number;
  compiled: boolean;
}

export function M3ScoreBars({ ruleset }: M3ScoreBarsProps) {
  const data: RuleBar[] = ruleset.rules
    .map((r) => ({
      name: r.rule_name,
      score: Math.round(r.confidence_score),
      compiled: r.compiled,
    }))
    .sort((a, b) => b.score - a.score);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Scores discriminants</CardTitle>
      </CardHeader>
      <CardContent>
        {data.length === 0 ? (
          <p className="py-12 text-center text-sm text-muted-foreground">
            Aucune règle générée.
          </p>
        ) : (
          <ResponsiveContainer width="100%" height={Math.max(220, data.length * 36)}>
            <BarChart
              layout="vertical"
              data={data}
              margin={{ top: 8, right: 16, bottom: 8, left: 8 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis
                type="number"
                domain={[0, 100]}
                tick={{ fill: "var(--text-secondary)", fontSize: 11 }}
              />
              <YAxis
                type="category"
                dataKey="name"
                width={160}
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
              <Bar dataKey="score" radius={[0, 4, 4, 0]}>
                {data.map((d) => (
                  <Cell
                    key={d.name}
                    fill={d.compiled ? "#00d4ff" : "#ff2d55"}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
}
