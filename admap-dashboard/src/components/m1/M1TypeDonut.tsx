/**
 * Donut (recharts) de la distribution des IOC par type.
 * Source : `bundle.analysis_stats.by_type` (fallback recalcul depuis `iocs`).
 */
import { Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { IOCBundle, IOCType } from "@/types";

import { IOC_TYPE_COLOR, IOC_TYPE_LABEL } from "./ioc-taxonomy";

export interface M1TypeDonutProps {
  bundle: IOCBundle;
}

interface Slice {
  type: string;
  name: string;
  value: number;
  color: string;
}

function buildSlices(bundle: IOCBundle): Slice[] {
  const counts = new Map<string, number>();
  const agg = bundle.analysis_stats.by_type ?? {};
  if (Object.keys(agg).length > 0) {
    for (const [key, value] of Object.entries(agg)) counts.set(key, value);
  } else {
    for (const ioc of bundle.iocs) {
      counts.set(ioc.type, (counts.get(ioc.type) ?? 0) + 1);
    }
  }
  return [...counts.entries()]
    .filter(([, value]) => value > 0)
    .map(([type, value]) => ({
      type,
      name: IOC_TYPE_LABEL[type as IOCType] ?? type,
      value,
      color: IOC_TYPE_COLOR[type as IOCType] ?? "#94a3b8",
    }));
}

export function M1TypeDonut({ bundle }: M1TypeDonutProps) {
  const slices = buildSlices(bundle);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Distribution par type</CardTitle>
      </CardHeader>
      <CardContent>
        {slices.length === 0 ? (
          <p className="py-12 text-center text-sm text-muted-foreground">
            Aucun IOC à représenter.
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
                  <Cell key={slice.type} fill={slice.color} />
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
