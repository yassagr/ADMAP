/**
 * Barres (recharts) du nombre d'IOC par catégorie (IP, domaines, hashes, …).
 * Agrège `bundle.iocs` selon la taxonomie partagée `IOC_CATEGORIES`.
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
import type { IOCBundle, IOCType } from "@/types";

import { IOC_CATEGORIES } from "./ioc-taxonomy";

export interface M1CategoryBarsProps {
  bundle: IOCBundle;
}

interface Bucket {
  category: string;
  count: number;
}

function buildBuckets(bundle: IOCBundle): Bucket[] {
  const counts = new Map<string, number>();
  for (const ioc of bundle.iocs) {
    counts.set(ioc.type, (counts.get(ioc.type) ?? 0) + 1);
  }
  return IOC_CATEGORIES.map((cat) => ({
    category: cat.label,
    count: cat.types.reduce(
      (sum, t) => sum + (counts.get(t as IOCType) ?? 0),
      0,
    ),
  })).filter((b) => b.count > 0);
}

export function M1CategoryBars({ bundle }: M1CategoryBarsProps) {
  const buckets = buildBuckets(bundle);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">IOC par catégorie</CardTitle>
      </CardHeader>
      <CardContent>
        {buckets.length === 0 ? (
          <p className="py-12 text-center text-sm text-muted-foreground">
            Aucun IOC à représenter.
          </p>
        ) : (
          <ResponsiveContainer width="100%" height={280}>
            <BarChart
              data={buckets}
              margin={{ top: 8, right: 8, bottom: 40, left: 0 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis
                dataKey="category"
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
              <Bar dataKey="count" fill="#00d4ff" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
}
