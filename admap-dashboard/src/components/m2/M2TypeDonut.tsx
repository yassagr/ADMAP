/**
 * Donut (recharts) de la distribution des `AlertType` d'un AlertBundle.
 * Source : `bundle.alerts_by_type` (fallback recalcul depuis `alerts`).
 */
import { Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { AlertBundle, AlertType } from "@/types";

/** Couleurs par type d'alerte (palette thème, hors purple réservé IA). */
const TYPE_COLOR: Record<AlertType, string> = {
  beaconing: "#00d4ff",
  dns_tunnel: "#22d3ee",
  dga: "#38bdf8",
  http_c2: "#ff6b35",
  tls_suspect: "#facc15",
  irc_c2: "#a3e635",
  port_scan: "#f59e0b",
  ioc_match: "#ff2d55",
  large_upload: "#fb7185",
  custom_protocol: "#94a3b8",
};

const TYPE_LABEL: Record<AlertType, string> = {
  beaconing: "Beaconing",
  dns_tunnel: "DNS Tunnel",
  dga: "DGA",
  http_c2: "HTTP C2",
  tls_suspect: "TLS suspect",
  irc_c2: "IRC C2",
  port_scan: "Port Scan",
  ioc_match: "IOC Match",
  large_upload: "Large Upload",
  custom_protocol: "Custom Proto",
};

export interface M2TypeDonutProps {
  bundle: AlertBundle;
}

interface Slice {
  type: AlertType;
  name: string;
  value: number;
  color: string;
}

function buildSlices(bundle: AlertBundle): Slice[] {
  const counts = new Map<AlertType, number>();
  const agg = bundle.alerts_by_type ?? {};
  if (Object.keys(agg).length > 0) {
    for (const [key, value] of Object.entries(agg)) {
      counts.set(key as AlertType, value);
    }
  } else {
    for (const alert of bundle.alerts) {
      counts.set(alert.alert_type, (counts.get(alert.alert_type) ?? 0) + 1);
    }
  }
  return [...counts.entries()]
    .filter(([, value]) => value > 0)
    .map(([type, value]) => ({
      type,
      name: TYPE_LABEL[type] ?? type,
      value,
      color: TYPE_COLOR[type] ?? "#94a3b8",
    }));
}

export function M2TypeDonut({ bundle }: M2TypeDonutProps) {
  const slices = buildSlices(bundle);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Distribution par type</CardTitle>
      </CardHeader>
      <CardContent>
        {slices.length === 0 ? (
          <p className="py-12 text-center text-sm text-muted-foreground">
            Aucune alerte à représenter.
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
