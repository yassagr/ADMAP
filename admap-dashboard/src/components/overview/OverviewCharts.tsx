/**
 * Graphes recharts du tableau de bord Overview. Chaque composant reçoit son jeu
 * de données déjà agrégé (cf. `lib/overview-stats`) et gère son état vide.
 */
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { ReactNode } from "react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type {
  ColoredCount,
  NamedCount,
  TimelinePoint,
} from "@/lib/overview-stats";

const TOOLTIP_STYLE = {
  backgroundColor: "var(--bg-tertiary)",
  border: "1px solid var(--border)",
  borderRadius: 8,
  color: "var(--text-primary)",
} as const;

const AXIS_TICK = { fill: "var(--text-secondary)", fontSize: 11 } as const;

function ChartCard({
  title,
  empty,
  children,
}: {
  title: string;
  empty: boolean;
  children: ReactNode;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{title}</CardTitle>
      </CardHeader>
      <CardContent>
        {empty ? (
          <p className="py-12 text-center text-sm text-muted-foreground">
            Aucune donnée à représenter.
          </p>
        ) : (
          children
        )}
      </CardContent>
    </Card>
  );
}

export function OverviewModuleBars({ data }: { data: ColoredCount[] }) {
  return (
    <ChartCard title="Analyses par module" empty={data.length === 0}>
      <ResponsiveContainer width="100%" height={260}>
        <BarChart data={data} margin={{ top: 8, right: 16, bottom: 8, left: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
          <XAxis dataKey="name" tick={AXIS_TICK} />
          <YAxis allowDecimals={false} tick={AXIS_TICK} />
          <Tooltip cursor={{ fill: "rgba(0, 212, 255, 0.08)" }} contentStyle={TOOLTIP_STYLE} />
          <Bar dataKey="value" radius={[4, 4, 0, 0]}>
            {data.map((d) => (
              <Cell key={d.name} fill={d.color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}

export function OverviewTimeline({ data }: { data: TimelinePoint[] }) {
  return (
    <ChartCard title="Activité (analyses / jour)" empty={data.length === 0}>
      <ResponsiveContainer width="100%" height={260}>
        <AreaChart data={data} margin={{ top: 8, right: 16, bottom: 8, left: 0 }}>
          <defs>
            <linearGradient id="ov-timeline" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#00d4ff" stopOpacity={0.5} />
              <stop offset="95%" stopColor="#00d4ff" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
          <XAxis dataKey="date" tick={AXIS_TICK} />
          <YAxis allowDecimals={false} tick={AXIS_TICK} />
          <Tooltip contentStyle={TOOLTIP_STYLE} />
          <Area
            type="monotone"
            dataKey="count"
            stroke="#00d4ff"
            strokeWidth={2}
            fill="url(#ov-timeline)"
          />
        </AreaChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}

function Donut({ data, title }: { data: ColoredCount[] | NamedCount[]; title: string }) {
  const slices = data as ColoredCount[];
  return (
    <ChartCard title={title} empty={slices.length === 0}>
      <ResponsiveContainer width="100%" height={260}>
        <PieChart>
          <Pie
            data={slices}
            dataKey="value"
            nameKey="name"
            innerRadius={56}
            outerRadius={92}
            paddingAngle={2}
            stroke="var(--bg-secondary)"
          >
            {slices.map((d, i) => (
              <Cell key={d.name} fill={d.color ?? DONUT_PALETTE[i % DONUT_PALETTE.length]} />
            ))}
          </Pie>
          <Tooltip contentStyle={TOOLTIP_STYLE} />
          <Legend wrapperStyle={{ fontSize: 12, color: "var(--text-secondary)" }} />
        </PieChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}

const DONUT_PALETTE = [
  "#00d4ff", "#ff6b35", "#6ee7b7", "#a78bfa", "#f59e0b",
  "#fb7185", "#38bdf8", "#facc15", "#34d399", "#c084fc",
];

export function OverviewSeverityDonut({ data }: { data: ColoredCount[] }) {
  return <Donut data={data} title="Sévérités d'alertes (cumulées)" />;
}

export function OverviewIocDonut({ data }: { data: NamedCount[] }) {
  return <Donut data={data} title="Types d'IOC (cumulés)" />;
}

function HorizontalBars({
  data,
  title,
  color,
}: {
  data: NamedCount[];
  title: string;
  color: string;
}) {
  return (
    <ChartCard title={title} empty={data.length === 0}>
      <ResponsiveContainer width="100%" height={Math.max(220, data.length * 30)}>
        <BarChart data={data} layout="vertical" margin={{ top: 8, right: 16, bottom: 8, left: 8 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
          <XAxis type="number" allowDecimals={false} tick={AXIS_TICK} />
          <YAxis type="category" dataKey="name" width={110} tick={AXIS_TICK} />
          <Tooltip cursor={{ fill: "rgba(167, 139, 250, 0.08)" }} contentStyle={TOOLTIP_STYLE} />
          <Bar dataKey="value" fill={color} radius={[0, 4, 4, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}

export function OverviewMitreBars({ data }: { data: NamedCount[] }) {
  return <HorizontalBars data={data} title="Top techniques MITRE (cumulées)" color="#ff6b35" />;
}

export function OverviewAptBars({ data }: { data: NamedCount[] }) {
  return <HorizontalBars data={data} title="Top acteurs APT suspectés" color="#a78bfa" />;
}
