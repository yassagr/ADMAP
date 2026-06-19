/**
 * Diagramme horizontal animé du pipeline M1 → M2 → M3 → M4 → M5.
 *
 * Chaque nœud reflète l'état de son étape (idle / running / done / skipped /
 * failed). Les chevrons entre nœuds s'illuminent quand les données passent à
 * l'étape suivante. Une bande SVG supérieure trace les dépendances de données
 * non adjacentes réelles (M1→M4, M1→M5, M2→M4, M2→M5), qui s'allument lorsque
 * leurs deux extrémités sont terminées. SVG/CSS uniquement, via framer-motion —
 * aucune dépendance ajoutée.
 */
import { motion } from "framer-motion";
import {
  ChevronRight,
  FileSearch,
  Fingerprint,
  Network,
  Radar,
  ScanLine,
  type LucideIcon,
} from "lucide-react";

import { Progress } from "@/components/ui/progress";
import { MODULE_IDS } from "@/types";
import type { ModuleId } from "@/types";
import type { PipelineStepMap, PipelineStepStatus } from "@/hooks/usePipeline";

interface NodeMeta {
  id: ModuleId;
  title: string;
  subtitle: string;
  icon: LucideIcon;
}

const NODES: readonly NodeMeta[] = [
  { id: "m1", title: "M1", subtitle: "IOC", icon: FileSearch },
  { id: "m2", title: "M2", subtitle: "C2", icon: Radar },
  { id: "m3", title: "M3", subtitle: "YARA", icon: ScanLine },
  { id: "m4", title: "M4", subtitle: "APT", icon: Network },
  { id: "m5", title: "M5", subtitle: "Attrib.", icon: Fingerprint },
];

interface StatusVisual {
  ring: string;
  bg: string;
  fg: string;
  label: string;
}

const STATUS_VISUALS: Record<PipelineStepStatus, StatusVisual> = {
  idle: {
    ring: "rgba(148, 163, 184, 0.35)",
    bg: "rgba(148, 163, 184, 0.06)",
    fg: "#94a3b8",
    label: "En attente",
  },
  running: {
    ring: "rgba(0, 212, 255, 0.7)",
    bg: "rgba(0, 212, 255, 0.10)",
    fg: "#7dd3fc",
    label: "En cours",
  },
  done: {
    ring: "rgba(16, 185, 129, 0.7)",
    bg: "rgba(16, 185, 129, 0.12)",
    fg: "#6ee7b7",
    label: "Terminé",
  },
  skipped: {
    ring: "rgba(100, 116, 139, 0.3)",
    bg: "transparent",
    fg: "#64748b",
    label: "Ignoré",
  },
  failed: {
    ring: "rgba(255, 45, 85, 0.7)",
    bg: "rgba(255, 45, 85, 0.12)",
    fg: "#ff8aa0",
    label: "Échec",
  },
};

/** Dépendances de données non adjacentes (indices de NODES). */
const DEP_ARCS: readonly { from: number; to: number }[] = [
  { from: 0, to: 3 }, // M1 → M4
  { from: 0, to: 4 }, // M1 → M5
  { from: 1, to: 3 }, // M2 → M4
  { from: 1, to: 4 }, // M2 → M5
];

/** Centre horizontal d'un nœud en pourcentage (grille à 5 colonnes égales). */
function nodeX(index: number): number {
  return index * 20 + 10;
}

/** Progression globale 0-100 sur les étapes actives (hors `skipped`). */
function overallProgress(steps: PipelineStepMap): number {
  const active = MODULE_IDS.filter((id) => steps[id].status !== "skipped");
  if (active.length === 0) return 0;
  const sum = active.reduce((acc, id) => {
    const step = steps[id];
    if (step.status === "done") return acc + 1;
    if (step.status === "running" || step.status === "failed") {
      return acc + Math.min(1, step.progress / 100);
    }
    return acc;
  }, 0);
  return (sum / active.length) * 100;
}

export interface PipelineFlowProps {
  steps: PipelineStepMap;
  isRunning: boolean;
}

export function PipelineFlow({ steps, isRunning }: PipelineFlowProps) {
  const progress = overallProgress(steps);
  const doneCount = MODULE_IDS.filter((id) => steps[id].status === "done").length;
  const activeCount = MODULE_IDS.filter(
    (id) => steps[id].status !== "skipped",
  ).length;

  return (
    <div className="flex flex-col gap-3 rounded-xl border bg-card p-5">
      {/* Bande de dépendances de données non adjacentes */}
      <svg
        viewBox="0 0 100 100"
        preserveAspectRatio="none"
        className="h-10 w-full"
        aria-hidden
      >
        {DEP_ARCS.map(({ from, to }) => {
          const x1 = nodeX(from);
          const x2 = nodeX(to);
          const mid = (x1 + x2) / 2;
          const span = x2 - x1;
          const peak = 60 - (span / 80) * 45;
          const active =
            steps[NODES[from].id].status === "done" &&
            steps[NODES[to].id].status === "done";
          return (
            <motion.path
              key={`${from}-${to}`}
              d={`M ${x1} 100 Q ${mid} ${peak} ${x2} 100`}
              fill="none"
              stroke={active ? "#6ee7b7" : "rgba(148, 163, 184, 0.25)"}
              strokeWidth={1.5}
              strokeDasharray="3 3"
              vectorEffect="non-scaling-stroke"
              animate={{ opacity: active ? 1 : 0.5 }}
              transition={{ duration: 0.5 }}
            />
          );
        })}
      </svg>

      {/* Rangée de nœuds + chevrons de flux */}
      <div className="relative grid grid-cols-5">
        {NODES.slice(0, -1).map((node, i) => {
          const next = steps[NODES[i + 1].id].status;
          const flowing = next === "running" || next === "done";
          const color = next === "done" ? "#6ee7b7" : "#7dd3fc";
          return (
            <motion.div
              key={`conn-${node.id}`}
              className="absolute top-9 -translate-x-1/2 -translate-y-1/2"
              style={{ left: `${(i + 1) * 20}%` }}
              animate={
                next === "running"
                  ? { opacity: [0.3, 1, 0.3], x: [-2, 2, -2] }
                  : { opacity: flowing ? 1 : 0.3, x: 0 }
              }
              transition={
                next === "running"
                  ? { duration: 1.2, repeat: Infinity, ease: "easeInOut" }
                  : { duration: 0.4 }
              }
            >
              <ChevronRight
                className="h-6 w-6"
                style={{ color: flowing ? color : "#475569" }}
              />
            </motion.div>
          );
        })}

        {NODES.map((node) => {
          const step = steps[node.id];
          const visual = STATUS_VISUALS[step.status];
          const Icon = node.icon;
          const isPulsing = step.status === "running";
          return (
            <div key={node.id} className="flex flex-col items-center gap-2 px-1">
              <motion.div
                className="relative flex h-16 w-16 items-center justify-center rounded-full border-2"
                style={{ borderColor: visual.ring, backgroundColor: visual.bg }}
                animate={
                  isPulsing
                    ? {
                        boxShadow: [
                          "0 0 0 rgba(0, 212, 255, 0)",
                          "0 0 16px rgba(0, 212, 255, 0.55)",
                          "0 0 0 rgba(0, 212, 255, 0)",
                        ],
                      }
                    : { boxShadow: "0 0 0 rgba(0,0,0,0)" }
                }
                transition={
                  isPulsing
                    ? { duration: 1.5, repeat: Infinity, ease: "easeInOut" }
                    : { duration: 0.3 }
                }
              >
                <Icon className="h-6 w-6" style={{ color: visual.fg }} />
                {isPulsing && (
                  <span
                    className="absolute inset-0 rounded-full text-[10px]"
                    style={{ boxShadow: `0 0 0 0 ${visual.ring}` }}
                  />
                )}
              </motion.div>
              <div className="text-center">
                <p className="text-sm font-semibold text-foreground">
                  {node.title}
                </p>
                <p className="text-[11px] text-muted-foreground">
                  {node.subtitle}
                </p>
                <p
                  className="text-[10px] font-medium uppercase tracking-wide"
                  style={{ color: visual.fg }}
                >
                  {step.status === "running" && step.progress > 0
                    ? `${Math.round(step.progress)}%`
                    : visual.label}
                </p>
              </div>
            </div>
          );
        })}
      </div>

      {/* Progression globale */}
      <div className="flex flex-col gap-1.5 pt-2">
        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span>
            {isRunning ? "Pipeline en cours" : "Progression"} · {doneCount}/
            {activeCount} étapes
          </span>
          <span className="font-mono">{Math.round(progress)}%</span>
        </div>
        <Progress value={progress} />
      </div>
    </div>
  );
}
