/**
 * Badge de statut de job (icône + couleur), avec spinner animé si `running`.
 * Couvre l'union complète `JobStatus` (incluant `queued` de M1 et `pending`).
 */
import {
  Ban,
  CheckCircle2,
  Clock,
  Loader2,
  XCircle,
  type LucideIcon,
} from "lucide-react";

import { cn } from "@/lib/utils";
import type { JobStatus } from "@/types";

interface StatusStyle {
  label: string;
  icon: LucideIcon;
  fg: string;
  bg: string;
  border: string;
  spin?: boolean;
}

const STYLES: Record<JobStatus, StatusStyle> = {
  queued: {
    label: "Queued",
    icon: Clock,
    fg: "#cbd5e1",
    bg: "rgba(148, 163, 184, 0.14)",
    border: "rgba(148, 163, 184, 0.4)",
  },
  pending: {
    label: "Pending",
    icon: Clock,
    fg: "#cbd5e1",
    bg: "rgba(148, 163, 184, 0.14)",
    border: "rgba(148, 163, 184, 0.4)",
  },
  running: {
    label: "Running",
    icon: Loader2,
    fg: "#7dd3fc",
    bg: "rgba(0, 212, 255, 0.14)",
    border: "rgba(0, 212, 255, 0.45)",
    spin: true,
  },
  completed: {
    label: "Completed",
    icon: CheckCircle2,
    fg: "#6ee7b7",
    bg: "rgba(0, 255, 136, 0.12)",
    border: "rgba(0, 255, 136, 0.4)",
  },
  failed: {
    label: "Failed",
    icon: XCircle,
    fg: "#ff8aa0",
    bg: "rgba(255, 45, 85, 0.16)",
    border: "rgba(255, 45, 85, 0.55)",
  },
  cancelled: {
    label: "Cancelled",
    icon: Ban,
    fg: "#94a3b8",
    bg: "rgba(71, 85, 105, 0.2)",
    border: "rgba(71, 85, 105, 0.5)",
  },
};

export interface JobStatusBadgeProps {
  status: JobStatus;
  className?: string;
}

export function JobStatusBadge({ status, className }: JobStatusBadgeProps) {
  const style = STYLES[status];
  const Icon = style.icon;

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-semibold",
        className,
      )}
      style={{ color: style.fg, backgroundColor: style.bg, borderColor: style.border }}
    >
      <Icon className={cn("h-3 w-3", style.spin && "animate-spin")} />
      {style.label}
    </span>
  );
}
