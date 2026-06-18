/**
 * Affichage step-by-step de l'avancement d'un job (ou d'un pipeline).
 * Chaque étape porte un statut : done | running | pending | error.
 */
import {
  AlertCircle,
  CheckCircle2,
  Circle,
  Loader2,
  type LucideIcon,
} from "lucide-react";

import { cn } from "@/lib/utils";

export type StepStatus = "done" | "running" | "pending" | "error";

export interface ProgressStep {
  label: string;
  status: StepStatus;
  /** Détail optionnel affiché sous le libellé. */
  detail?: string;
}

interface StepVisual {
  icon: LucideIcon;
  color: string;
  spin?: boolean;
}

const VISUALS: Record<StepStatus, StepVisual> = {
  done: { icon: CheckCircle2, color: "#6ee7b7" },
  running: { icon: Loader2, color: "#7dd3fc", spin: true },
  pending: { icon: Circle, color: "#64748b" },
  error: { icon: AlertCircle, color: "#ff8aa0" },
};

export interface JobProgressStepsProps {
  steps: ProgressStep[];
  className?: string;
}

export function JobProgressSteps({ steps, className }: JobProgressStepsProps) {
  return (
    <ol className={cn("flex flex-col", className)}>
      {steps.map((step, i) => {
        const visual = VISUALS[step.status];
        const Icon = visual.icon;
        const isLast = i === steps.length - 1;
        return (
          <li key={`${step.label}-${i}`} className="flex gap-3">
            <div className="flex flex-col items-center">
              <Icon
                className={cn("h-5 w-5 shrink-0", visual.spin && "animate-spin")}
                style={{ color: visual.color }}
              />
              {!isLast && (
                <span
                  className="my-1 w-px flex-1"
                  style={{
                    minHeight: 16,
                    backgroundColor:
                      step.status === "done" ? "#6ee7b7" : "var(--border)",
                  }}
                />
              )}
            </div>
            <div className={cn("pb-4", isLast && "pb-0")}>
              <p
                className="text-sm font-medium"
                style={{
                  color:
                    step.status === "pending"
                      ? "var(--text-secondary)"
                      : "var(--text-primary)",
                }}
              >
                {step.label}
              </p>
              {step.detail && (
                <p className="text-xs text-muted-foreground">{step.detail}</p>
              )}
            </div>
          </li>
        );
      })}
    </ol>
  );
}
