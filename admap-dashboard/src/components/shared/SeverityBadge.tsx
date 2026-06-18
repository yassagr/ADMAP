/**
 * Badge de sévérité (critical | high | medium | low | info).
 *
 * Couleurs alignées sur le codage sévérité ADMAP. Le thème n'étant pas
 * alpha-aware sur ses tokens CSS-var, les fonds/bordures translucides utilisent
 * `rgba()` brut. `critical` reçoit un halo pulsé (framer-motion). `aiEnhanced`
 * ajoute un indicateur purple (Phase 2 IA).
 */
import { motion } from "framer-motion";
import { Sparkles } from "lucide-react";

import { cn } from "@/lib/utils";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

interface SeverityStyle {
  label: string;
  fg: string;
  bg: string;
  border: string;
}

const STYLES: Record<Severity, SeverityStyle> = {
  critical: {
    label: "Critical",
    fg: "#ff8aa0",
    bg: "rgba(255, 45, 85, 0.16)",
    border: "rgba(255, 45, 85, 0.55)",
  },
  high: {
    label: "High",
    fg: "#ffb089",
    bg: "rgba(255, 107, 53, 0.16)",
    border: "rgba(255, 107, 53, 0.55)",
  },
  medium: {
    label: "Medium",
    fg: "#fcd34d",
    bg: "rgba(245, 158, 11, 0.16)",
    border: "rgba(245, 158, 11, 0.5)",
  },
  low: {
    label: "Low",
    fg: "#7dd3fc",
    bg: "rgba(0, 212, 255, 0.14)",
    border: "rgba(0, 212, 255, 0.45)",
  },
  info: {
    label: "Info",
    fg: "#cbd5e1",
    bg: "rgba(148, 163, 184, 0.14)",
    border: "rgba(148, 163, 184, 0.4)",
  },
};

export interface SeverityBadgeProps {
  severity: Severity;
  /** Marque l'élément comme enrichi par l'IA (Phase 2) — liseré purple + icône. */
  aiEnhanced?: boolean;
  /** Texte affiché ; par défaut le libellé canonique de la sévérité. */
  label?: string;
  className?: string;
}

export function SeverityBadge({
  severity,
  aiEnhanced = false,
  label,
  className,
}: SeverityBadgeProps) {
  const style = STYLES[severity];

  return (
    <motion.span
      className={cn(
        "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-semibold uppercase tracking-wide",
        className,
      )}
      style={{
        color: aiEnhanced ? "#c4b5fd" : style.fg,
        backgroundColor: aiEnhanced ? "rgba(139, 92, 246, 0.16)" : style.bg,
        borderColor: aiEnhanced ? "rgba(139, 92, 246, 0.55)" : style.border,
      }}
      animate={
        severity === "critical"
          ? {
              boxShadow: [
                "0 0 0 rgba(255, 45, 85, 0)",
                "0 0 10px rgba(255, 45, 85, 0.55)",
                "0 0 0 rgba(255, 45, 85, 0)",
              ],
            }
          : undefined
      }
      transition={
        severity === "critical"
          ? { duration: 1.6, repeat: Infinity, ease: "easeInOut" }
          : undefined
      }
    >
      {aiEnhanced && <Sparkles className="h-3 w-3" />}
      {label ?? style.label}
    </motion.span>
  );
}
