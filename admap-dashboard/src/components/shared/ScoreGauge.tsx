/**
 * Jauge de score circulaire 0-100.
 *
 * Anneau SVG dont l'arc se remplit en fonction de la valeur (sweep animé via
 * framer-motion). La couleur suit un dégradé vert -> jaune -> rouge selon la
 * valeur. SVG pur (pas de recharts) : un dégradé le long d'un arc s'exprime
 * mieux ainsi.
 */
import { motion } from "framer-motion";

import { cn } from "@/lib/utils";

export interface ScoreGaugeProps {
  /** Valeur 0-100 (bornée). */
  value: number;
  /** Diamètre en pixels. */
  size?: number;
  /** Épaisseur de l'anneau. */
  thickness?: number;
  /** Libellé sous la valeur (ex. "confiance"). */
  label?: string;
  className?: string;
}

/** Interpole vert (#00ff88) -> jaune (#facc15) -> rouge (#ff2d55) selon 0..100. */
function colorForValue(value: number): string {
  if (value <= 50) {
    const t = value / 50; // 0 -> vert, 1 -> jaune
    const r = Math.round(0 + t * (250 - 0));
    const g = Math.round(255 - t * (255 - 204));
    const b = Math.round(136 - t * (136 - 21));
    return `rgb(${r}, ${g}, ${b})`;
  }
  const t = (value - 50) / 50; // 0 -> jaune, 1 -> rouge
  const r = Math.round(250 + t * (255 - 250));
  const g = Math.round(204 - t * (204 - 45));
  const b = Math.round(21 + t * (85 - 21));
  return `rgb(${r}, ${g}, ${b})`;
}

export function ScoreGauge({
  value,
  size = 120,
  thickness = 10,
  label,
  className,
}: ScoreGaugeProps) {
  const clamped = Math.max(0, Math.min(100, value));
  const radius = (size - thickness) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference * (1 - clamped / 100);
  const color = colorForValue(clamped);
  const center = size / 2;

  return (
    <div
      className={cn("relative inline-flex items-center justify-center", className)}
      style={{ width: size, height: size }}
    >
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={center}
          cy={center}
          r={radius}
          fill="none"
          stroke="var(--border)"
          strokeWidth={thickness}
        />
        <motion.circle
          cx={center}
          cy={center}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={thickness}
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: 0.9, ease: "easeOut" }}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="text-xl font-bold" style={{ color }}>
          {Math.round(clamped)}
        </span>
        {label && (
          <span className="text-[10px] uppercase tracking-wide text-muted-foreground">
            {label}
          </span>
        )}
      </div>
    </div>
  );
}
