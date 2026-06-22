/**
 * Pastille colorée identifiant l'origine d'une analyse (M1-M5 ou PIPELINE),
 * partagée par l'Overview et l'Historique. Couleurs alignées sur `MODULE_COLOR`.
 */
import { MODULE_COLOR } from "@/lib/overview-stats";
import type { AnalysisModule } from "@/types";

const MODULE_LABEL: Record<AnalysisModule, string> = {
  M1: "M1 · IOC",
  M2: "M2 · C2",
  M3: "M3 · YARA",
  M4: "M4 · APT",
  M5: "M5 · Attribution",
  PIPELINE: "Pipeline",
};

export interface ModuleBadgeProps {
  module: AnalysisModule;
  /** Forme courte (M1) plutôt que le libellé long. */
  short?: boolean;
}

export function ModuleBadge({ module, short = false }: ModuleBadgeProps) {
  const color = MODULE_COLOR[module];
  return (
    <span
      className="inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold"
      style={{
        color,
        borderColor: `${color}88`,
        backgroundColor: `${color}1f`,
      }}
    >
      {short ? module : MODULE_LABEL[module]}
    </span>
  );
}
