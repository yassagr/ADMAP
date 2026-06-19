/**
 * Pied de page du rapport : mention de génération automatique, niveau TLP et
 * date. Imprimé en bas du document.
 */
import type { TLPLevel } from "@/types";

export interface ReportFooterProps {
  /** Niveau TLP du document (par défaut TLP:AMBER pour un rapport interne SOC). */
  tlp?: TLPLevel;
  generatedAt: string;
}

export function ReportFooter({ tlp = "TLP:AMBER", generatedAt }: ReportFooterProps) {
  return (
    <footer className="report-section flex flex-wrap items-center justify-between gap-2 border-t border-border pt-4 text-xs text-muted-foreground">
      <span>Généré automatiquement par ADMAP — SOC / CERT.</span>
      <span className="flex items-center gap-3">
        <span className="font-mono font-semibold text-foreground">{tlp}</span>
        <span>{new Date(generatedAt).toLocaleDateString("fr-FR")}</span>
      </span>
    </footer>
  );
}
