/**
 * Bouton « Générer le rapport » : navigue vers /report en transmettant l'id de
 * l'analyse enregistrée. Inactif tant qu'aucun enregistrement n'existe.
 */
import { Link } from "react-router-dom";
import { FileText } from "lucide-react";

import { Button } from "@/components/ui/button";

export interface ReportButtonProps {
  recordId?: string | null;
  className?: string;
}

export function ReportButton({ recordId, className }: ReportButtonProps) {
  if (!recordId) {
    return (
      <Button variant="outline" size="sm" disabled className={className}>
        <FileText className="h-4 w-4" />
        Générer le rapport
      </Button>
    );
  }
  return (
    <Button asChild variant="outline" size="sm" className={className}>
      <Link to="/report" state={{ recordId }}>
        <FileText className="h-4 w-4" />
        Générer le rapport
      </Link>
    </Button>
  );
}
