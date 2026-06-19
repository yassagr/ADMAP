/**
 * État vide de la page IA / Modèle : affiché lorsque le modèle n'est pas encore
 * entraîné (`is_trained=false`) ou que les données exploitables sont absentes.
 */
import { BrainCircuit } from "lucide-react";

import { Card, CardContent } from "@/components/ui/card";

export interface AIEmptyStateProps {
  /** Message complémentaire optionnel (ex. nom du fichier attendu). */
  hint?: string;
}

export function AIEmptyState({ hint }: AIEmptyStateProps) {
  return (
    <Card>
      <CardContent className="flex flex-col items-center gap-4 py-16 text-center">
        <span
          className="flex h-14 w-14 items-center justify-center rounded-full"
          style={{ backgroundColor: "rgba(168, 85, 247, 0.12)" }}
        >
          <BrainCircuit className="h-7 w-7" style={{ color: "#a855f7" }} />
        </span>
        <div className="flex flex-col gap-1">
          <h2 className="text-lg font-semibold text-foreground">
            Modèle non encore entraîné
          </h2>
          <p className="max-w-md text-sm text-muted-foreground">
            {hint ??
              "Déposez un fichier model_metrics.json renseigné dans public/ pour afficher les performances du modèle (matrice de confusion, ROC, importance des features)."}
          </p>
        </div>
        <code className="rounded border border-border bg-muted/40 px-3 py-1 text-xs text-muted-foreground">
          admap-dashboard/public/model_metrics.json
        </code>
      </CardContent>
    </Card>
  );
}
