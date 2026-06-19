/**
 * Formulaire de soumission M1 : dépôt d'un fichier suspect générique
 * (PE / ELF / texte — PAS un PCAP) + toggles d'enrichissement VirusTotal et de
 * désobfuscation. Émet `(file, options)` au parent. Calqué sur `M2SubmitForm`.
 */
import { useState } from "react";
import { FileSearch } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Toggle } from "@/components/ui/toggle";
import { FileDropZone } from "@/components/shared";
import type { M1AnalyzeOptions } from "@/api/m1";

export interface M1SubmitFormProps {
  onSubmit: (file: File, options: M1AnalyzeOptions) => void;
  /** Désactive le formulaire (soumission/analyse en cours). */
  disabled?: boolean;
}

export function M1SubmitForm({ onSubmit, disabled = false }: M1SubmitFormProps) {
  const [file, setFile] = useState<File | null>(null);
  const [enableVt, setEnableVt] = useState(false);
  const [enableDeobfuscation, setEnableDeobfuscation] = useState(true);

  const handleAnalyze = (): void => {
    if (!file) return;
    onSubmit(file, { enableVt, enableDeobfuscation });
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FileSearch className="h-5 w-5 text-primary" />
          Extraction d'IOC
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-5">
        <FileDropZone
          label={
            file
              ? `Fichier sélectionné : ${file.name}`
              : "Glissez un fichier suspect (PE / ELF / texte) ou cliquez pour parcourir"
          }
          disabled={disabled}
          onFiles={(files) => setFile(files[0] ?? null)}
        />

        <div className="flex flex-col gap-2">
          <Label>Options d'analyse</Label>
          <div className="flex flex-wrap gap-2">
            <Toggle
              variant="outline"
              size="sm"
              pressed={enableDeobfuscation}
              onPressedChange={setEnableDeobfuscation}
              disabled={disabled}
            >
              Désobfuscation
            </Toggle>
            <Toggle
              variant="outline"
              size="sm"
              pressed={enableVt}
              onPressedChange={setEnableVt}
              disabled={disabled}
            >
              Enrichissement VirusTotal
            </Toggle>
          </div>
          <p className="text-xs text-muted-foreground">
            VirusTotal requiert une clé API configurée côté microservice M1 ;
            laissez désactivé pour une extraction hors-ligne.
          </p>
        </div>

        <div>
          <Button onClick={handleAnalyze} disabled={disabled || !file}>
            <FileSearch className="h-4 w-4" />
            Extraire
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
