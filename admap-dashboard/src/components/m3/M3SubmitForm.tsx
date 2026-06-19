/**
 * Formulaire de soumission M3 : DEUX corpus de fichiers (malveillant + bénin,
 * les deux requis car M3 est discriminant) + IOCBundle M1 optionnel. Émet
 * `(malwareFiles, benignFiles, m1Bundle?)` au parent. Calqué sur le bloc corpus
 * du formulaire pipeline.
 */
import { useState } from "react";
import { ScanLine, Sparkles, X } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { FileDropZone } from "@/components/shared";
import { useAdmapStore } from "@/store";
import type { IOCBundle } from "@/types";

export interface M3SubmitFormProps {
  onSubmit: (
    malwareFiles: File[],
    benignFiles: File[],
    m1Bundle?: File,
  ) => void;
  /** Désactive le formulaire (soumission/analyse en cours). */
  disabled?: boolean;
}

/** Ligne d'affichage d'un fichier sélectionné, avec retrait. */
function SelectedFile({
  name,
  onRemove,
  disabled,
}: {
  name: string;
  onRemove: () => void;
  disabled: boolean;
}) {
  return (
    <div className="flex items-center justify-between gap-2 rounded-md border border-border px-3 py-1.5 text-sm">
      <span className="truncate font-mono text-foreground">{name}</span>
      <button
        type="button"
        onClick={onRemove}
        disabled={disabled}
        className="shrink-0 text-muted-foreground hover:text-destructive disabled:opacity-50"
        aria-label={`Retirer ${name}`}
      >
        <X className="h-4 w-4" />
      </button>
    </div>
  );
}

/** Dernier `IOCBundle` M1 disponible dans le store (job M1 le plus récent). */
function useLastM1Bundle(): IOCBundle | null {
  return useAdmapStore((s) => {
    let latest: { job_id: string; created_at: string } | null = null;
    for (const job of Object.values(s.activeJobs)) {
      if (job.module !== "m1") continue;
      if (!latest || job.created_at >= latest.created_at) latest = job;
    }
    if (!latest) return null;
    const result = s.jobResults[latest.job_id];
    return result ? (result as IOCBundle) : null;
  });
}

export function M3SubmitForm({ onSubmit, disabled = false }: M3SubmitFormProps) {
  const lastM1Bundle = useLastM1Bundle();

  const [malware, setMalware] = useState<File[]>([]);
  const [benign, setBenign] = useState<File[]>([]);
  const [m1Bundle, setM1Bundle] = useState<File | null>(null);

  const removeFrom = (
    setter: React.Dispatch<React.SetStateAction<File[]>>,
    index: number,
  ): void => setter((prev) => prev.filter((_, i) => i !== index));

  const useLastM1 = (): void => {
    if (!lastM1Bundle) return;
    const json = JSON.stringify(lastM1Bundle, null, 2);
    setM1Bundle(
      new File([json], `m1-ioc-bundle-${lastM1Bundle.bundle_id}.json`, {
        type: "application/json",
      }),
    );
  };

  const ready = malware.length > 0 && benign.length > 0;

  const handleGenerate = (): void => {
    if (!ready) return;
    onSubmit(malware, benign, m1Bundle ?? undefined);
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ScanLine className="h-5 w-5 text-primary" />
          Génération de règles YARA
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-6">
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="flex flex-col gap-2">
            <Label className="flex items-center gap-2">
              Corpus malveillant
              <span className="text-xs font-normal text-destructive">
                · obligatoire ({malware.length})
              </span>
            </Label>
            <FileDropZone
              multiple
              label="Déposez les échantillons malveillants"
              disabled={disabled}
              onFiles={(files) => setMalware((prev) => [...prev, ...files])}
            />
            {malware.map((f, i) => (
              <SelectedFile
                key={`${f.name}-${i}`}
                name={f.name}
                onRemove={() => removeFrom(setMalware, i)}
                disabled={disabled}
              />
            ))}
          </div>

          <div className="flex flex-col gap-2">
            <Label className="flex items-center gap-2">
              Corpus bénin
              <span className="text-xs font-normal text-destructive">
                · obligatoire ({benign.length})
              </span>
            </Label>
            <FileDropZone
              multiple
              label="Déposez les échantillons bénins"
              disabled={disabled}
              onFiles={(files) => setBenign((prev) => [...prev, ...files])}
            />
            {benign.map((f, i) => (
              <SelectedFile
                key={`${f.name}-${i}`}
                name={f.name}
                onRemove={() => removeFrom(setBenign, i)}
                disabled={disabled}
              />
            ))}
          </div>
        </div>

        <div className="flex flex-col gap-2">
          <div className="flex items-center justify-between">
            <Label>IOCBundle M1 (optionnel — enrichit les métadonnées)</Label>
            {lastM1Bundle && (
              <Button
                variant="outline"
                size="sm"
                onClick={useLastM1}
                disabled={disabled}
              >
                <Sparkles className="h-4 w-4" />
                Utiliser le dernier résultat M1
              </Button>
            )}
          </div>
          {m1Bundle ? (
            <SelectedFile
              name={m1Bundle.name}
              onRemove={() => setM1Bundle(null)}
              disabled={disabled}
            />
          ) : (
            <FileDropZone
              accept=".json"
              label="Déposer un IOCBundle M1 (.json)"
              disabled={disabled}
              onFiles={(files) => setM1Bundle(files[0] ?? null)}
            />
          )}
        </div>

        {!ready && (malware.length > 0 || benign.length > 0) && (
          <p className="text-xs text-amber-400">
            Les deux corpus (malveillant ET bénin) sont requis : M3 sélectionne
            les chaînes discriminantes par contraste.
          </p>
        )}

        <div>
          <Button onClick={handleGenerate} disabled={disabled || !ready}>
            <ScanLine className="h-4 w-4" />
            Générer
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
