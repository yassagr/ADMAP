/**
 * Formulaire de lancement du pipeline complet.
 *
 * Trois groupes d'entrée : PCAP (obligatoire → M2), fichier suspect
 * (optionnel → M1), corpus YARA malveillant + bénin (optionnel → M3, les deux
 * corpus sont requis ensemble car M3 est discriminant). Émet les entrées
 * agrégées au parent ; ne lance rien lui-même.
 */
import { useState } from "react";
import { FileSearch, Network, Play, ScanLine, X } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { FileDropZone } from "@/components/shared";
import type { PipelineInputs } from "@/hooks/usePipeline";

export interface PipelineFormProps {
  onSubmit: (inputs: PipelineInputs) => void;
  /** Désactive le formulaire (pipeline en cours). */
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

export function PipelineForm({ onSubmit, disabled = false }: PipelineFormProps) {
  const [pcap, setPcap] = useState<File | null>(null);
  const [suspectFile, setSuspectFile] = useState<File | null>(null);
  const [corpusMalware, setCorpusMalware] = useState<File[]>([]);
  const [corpusBenign, setCorpusBenign] = useState<File[]>([]);

  const removeFrom = (
    setter: React.Dispatch<React.SetStateAction<File[]>>,
    index: number,
  ): void => setter((prev) => prev.filter((_, i) => i !== index));

  const handleRun = (): void => {
    if (!pcap) return;
    onSubmit({
      pcap,
      suspectFile: suspectFile ?? undefined,
      corpusMalware: corpusMalware.length ? corpusMalware : undefined,
      corpusBenign: corpusBenign.length ? corpusBenign : undefined,
    });
  };

  const corpusReady = corpusMalware.length > 0 && corpusBenign.length > 0;
  const corpusPartial =
    (corpusMalware.length > 0) !== (corpusBenign.length > 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Play className="h-5 w-5 text-primary" />
          Lancer le pipeline ADMAP
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-6">
        {/* PCAP — obligatoire (M2) */}
        <div className="flex flex-col gap-2">
          <Label className="flex items-center gap-2">
            <Network className="h-4 w-4 text-primary" />
            PCAP réseau
            <span className="text-xs font-normal text-destructive">
              · obligatoire (M2)
            </span>
          </Label>
          <FileDropZone
            accept=".pcap,.pcapng"
            label={
              pcap
                ? `PCAP sélectionné : ${pcap.name}`
                : "Glissez un PCAP ici ou cliquez pour parcourir"
            }
            disabled={disabled}
            onFiles={(files) => setPcap(files[0] ?? null)}
          />
        </div>

        {/* Fichier suspect — optionnel (M1) */}
        <div className="flex flex-col gap-2">
          <Label className="flex items-center gap-2">
            <FileSearch className="h-4 w-4 text-muted-foreground" />
            Fichier suspect
            <span className="text-xs font-normal text-muted-foreground">
              · optionnel (M1 — extraction d'IOC)
            </span>
          </Label>
          {suspectFile ? (
            <SelectedFile
              name={suspectFile.name}
              onRemove={() => setSuspectFile(null)}
              disabled={disabled}
            />
          ) : (
            <FileDropZone
              label="PE / ELF / texte — déposez pour enrichir le pipeline"
              disabled={disabled}
              onFiles={(files) => setSuspectFile(files[0] ?? null)}
            />
          )}
        </div>

        {/* Corpus YARA — optionnel (M3) */}
        <div className="flex flex-col gap-3">
          <Label className="flex items-center gap-2">
            <ScanLine className="h-4 w-4 text-muted-foreground" />
            Corpus YARA
            <span className="text-xs font-normal text-muted-foreground">
              · optionnel (M3 — les deux corpus sont requis)
            </span>
          </Label>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="flex flex-col gap-2">
              <span className="text-xs font-medium text-muted-foreground">
                Échantillons malveillants ({corpusMalware.length})
              </span>
              <FileDropZone
                multiple
                label="Déposez les fichiers malveillants"
                disabled={disabled}
                onFiles={(files) =>
                  setCorpusMalware((prev) => [...prev, ...files])
                }
              />
              {corpusMalware.map((f, i) => (
                <SelectedFile
                  key={`${f.name}-${i}`}
                  name={f.name}
                  onRemove={() => removeFrom(setCorpusMalware, i)}
                  disabled={disabled}
                />
              ))}
            </div>
            <div className="flex flex-col gap-2">
              <span className="text-xs font-medium text-muted-foreground">
                Échantillons bénins ({corpusBenign.length})
              </span>
              <FileDropZone
                multiple
                label="Déposez les fichiers bénins"
                disabled={disabled}
                onFiles={(files) =>
                  setCorpusBenign((prev) => [...prev, ...files])
                }
              />
              {corpusBenign.map((f, i) => (
                <SelectedFile
                  key={`${f.name}-${i}`}
                  name={f.name}
                  onRemove={() => removeFrom(setCorpusBenign, i)}
                  disabled={disabled}
                />
              ))}
            </div>
          </div>
          {corpusPartial && (
            <p className="text-xs text-amber-400">
              M3 nécessite les deux corpus (malveillant + bénin) ; il sera ignoré
              tant que l'un des deux est vide.
            </p>
          )}
        </div>

        <div className="flex items-center gap-3">
          <Button onClick={handleRun} disabled={disabled || !pcap}>
            <Play className="h-4 w-4" />
            Exécuter le pipeline
          </Button>
          <span className="text-xs text-muted-foreground">
            Étapes actives : M2{suspectFile ? " · M1" : ""}
            {corpusReady ? " · M3" : ""} · M4 · M5
          </span>
        </div>
      </CardContent>
    </Card>
  );
}
