/**
 * Formulaire de soumission M4 : dépôt de l'AlertBundle M2 (JSON, OBLIGATOIRE) +
 * IOCBundle M1 / YaraRuleSet M3 optionnels + paramètres DBSCAN sérialisés en
 * `options` JSON. Émet `(alertBundle, extras)` au parent.
 *
 * Raccourci : si le store contient déjà un résultat M2 (`AlertBundle`), un
 * bouton « Utiliser le dernier résultat M2 » le sérialise en `File` JSON.
 */
import { useState } from "react";
import { GitBranch, Sparkles } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Slider } from "@/components/ui/slider";
import { Toggle } from "@/components/ui/toggle";
import { FileDropZone } from "@/components/shared";
import { useAdmapStore } from "@/store";
import type { M4AnalyzeExtras } from "@/api/m4";
import type { AlertBundle } from "@/types";

export interface M4SubmitFormProps {
  onSubmit: (alertBundle: File, extras: M4AnalyzeExtras) => void;
  /** Désactive le formulaire (soumission/analyse en cours). */
  disabled?: boolean;
}

/**
 * Sélectionne le dernier `AlertBundle` M2 disponible dans le store (job M2 le
 * plus récent dont le résultat a été mis en cache). Renvoie une référence
 * stable (le résultat stocké) ou `null` — pas de nouvel objet à chaque render.
 */
function useLastM2Bundle(): AlertBundle | null {
  return useAdmapStore((s) => {
    let latest: { job_id: string; created_at: string } | null = null;
    for (const job of Object.values(s.activeJobs)) {
      if (job.module !== "m2") continue;
      if (!latest || job.created_at >= latest.created_at) latest = job;
    }
    if (!latest) return null;
    const result = s.jobResults[latest.job_id];
    return result ? (result as AlertBundle) : null;
  });
}

export function M4SubmitForm({ onSubmit, disabled = false }: M4SubmitFormProps) {
  const lastM2Bundle = useLastM2Bundle();

  const [alertFile, setAlertFile] = useState<File | null>(null);
  const [iocFile, setIocFile] = useState<File | null>(null);
  const [yaraFile, setYaraFile] = useState<File | null>(null);

  const [epsilon, setEpsilon] = useState(0.5);
  const [minSamples, setMinSamples] = useState(2);
  const [minConfidence, setMinConfidence] = useState(0);
  const [includeYara, setIncludeYara] = useState(true);
  const [includeIoc, setIncludeIoc] = useState(true);

  const useLastM2 = (): void => {
    if (!lastM2Bundle) return;
    const json = JSON.stringify(lastM2Bundle, null, 2);
    const file = new File([json], `m2-alert-bundle-${lastM2Bundle.bundle_id}.json`, {
      type: "application/json",
    });
    setAlertFile(file);
  };

  const handleAnalyze = (): void => {
    if (!alertFile) return;
    const options = {
      dbscan_epsilon: epsilon,
      dbscan_min_samples: minSamples,
      min_confidence_score: minConfidence,
      include_yara_tags: includeYara,
      include_ioc_enrichment: includeIoc,
    };
    onSubmit(alertFile, {
      iocBundle: iocFile ?? undefined,
      yaraRuleset: yaraFile ?? undefined,
      options: JSON.stringify(options),
    });
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <GitBranch className="h-5 w-5 text-primary" />
          Clustering de campagnes APT
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-5">
        <div className="flex flex-col gap-2">
          <div className="flex items-center justify-between">
            <Label>AlertBundle M2 (JSON — obligatoire)</Label>
            {lastM2Bundle && (
              <Button
                variant="outline"
                size="sm"
                onClick={useLastM2}
                disabled={disabled}
              >
                <Sparkles className="h-4 w-4" />
                Utiliser le dernier résultat M2
              </Button>
            )}
          </div>
          <FileDropZone
            accept=".json"
            label={
              alertFile
                ? `AlertBundle : ${alertFile.name}`
                : "Glissez l'AlertBundle M2 (.json) ou cliquez pour parcourir"
            }
            disabled={disabled}
            onFiles={(files) => setAlertFile(files[0] ?? null)}
          />
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <div className="flex flex-col gap-2">
            <Label>IOCBundle M1 (optionnel)</Label>
            <FileDropZone
              accept=".json"
              label={
                iocFile
                  ? `IOCBundle : ${iocFile.name}`
                  : "Déposer un IOCBundle (.json)"
              }
              disabled={disabled}
              onFiles={(files) => setIocFile(files[0] ?? null)}
            />
          </div>
          <div className="flex flex-col gap-2">
            <Label>YaraRuleSet M3 (optionnel)</Label>
            <FileDropZone
              accept=".json,.yar,.yara"
              label={
                yaraFile
                  ? `YaraRuleSet : ${yaraFile.name}`
                  : "Déposer un YaraRuleSet"
              }
              disabled={disabled}
              onFiles={(files) => setYaraFile(files[0] ?? null)}
            />
          </div>
        </div>

        <div className="grid gap-5 md:grid-cols-3">
          <div className="flex flex-col gap-2">
            <Label>
              DBSCAN epsilon :{" "}
              <span className="font-mono text-primary">{epsilon.toFixed(2)}</span>
            </Label>
            <Slider
              value={[epsilon]}
              min={0.1}
              max={2}
              step={0.05}
              disabled={disabled}
              onValueChange={(v) => setEpsilon(v[0] ?? 0.5)}
            />
          </div>
          <div className="flex flex-col gap-2">
            <Label>
              Min. échantillons :{" "}
              <span className="font-mono text-primary">{minSamples}</span>
            </Label>
            <Slider
              value={[minSamples]}
              min={2}
              max={10}
              step={1}
              disabled={disabled}
              onValueChange={(v) => setMinSamples(v[0] ?? 2)}
            />
          </div>
          <div className="flex flex-col gap-2">
            <Label>
              Confiance min. :{" "}
              <span className="font-mono text-primary">{minConfidence}</span>
            </Label>
            <Slider
              value={[minConfidence]}
              min={0}
              max={100}
              step={5}
              disabled={disabled}
              onValueChange={(v) => setMinConfidence(v[0] ?? 0)}
            />
          </div>
        </div>

        <div className="flex flex-col gap-2">
          <Label>Enrichissement</Label>
          <div className="flex flex-wrap gap-2">
            <Toggle
              variant="outline"
              size="sm"
              pressed={includeYara}
              onPressedChange={setIncludeYara}
              disabled={disabled}
            >
              Tags YARA
            </Toggle>
            <Toggle
              variant="outline"
              size="sm"
              pressed={includeIoc}
              onPressedChange={setIncludeIoc}
              disabled={disabled}
            >
              Enrichissement IOC
            </Toggle>
          </div>
        </div>

        <div>
          <Button onClick={handleAnalyze} disabled={disabled || !alertFile}>
            <GitBranch className="h-4 w-4" />
            Cartographier
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
