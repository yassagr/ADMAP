/**
 * Formulaire de soumission M5 : dépôt de l'APTMapReport M4 (JSON, OBLIGATOIRE) +
 * IOCBundle M1 / AlertBundle M2 optionnels, sérialisés en `extras`. Émet
 * `(aptMapReport, extras)` au parent. Calqué sur `M4SubmitForm`.
 *
 * Raccourci : si le store contient déjà un résultat M4 (`APTMapReport`), un
 * bouton « Utiliser le dernier résultat M4 » le sérialise en `File` JSON.
 */
import { useState } from "react";
import { Fingerprint, Sparkles } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { FileDropZone } from "@/components/shared";
import { useAdmapStore } from "@/store";
import type { M5AnalyzeExtras } from "@/api/m5";
import type { APTMapReport } from "@/types";

export interface M5SubmitFormProps {
  onSubmit: (aptMapReport: File, extras: M5AnalyzeExtras) => void;
  /** Désactive le formulaire (soumission/analyse en cours). */
  disabled?: boolean;
}

/** Dernier `APTMapReport` M4 disponible dans le store (job M4 le plus récent). */
function useLastM4Report(): APTMapReport | null {
  return useAdmapStore((s) => {
    let latest: { job_id: string; created_at: string } | null = null;
    for (const job of Object.values(s.activeJobs)) {
      if (job.module !== "m4") continue;
      if (!latest || job.created_at >= latest.created_at) latest = job;
    }
    if (!latest) return null;
    const result = s.jobResults[latest.job_id];
    return result ? (result as APTMapReport) : null;
  });
}

export function M5SubmitForm({ onSubmit, disabled = false }: M5SubmitFormProps) {
  const lastM4Report = useLastM4Report();

  const [reportFile, setReportFile] = useState<File | null>(null);
  const [iocFile, setIocFile] = useState<File | null>(null);
  const [alertFile, setAlertFile] = useState<File | null>(null);

  const useLastM4 = (): void => {
    if (!lastM4Report) return;
    const json = JSON.stringify(lastM4Report, null, 2);
    setReportFile(
      new File([json], `m4-apt-map-${lastM4Report.report_id}.json`, {
        type: "application/json",
      }),
    );
  };

  const handleAnalyze = (): void => {
    if (!reportFile) return;
    onSubmit(reportFile, {
      iocBundle: iocFile ?? undefined,
      alertBundle: alertFile ?? undefined,
    });
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Fingerprint className="h-5 w-5 text-primary" />
          Attribution APT
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-5">
        <div className="flex flex-col gap-2">
          <div className="flex items-center justify-between">
            <Label>APTMapReport M4 (JSON — obligatoire)</Label>
            {lastM4Report && (
              <Button
                variant="outline"
                size="sm"
                onClick={useLastM4}
                disabled={disabled}
              >
                <Sparkles className="h-4 w-4" />
                Utiliser le dernier résultat M4
              </Button>
            )}
          </div>
          <FileDropZone
            accept=".json"
            label={
              reportFile
                ? `APTMapReport : ${reportFile.name}`
                : "Glissez l'APTMapReport M4 (.json) ou cliquez pour parcourir"
            }
            disabled={disabled}
            onFiles={(files) => setReportFile(files[0] ?? null)}
          />
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <div className="flex flex-col gap-2">
            <Label>IOCBundle M1 (optionnel)</Label>
            <FileDropZone
              accept=".json"
              label={
                iocFile ? `IOCBundle : ${iocFile.name}` : "Déposer un IOCBundle (.json)"
              }
              disabled={disabled}
              onFiles={(files) => setIocFile(files[0] ?? null)}
            />
          </div>
          <div className="flex flex-col gap-2">
            <Label>AlertBundle M2 (optionnel)</Label>
            <FileDropZone
              accept=".json"
              label={
                alertFile
                  ? `AlertBundle : ${alertFile.name}`
                  : "Déposer un AlertBundle (.json)"
              }
              disabled={disabled}
              onFiles={(files) => setAlertFile(files[0] ?? null)}
            />
          </div>
        </div>

        <div>
          <Button onClick={handleAnalyze} disabled={disabled || !reportFile}>
            <Fingerprint className="h-4 w-4" />
            Attribuer
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
