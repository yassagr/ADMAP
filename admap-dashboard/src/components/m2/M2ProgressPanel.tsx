/**
 * Panneau de progression de l'analyse M2.
 *
 * Mappe `progress` (0-100) sur les 7 stages du pipeline M2 et délègue le rendu à
 * `JobProgressSteps`. Le statut de chaque étape est dérivé du pourcentage ; si
 * `currentStage` correspond à un libellé (substring), cette étape est marquée
 * « en cours ». Aucune dépendance dure aux chaînes exactes du backend.
 */
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { JobProgressSteps } from "@/components/shared";
import type { ProgressStep, StepStatus } from "@/components/shared";
import type { JobStatus } from "@/types";

/** Libellés des stages M2, dans l'ordre du pipeline. */
const M2_STAGES: readonly string[] = [
  "PCAP parsing",
  "Flow reconstruction",
  "Beaconing detection",
  "DGA / DNS tunneling",
  "JA3 fingerprinting",
  "IOC correlation",
  "Export",
];

export interface M2ProgressPanelProps {
  progress: number;
  status: JobStatus | null;
  currentStage?: string;
}

function buildSteps(
  progress: number,
  status: JobStatus | null,
  currentStage?: string,
): ProgressStep[] {
  const n = M2_STAGES.length;
  const failed = status === "failed";
  const stageHint = currentStage?.toLowerCase() ?? "";

  return M2_STAGES.map((label, i): ProgressStep => {
    const start = (i / n) * 100;
    const end = ((i + 1) / n) * 100;
    let stepStatus: StepStatus;
    if (progress >= end) {
      stepStatus = "done";
    } else if (progress >= start) {
      stepStatus = failed ? "error" : "running";
    } else {
      stepStatus = "pending";
    }
    // Surlignage opportuniste si le backend nomme explicitement l'étape.
    if (
      !failed &&
      stageHint &&
      label.toLowerCase().split(/[ /]+/).some((w) => w.length > 2 && stageHint.includes(w))
    ) {
      stepStatus = stepStatus === "done" ? "done" : "running";
    }
    return { label, status: stepStatus };
  });
}

export function M2ProgressPanel({
  progress,
  status,
  currentStage,
}: M2ProgressPanelProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          Analyse en cours · {Math.round(progress)}%
        </CardTitle>
      </CardHeader>
      <CardContent>
        <JobProgressSteps steps={buildSteps(progress, status, currentStage)} />
      </CardContent>
    </Card>
  );
}
