/**
 * Panneau de progression de l'analyse M1 (extraction d'IOC).
 *
 * Même mécanique que `M2ProgressPanel` : statut de chaque étape dérivé du
 * pourcentage, surlignage opportuniste si le backend nomme l'étape courante.
 */
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { JobProgressSteps } from "@/components/shared";
import type { ProgressStep, StepStatus } from "@/components/shared";
import type { JobStatus } from "@/types";

/** Libellés des stages M1, dans l'ordre du pipeline. */
const M1_STAGES: readonly string[] = [
  "File parsing",
  "Deobfuscation",
  "IOC extraction",
  "Filtering",
  "Scoring",
  "VT enrichment",
  "Export",
];

export interface M1ProgressPanelProps {
  progress: number;
  status: JobStatus | null;
  currentStage?: string;
}

function buildSteps(
  progress: number,
  status: JobStatus | null,
  currentStage?: string,
): ProgressStep[] {
  const n = M1_STAGES.length;
  const failed = status === "failed";
  const stageHint = currentStage?.toLowerCase() ?? "";

  return M1_STAGES.map((label, i): ProgressStep => {
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

export function M1ProgressPanel({
  progress,
  status,
  currentStage,
}: M1ProgressPanelProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          Extraction en cours · {Math.round(progress)}%
        </CardTitle>
      </CardHeader>
      <CardContent>
        <JobProgressSteps steps={buildSteps(progress, status, currentStage)} />
      </CardContent>
    </Card>
  );
}
