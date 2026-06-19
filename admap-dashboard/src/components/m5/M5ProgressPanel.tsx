/**
 * Panneau de progression de l'analyse M5 (attribution APT).
 *
 * Même mécanique que `M2ProgressPanel` : statut de chaque étape dérivé du
 * pourcentage, surlignage opportuniste si le backend nomme l'étape courante.
 */
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { JobProgressSteps } from "@/components/shared";
import type { ProgressStep, StepStatus } from "@/components/shared";
import type { JobStatus } from "@/types";

/** Libellés des stages M5, dans l'ordre du pipeline. */
const M5_STAGES: readonly string[] = [
  "Report parsing",
  "Feature vectorization",
  "XGBoost inference",
  "Cosine similarity",
  "Candidate ranking",
  "Export",
];

export interface M5ProgressPanelProps {
  progress: number;
  status: JobStatus | null;
  currentStage?: string;
}

function buildSteps(
  progress: number,
  status: JobStatus | null,
  currentStage?: string,
): ProgressStep[] {
  const n = M5_STAGES.length;
  const failed = status === "failed";
  const stageHint = currentStage?.toLowerCase() ?? "";

  return M5_STAGES.map((label, i): ProgressStep => {
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

export function M5ProgressPanel({
  progress,
  status,
  currentStage,
}: M5ProgressPanelProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          Attribution en cours · {Math.round(progress)}%
        </CardTitle>
      </CardHeader>
      <CardContent>
        <JobProgressSteps steps={buildSteps(progress, status, currentStage)} />
      </CardContent>
    </Card>
  );
}
