/**
 * Panneau de progression de l'analyse M4 (clustering APT).
 *
 * Mappe `progress` (0-100) sur les stages du pipeline M4 et délègue le rendu à
 * `JobProgressSteps`. Même mécanique que `M2ProgressPanel` : statut dérivé du
 * pourcentage, surlignage opportuniste si le backend nomme l'étape courante.
 */
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { JobProgressSteps } from "@/components/shared";
import type { ProgressStep, StepStatus } from "@/components/shared";
import type { JobStatus } from "@/types";

/** Libellés des stages M4, dans l'ordre du pipeline. */
const M4_STAGES: readonly string[] = [
  "AlertBundle parsing",
  "Profile building",
  "Feature vectorization",
  "DBSCAN clustering",
  "MITRE mapping",
  "Campaign labeling",
  "Export",
];

export interface M4ProgressPanelProps {
  progress: number;
  status: JobStatus | null;
  currentStage?: string;
}

function buildSteps(
  progress: number,
  status: JobStatus | null,
  currentStage?: string,
): ProgressStep[] {
  const n = M4_STAGES.length;
  const failed = status === "failed";
  const stageHint = currentStage?.toLowerCase() ?? "";

  return M4_STAGES.map((label, i): ProgressStep => {
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

export function M4ProgressPanel({
  progress,
  status,
  currentStage,
}: M4ProgressPanelProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          Clustering en cours · {Math.round(progress)}%
        </CardTitle>
      </CardHeader>
      <CardContent>
        <JobProgressSteps steps={buildSteps(progress, status, currentStage)} />
      </CardContent>
    </Card>
  );
}
