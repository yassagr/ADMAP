/**
 * Panneau de progression de la génération M3 (règles YARA).
 *
 * Même mécanique que `M2ProgressPanel` : statut de chaque étape dérivé du
 * pourcentage, surlignage opportuniste si le backend nomme l'étape courante.
 */
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { JobProgressSteps } from "@/components/shared";
import type { ProgressStep, StepStatus } from "@/components/shared";
import type { JobStatus } from "@/types";

/** Libellés des stages M3, dans l'ordre du pipeline. */
const M3_STAGES: readonly string[] = [
  "Corpus loading",
  "Feature extraction",
  "Discriminant string selection",
  "Rule generation",
  "yara.compile()",
  "Export",
];

export interface M3ProgressPanelProps {
  progress: number;
  status: JobStatus | null;
  currentStage?: string;
}

function buildSteps(
  progress: number,
  status: JobStatus | null,
  currentStage?: string,
): ProgressStep[] {
  const n = M3_STAGES.length;
  const failed = status === "failed";
  const stageHint = currentStage?.toLowerCase() ?? "";

  return M3_STAGES.map((label, i): ProgressStep => {
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

export function M3ProgressPanel({
  progress,
  status,
  currentStage,
}: M3ProgressPanelProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          Génération en cours · {Math.round(progress)}%
        </CardTitle>
      </CardHeader>
      <CardContent>
        <JobProgressSteps steps={buildSteps(progress, status, currentStage)} />
      </CardContent>
    </Card>
  );
}
