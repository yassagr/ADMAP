/**
 * Page M5 — Attribution. Calquée sur la page M4.
 *
 * Orchestration : soumission d'un APTMapReport M4 (+ entrées optionnelles) →
 * suivi temps réel (WebSocket + fallback HTTP via `useJobPolling`) → verdict
 * d'attribution APT + résultats par cluster + export. Gère l'état hors-ligne du
 * module, l'échec de job (retry) et les erreurs réseau. M5 est le module IA :
 * un `AIPhaseSlot` présente les évolutions Phase 2.
 */
import { useState } from "react";
import { motion } from "framer-motion";
import { AlertTriangle, RotateCcw } from "lucide-react";

import { analyzeM5, type M5AnalyzeExtras } from "@/api/m5";
import { useJobPolling } from "@/hooks/useJobPolling";
import { useAdmapStore } from "@/store";
import { fadeInUp } from "@/lib/motion";
import { AIPhaseSlot, JobStatusBadge, JsonViewer, useToast } from "@/components/shared";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { M5ProgressPanel, M5ResultsView, M5SubmitForm } from "@/components/m5";
import type { AttributionReport } from "@/types";

interface Submission {
  file: File;
  extras: M5AnalyzeExtras;
}

export function M5() {
  const { toast } = useToast();
  const moduleStatus = useAdmapStore((s) => s.moduleStatus.m5);

  const [submission, setSubmission] = useState<Submission | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const { status, progress, job, result } = useJobPolling(
    jobId,
    jobId ? "m5" : null,
  );

  const runAnalysis = async (
    file: File,
    extras: M5AnalyzeExtras,
  ): Promise<void> => {
    setIsSubmitting(true);
    setJobId(null);
    try {
      const res = await analyzeM5(file, extras);
      setSubmission({ file, extras });
      setJobId(res.job_id);
    } catch (e) {
      toast({
        variant: "error",
        title: "Échec de la soumission",
        description: e instanceof Error ? e.message : "Erreur réseau",
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  const retry = (): void => {
    if (submission) void runAnalysis(submission.file, submission.extras);
  };

  const analyzing =
    isSubmitting ||
    (jobId !== null &&
      (status === null ||
        status === "queued" ||
        status === "pending" ||
        status === "running"));

  const failed = status === "failed";
  const report = status === "completed" ? (result as AttributionReport | null) : null;
  const offline = moduleStatus.status !== "ok";

  return (
    <motion.section
      className="flex flex-col gap-6"
      variants={fadeInUp}
      initial="hidden"
      animate="visible"
    >
      <header>
        <h1 className="text-2xl font-bold text-white">M5 · Attribution</h1>
        <p className="mt-1 text-slate-400">
          Attribution d'acteurs APT à partir d'un APTMapReport M4 : inférence
          XGBoost + similarité cosinus TTP sur la base MITRE ATT&CK.
        </p>
      </header>

      {offline && (
        <div
          className="flex items-center gap-2 rounded-lg border px-4 py-3 text-sm"
          style={{
            borderColor: "rgba(245, 158, 11, 0.5)",
            backgroundColor: "rgba(245, 158, 11, 0.08)",
            color: "#fcd34d",
          }}
        >
          <AlertTriangle className="h-4 w-4 shrink-0" />
          Module M5 injoignable ({moduleStatus.status}). Vous pouvez préparer une
          analyse, mais la soumission échouera tant que le service est hors ligne.
        </div>
      )}

      <M5SubmitForm
        onSubmit={(f, extras) => void runAnalysis(f, extras)}
        disabled={analyzing}
      />

      {jobId && analyzing && (
        <div className="flex flex-col gap-2">
          {status && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              Statut : <JobStatusBadge status={status} />
            </div>
          )}
          <M5ProgressPanel
            progress={progress}
            status={status}
            currentStage={job?.current_stage}
          />
        </div>
      )}

      {failed && (
        <Card style={{ borderColor: "rgba(255, 45, 85, 0.5)" }}>
          <CardHeader className="flex-row items-center justify-between space-y-0">
            <CardTitle className="flex items-center gap-2 text-base text-destructive">
              <AlertTriangle className="h-5 w-5" />
              Attribution échouée
            </CardTitle>
            <Button variant="outline" size="sm" onClick={retry} disabled={!submission}>
              <RotateCcw className="h-4 w-4" />
              Réessayer
            </Button>
          </CardHeader>
          <CardContent>
            <JsonViewer
              data={job ?? { error: "Détail indisponible" }}
              defaultExpandedDepth={2}
            />
          </CardContent>
        </Card>
      )}

      {report && <M5ResultsView report={report} jobId={jobId!} />}

      <AIPhaseSlot
        title="M5-IA · Attribution XGBoost (cœur IA d'ADMAP)"
        description="Classifieur XGBoost multi-classes sur vecteurs TTP + similarité cosinus contre les profils MITRE ATT&CK. Évolutions Phase 2 : ré-entraînement continu et calibration des probabilités."
      >
        <div className="flex gap-2 text-sm">
          <span className="rounded border border-border px-2 py-1">XGBoost</span>
          <span className="rounded border border-border px-2 py-1">
            Cosine TTP
          </span>
          <span className="rounded border border-border px-2 py-1">
            MITRE ATT&CK
          </span>
        </div>
      </AIPhaseSlot>
    </motion.section>
  );
}
