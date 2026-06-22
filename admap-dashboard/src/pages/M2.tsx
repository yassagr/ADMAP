/**
 * Page M2 — C2 Detector. Gabarit de référence des pages module ADMAP.
 *
 * Orchestration : soumission PCAP → suivi temps réel (WebSocket + fallback HTTP
 * via `useJobPolling`) → résultats (alertes, donut, graphe réseau, export).
 * Gère l'état hors-ligne du module, l'échec de job (retry) et les erreurs réseau.
 */
import { useState } from "react";
import { motion } from "framer-motion";
import { AlertTriangle, RotateCcw } from "lucide-react";

import { analyzeM2, type M2AnalyzeOptions } from "@/api/m2";
import { useJobPolling } from "@/hooks/useJobPolling";
import { useAnalysisRecorder } from "@/hooks/useAnalysisRecorder";
import { summarizeM2 } from "@/lib/analysis-summary";
import { useAdmapStore } from "@/store";
import { fadeInUp } from "@/lib/motion";
import { AIPhaseSlot, JobStatusBadge, JsonViewer, useToast } from "@/components/shared";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  M2ProgressPanel,
  M2ResultsView,
  M2SubmitForm,
} from "@/components/m2";
import type { AlertBundle } from "@/types";

interface Submission {
  file: File;
  options: M2AnalyzeOptions;
}

export function M2() {
  const { toast } = useToast();
  const moduleStatus = useAdmapStore((s) => s.moduleStatus.m2);

  const [submission, setSubmission] = useState<Submission | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const { status, progress, job, result } = useJobPolling(
    jobId,
    jobId ? "m2" : null,
  );

  const runAnalysis = async (file: File, options: M2AnalyzeOptions): Promise<void> => {
    setIsSubmitting(true);
    setJobId(null);
    try {
      const res = await analyzeM2(file, options);
      setSubmission({ file, options });
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
    if (submission) void runAnalysis(submission.file, submission.options);
  };

  const analyzing =
    isSubmitting ||
    (jobId !== null &&
      (status === null ||
        status === "queued" ||
        status === "pending" ||
        status === "running"));

  const failed = status === "failed";
  const bundle = status === "completed" ? (result as AlertBundle | null) : null;
  const offline = moduleStatus.status !== "ok";

  const recordId = useAnalysisRecorder("M2", jobId, bundle, (b) => ({
    inputName: submission?.file.name ?? b.pcap_filename,
    summary: summarizeM2(b),
  }));

  return (
    <motion.section
      className="flex flex-col gap-6"
      variants={fadeInUp}
      initial="hidden"
      animate="visible"
    >
      <header>
        <h1 className="text-2xl font-bold text-white">M2 · C2 Detector</h1>
        <p className="mt-1 text-slate-400">
          Analyse de PCAP : beaconing, DGA/DNS tunneling, JA3, corrélation IOC.
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
          Module M2 injoignable ({moduleStatus.status}). Vous pouvez préparer une
          analyse, mais la soumission échouera tant que le service est hors ligne.
        </div>
      )}

      <M2SubmitForm onSubmit={(f, o) => void runAnalysis(f, o)} disabled={analyzing} />

      {jobId && analyzing && (
        <div className="flex flex-col gap-2">
          {status && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              Statut : <JobStatusBadge status={status} />
            </div>
          )}
          <M2ProgressPanel
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
              Analyse échouée
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

      {bundle && (
        <M2ResultsView bundle={bundle} jobId={jobId!} reportRecordId={recordId} />
      )}

      <AIPhaseSlot
        title="M2-IA · Détection ML (Phase 2)"
        description="Random Forest + LSTM sur NetworkFeature (36 champs). Bientôt disponible."
      >
        <div className="flex gap-2 text-sm">
          <span className="rounded border border-border px-2 py-1">Random Forest</span>
          <span className="rounded border border-border px-2 py-1">LSTM</span>
        </div>
      </AIPhaseSlot>
    </motion.section>
  );
}
