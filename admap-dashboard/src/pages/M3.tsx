/**
 * Page M3 — YARA Generator. Calquée sur la page M2.
 *
 * Orchestration : soumission de deux corpus (malveillant + bénin) → suivi temps
 * réel (WebSocket + fallback HTTP via `useJobPolling`) → résultats (règles YARA,
 * scores discriminants, statut de compilation, export). Gère l'état hors-ligne
 * du module, l'échec de job (retry) et les erreurs réseau.
 */
import { useState } from "react";
import { motion } from "framer-motion";
import { AlertTriangle, RotateCcw } from "lucide-react";

import { generateM3 } from "@/api/m3";
import { useJobPolling } from "@/hooks/useJobPolling";
import { useAnalysisRecorder } from "@/hooks/useAnalysisRecorder";
import { summarizeM3 } from "@/lib/analysis-summary";
import { useAdmapStore } from "@/store";
import { fadeInUp } from "@/lib/motion";
import { JobStatusBadge, JsonViewer, useToast } from "@/components/shared";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { M3ProgressPanel, M3ResultsView, M3SubmitForm } from "@/components/m3";
import type { YaraRuleSet } from "@/types";

interface Submission {
  malwareFiles: File[];
  benignFiles: File[];
  m1Bundle?: File;
}

export function M3() {
  const { toast } = useToast();
  const moduleStatus = useAdmapStore((s) => s.moduleStatus.m3);

  const [submission, setSubmission] = useState<Submission | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const { status, progress, job, result } = useJobPolling(
    jobId,
    jobId ? "m3" : null,
  );

  const runGeneration = async (
    malwareFiles: File[],
    benignFiles: File[],
    m1Bundle?: File,
  ): Promise<void> => {
    setIsSubmitting(true);
    setJobId(null);
    try {
      const res = await generateM3(malwareFiles, benignFiles, m1Bundle);
      setSubmission({ malwareFiles, benignFiles, m1Bundle });
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
    if (submission)
      void runGeneration(
        submission.malwareFiles,
        submission.benignFiles,
        submission.m1Bundle,
      );
  };

  const analyzing =
    isSubmitting ||
    (jobId !== null &&
      (status === null ||
        status === "queued" ||
        status === "pending" ||
        status === "running"));

  const failed = status === "failed";
  const ruleset = status === "completed" ? (result as YaraRuleSet | null) : null;
  const offline = moduleStatus.status !== "ok";

  const recordId = useAnalysisRecorder("M3", jobId, ruleset, (rs) => ({
    inputName: submission
      ? `${submission.malwareFiles.length} malveillant(s) / ${submission.benignFiles.length} bénin(s)`
      : `Corpus ${rs.corpus_id}`,
    summary: summarizeM3(rs),
  }));

  return (
    <motion.section
      className="flex flex-col gap-6"
      variants={fadeInUp}
      initial="hidden"
      animate="visible"
    >
      <header>
        <h1 className="text-2xl font-bold text-white">M3 · YARA Generator</h1>
        <p className="mt-1 text-slate-400">
          Génération de règles YARA discriminantes par contraste entre un corpus
          malveillant et un corpus bénin, avec validation `yara.compile()`.
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
          Module M3 injoignable ({moduleStatus.status}). Vous pouvez préparer une
          génération, mais la soumission échouera tant que le service est hors ligne.
        </div>
      )}

      <M3SubmitForm
        onSubmit={(m, b, ioc) => void runGeneration(m, b, ioc)}
        disabled={analyzing}
      />

      {jobId && analyzing && (
        <div className="flex flex-col gap-2">
          {status && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              Statut : <JobStatusBadge status={status} />
            </div>
          )}
          <M3ProgressPanel
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
              Génération échouée
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

      {ruleset && (
        <M3ResultsView ruleset={ruleset} jobId={jobId!} reportRecordId={recordId} />
      )}
    </motion.section>
  );
}
