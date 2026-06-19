/**
 * Page M1 — IOC Extractor. Calquée sur la page M2.
 *
 * Orchestration : soumission d'un fichier suspect (PE/ELF/texte) → suivi temps
 * réel (WebSocket + fallback HTTP via `useJobPolling`) → résultats (IOC groupés,
 * donut, barres, tables, export). Gère l'état hors-ligne du module, l'échec de
 * job (retry) et les erreurs réseau.
 */
import { useState } from "react";
import { motion } from "framer-motion";
import { AlertTriangle, RotateCcw } from "lucide-react";

import { analyzeM1, type M1AnalyzeOptions } from "@/api/m1";
import { useJobPolling } from "@/hooks/useJobPolling";
import { useAdmapStore } from "@/store";
import { fadeInUp } from "@/lib/motion";
import { JobStatusBadge, JsonViewer, useToast } from "@/components/shared";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { M1ProgressPanel, M1ResultsView, M1SubmitForm } from "@/components/m1";
import type { IOCBundle } from "@/types";

interface Submission {
  file: File;
  options: M1AnalyzeOptions;
}

export function M1() {
  const { toast } = useToast();
  const moduleStatus = useAdmapStore((s) => s.moduleStatus.m1);

  const [submission, setSubmission] = useState<Submission | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const { status, progress, job, result } = useJobPolling(
    jobId,
    jobId ? "m1" : null,
  );

  const runAnalysis = async (
    file: File,
    options: M1AnalyzeOptions,
  ): Promise<void> => {
    setIsSubmitting(true);
    setJobId(null);
    try {
      const res = await analyzeM1(file, options);
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
  const bundle = status === "completed" ? (result as IOCBundle | null) : null;
  const offline = moduleStatus.status !== "ok";

  return (
    <motion.section
      className="flex flex-col gap-6"
      variants={fadeInUp}
      initial="hidden"
      animate="visible"
    >
      <header>
        <h1 className="text-2xl font-bold text-white">M1 · IOC Extractor</h1>
        <p className="mt-1 text-slate-400">
          Extraction d'indicateurs de compromission depuis un fichier suspect
          (PE/ELF/texte) : réseau, hashes, hôte, commandes — désobfuscation et
          enrichissement VirusTotal optionnels.
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
          Module M1 injoignable ({moduleStatus.status}). Vous pouvez préparer une
          analyse, mais la soumission échouera tant que le service est hors ligne.
        </div>
      )}

      <M1SubmitForm onSubmit={(f, o) => void runAnalysis(f, o)} disabled={analyzing} />

      {jobId && analyzing && (
        <div className="flex flex-col gap-2">
          {status && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              Statut : <JobStatusBadge status={status} />
            </div>
          )}
          <M1ProgressPanel
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
              Extraction échouée
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

      {bundle && <M1ResultsView bundle={bundle} jobId={jobId!} />}
    </motion.section>
  );
}
