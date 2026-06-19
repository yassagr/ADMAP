/**
 * Page M4 — APT Mapper / Clustering. Calquée sur la page M2.
 *
 * Orchestration : soumission d'un AlertBundle M2 (+ entrées optionnelles) →
 * suivi temps réel (WebSocket + fallback HTTP via `useJobPolling`) → résultats
 * (graphe de campagnes, analyses MITRE, table de clusters, export). Gère l'état
 * hors-ligne du module, l'échec de job (retry) et les erreurs réseau.
 */
import { useState } from "react";
import { motion } from "framer-motion";
import { AlertTriangle, RotateCcw } from "lucide-react";

import { analyzeM4, type M4AnalyzeExtras } from "@/api/m4";
import { useJobPolling } from "@/hooks/useJobPolling";
import { useAdmapStore } from "@/store";
import { fadeInUp } from "@/lib/motion";
import { AIPhaseSlot, JobStatusBadge, JsonViewer, useToast } from "@/components/shared";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { M4ProgressPanel, M4ResultsView, M4SubmitForm } from "@/components/m4";
import type { APTMapReport } from "@/types";

interface Submission {
  file: File;
  extras: M4AnalyzeExtras;
}

export function M4() {
  const { toast } = useToast();
  const moduleStatus = useAdmapStore((s) => s.moduleStatus.m4);

  const [submission, setSubmission] = useState<Submission | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const { status, progress, job, result } = useJobPolling(
    jobId,
    jobId ? "m4" : null,
  );

  const runAnalysis = async (
    file: File,
    extras: M4AnalyzeExtras,
  ): Promise<void> => {
    setIsSubmitting(true);
    setJobId(null);
    try {
      const res = await analyzeM4(file, extras);
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
  const report = status === "completed" ? (result as APTMapReport | null) : null;
  const offline = moduleStatus.status !== "ok";

  return (
    <motion.section
      className="flex flex-col gap-6"
      variants={fadeInUp}
      initial="hidden"
      animate="visible"
    >
      <header>
        <h1 className="text-2xl font-bold text-white">M4 · APT Mapper</h1>
        <p className="mt-1 text-slate-400">
          Clustering DBSCAN de profils d'attaque (AlertBundle M2) en campagnes APT,
          cartographie MITRE ATT&CK.
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
          Module M4 injoignable ({moduleStatus.status}). Vous pouvez préparer une
          analyse, mais la soumission échouera tant que le service est hors ligne.
        </div>
      )}

      <M4SubmitForm
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
          <M4ProgressPanel
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

      {report && <M4ResultsView report={report} jobId={jobId!} />}

      <AIPhaseSlot
        title="M4-IA · Clustering DBSCAN (Phase 2)"
        description="Regroupement non supervisé des profils d'attaque en campagnes APT, enrichi par auto-tuning epsilon et scoring de cohésion. Bientôt disponible."
      >
        <div className="flex gap-2 text-sm">
          <span className="rounded border border-border px-2 py-1">DBSCAN</span>
          <span className="rounded border border-border px-2 py-1">Auto-epsilon</span>
        </div>
      </AIPhaseSlot>
    </motion.section>
  );
}
