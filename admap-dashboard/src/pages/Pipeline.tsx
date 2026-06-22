/**
 * Page Pipeline — orchestration complète M1→M2→M3→M4→M5.
 *
 * Page centrale de la démo : enchaîne les 5 microservices via `usePipeline`,
 * anime le flux de données entre étapes (`PipelineFlow`), puis agrège les
 * résultats en se terminant sur le verdict d'attribution APT (M5). Gère l'état
 * hors-ligne des modules, l'échec partiel (retry) et les toasts.
 */
import { useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import { AlertTriangle, RotateCcw } from "lucide-react";

import { useAdmapStore } from "@/store";
import { usePipeline, type PipelineInputs } from "@/hooks/usePipeline";
import { summarizePipeline } from "@/lib/analysis-summary";
import { fadeInUp } from "@/lib/motion";
import { useToast } from "@/components/shared";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  PipelineFlow,
  PipelineForm,
  PipelineResults,
} from "@/components/pipeline";
import { MODULE_IDS } from "@/types";
import type { ModuleId } from "@/types";

export function Pipeline() {
  const { toast } = useToast();
  const moduleStatus = useAdmapStore((s) => s.moduleStatus);
  const setLastPipelineRun = useAdmapStore((s) => s.setLastPipelineRun);
  const addAnalysisRecord = useAdmapStore((s) => s.addAnalysisRecord);
  const { steps, results, isRunning, error, run, reset } = usePipeline();

  const [lastInputs, setLastInputs] = useState<PipelineInputs | null>(null);
  const prevRunningRef = useRef(false);

  const offlineModules: ModuleId[] = MODULE_IDS.filter(
    (id) => moduleStatus[id].status !== "ok",
  );

  // Toasts de fin de pipeline (transition running → arrêt) + persistance du run.
  useEffect(() => {
    if (prevRunningRef.current && !isRunning) {
      if (error) {
        toast({
          variant: "error",
          title: "Pipeline interrompu",
          description: error,
        });
      } else if (results.m5) {
        const apt = results.m5.top_global_candidate?.apt_name;
        toast({
          variant: "success",
          title: "Pipeline terminé",
          description: apt
            ? `Attribution APT : ${apt}`
            : "Aucun acteur APT retenu.",
        });
      }

      // Persiste le dernier run (même partiel) pour la page Rapport (/report)
      // et l'ajoute à l'historique agrégé (Overview / History).
      const hasResults =
        results.m1 || results.m2 || results.m3 || results.m4 || results.m5;
      if (hasResults && lastInputs) {
        const createdAt = new Date().toISOString();
        const snapshot = { ...results };
        setLastPipelineRun({
          runId: crypto.randomUUID(),
          createdAt,
          meta: {
            pcapName: lastInputs.pcap.name,
            suspectFileName: lastInputs.suspectFile?.name,
            corpusMalwareCount: lastInputs.corpusMalware?.length ?? 0,
            corpusBenignCount: lastInputs.corpusBenign?.length ?? 0,
          },
          results: snapshot,
        });
        addAnalysisRecord({
          id: crypto.randomUUID(),
          module: "PIPELINE",
          createdAt,
          inputName: lastInputs.pcap.name,
          summary: summarizePipeline(snapshot),
          result: snapshot,
        });
      }
    }
    prevRunningRef.current = isRunning;
  }, [isRunning, error, results, toast, lastInputs, setLastPipelineRun, addAnalysisRecord]);

  const handleSubmit = (inputs: PipelineInputs): void => {
    setLastInputs(inputs);
    void run(inputs);
  };

  const retry = (): void => {
    if (lastInputs) void run(lastInputs);
  };

  return (
    <motion.section
      className="flex flex-col gap-6"
      variants={fadeInUp}
      initial="hidden"
      animate="visible"
    >
      <header>
        <h1 className="text-2xl font-bold text-white">Pipeline ADMAP</h1>
        <p className="mt-1 text-slate-400">
          Orchestration complète : extraction d'IOC (M1), détection C2 (M2),
          génération YARA (M3), clustering APT (M4) et attribution (M5).
        </p>
      </header>

      {offlineModules.length > 0 && (
        <div
          className="flex items-center gap-2 rounded-lg border px-4 py-3 text-sm"
          style={{
            borderColor: "rgba(245, 158, 11, 0.5)",
            backgroundColor: "rgba(245, 158, 11, 0.08)",
            color: "#fcd34d",
          }}
        >
          <AlertTriangle className="h-4 w-4 shrink-0" />
          Module(s) injoignable(s) :{" "}
          {offlineModules.map((m) => m.toUpperCase()).join(", ")}. Vous pouvez
          préparer le pipeline, mais les étapes concernées échoueront tant que
          les services sont hors ligne.
        </div>
      )}

      <PipelineForm onSubmit={handleSubmit} disabled={isRunning} />

      <PipelineFlow steps={steps} isRunning={isRunning} />

      {error && (
        <Card style={{ borderColor: "rgba(255, 45, 85, 0.5)" }}>
          <CardHeader className="flex-row items-center justify-between space-y-0">
            <CardTitle className="flex items-center gap-2 text-base text-destructive">
              <AlertTriangle className="h-5 w-5" />
              Pipeline interrompu
            </CardTitle>
            <Button
              variant="outline"
              size="sm"
              onClick={retry}
              disabled={isRunning || !lastInputs}
            >
              <RotateCcw className="h-4 w-4" />
              Réessayer
            </Button>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">{error}</p>
            <p className="mt-1 text-xs text-muted-foreground">
              Les résultats des étapes déjà terminées sont conservés ci-dessous.
            </p>
          </CardContent>
        </Card>
      )}

      <PipelineResults results={results} steps={steps} />

      {(error || results.m5) && !isRunning && (
        <div>
          <Button variant="ghost" size="sm" onClick={reset}>
            Réinitialiser le pipeline
          </Button>
        </div>
      )}
    </motion.section>
  );
}
