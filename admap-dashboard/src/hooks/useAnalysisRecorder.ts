/**
 * Enregistre une analyse terminée dans l'historique persisté, une seule fois
 * par job. À monter dans une page module : dès que `result` devient disponible
 * pour un `jobId` non encore enregistré, crée un `AnalysisRecord` et renvoie son
 * identifiant (utilisé pour le bouton « Générer le rapport »).
 */
import { useEffect, useRef, useState } from "react";

import { useAdmapStore } from "@/store";
import type { AnalysisModule, AnalysisSummary } from "@/types";

export function useAnalysisRecorder<T>(
  module: AnalysisModule,
  jobId: string | null,
  result: T | null,
  build: (result: T) => { inputName: string; summary: AnalysisSummary },
): string | null {
  const addAnalysisRecord = useAdmapStore((s) => s.addAnalysisRecord);
  const [recordId, setRecordId] = useState<string | null>(null);
  const recordedJobRef = useRef<string | null>(null);

  useEffect(() => {
    if (!result || !jobId || recordedJobRef.current === jobId) return;
    recordedJobRef.current = jobId;
    const id = crypto.randomUUID();
    const { inputName, summary } = build(result);
    addAnalysisRecord({
      id,
      module,
      createdAt: new Date().toISOString(),
      inputName,
      summary,
      result,
    });
    setRecordId(id);
    // `build` est volontairement hors deps : sa réévaluation à chaque rendu
    // est neutralisée par le garde `recordedJobRef` (un seul enregistrement/job).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [result, jobId, module, addAnalysisRecord]);

  return recordId;
}
