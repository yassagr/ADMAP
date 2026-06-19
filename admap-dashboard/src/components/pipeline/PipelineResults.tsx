/**
 * Résultats agrégés du pipeline.
 *
 * Une section repliable par étape terminée (M1 récap, M2 vue complète réutilisée,
 * M3 récap, M4 vue complète réutilisée), puis le VERDICT M5 mis en évidence comme
 * point culminant (attribution APT), et enfin le panneau d'export consolidé.
 */
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { Download, FileText, Loader2 } from "lucide-react";

import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useExport } from "@/hooks/useExport";
import { exportM1 } from "@/api/m1";
import { exportM2 } from "@/api/m2";
import { exportM3 } from "@/api/m3";
import { exportM4 } from "@/api/m4";
import { exportM5 } from "@/api/m5";
import { fadeInUp } from "@/lib/motion";
import { M2ResultsView } from "@/components/m2";
import { M4ResultsView } from "@/components/m4";
import { M5Verdict } from "@/components/m5";
import type { IOCBundle, YaraRuleSet } from "@/types";
import type { PipelineResults as PipelineResultsData, PipelineStepMap } from "@/hooks/usePipeline";

/** Récapitulatif compact M1 : nombre d'IOC par type. */
function M1Recap({ bundle }: { bundle: IOCBundle }) {
  const { total_iocs, by_type } = bundle.analysis_stats;
  const entries = Object.entries(by_type).filter(([, n]) => n > 0);
  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm text-muted-foreground">
        <span className="font-mono text-lg text-foreground">{total_iocs}</span>{" "}
        IOC extraits depuis{" "}
        <span className="font-mono">{bundle.metadata.filename}</span>
      </p>
      <div className="flex flex-wrap gap-2">
        {entries.length > 0 ? (
          entries.map(([type, count]) => (
            <span
              key={type}
              className="rounded-md border border-border px-2 py-1 text-xs"
            >
              {type} · <span className="font-mono text-primary">{count}</span>
            </span>
          ))
        ) : (
          <span className="text-sm text-muted-foreground">Aucun IOC.</span>
        )}
      </div>
    </div>
  );
}

/** Récapitulatif compact M3 : règles YARA générées. */
function M3Recap({ ruleset }: { ruleset: YaraRuleSet }) {
  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm text-muted-foreground">
        <span className="font-mono text-lg text-foreground">
          {ruleset.total_rules}
        </span>{" "}
        règle(s) — {ruleset.compiled_rules} compilée(s), {ruleset.failed_rules}{" "}
        en échec
      </p>
      <ul className="flex flex-col gap-1">
        {ruleset.rules.map((rule) => (
          <li key={rule.rule_id} className="font-mono text-sm text-foreground">
            {rule.rule_name}
            <span className="ml-2 text-xs text-muted-foreground">
              conf. {Math.round(rule.confidence_score)}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Panneau d'export consolidé du pipeline. */
function PipelineExport({
  results,
  steps,
}: {
  results: PipelineResultsData;
  steps: PipelineStepMap;
}) {
  const { download, isExporting } = useExport();
  const navigate = useNavigate();
  const [active, setActive] = useState<string | null>(null);

  // Le rapport est disponible dès qu'une étape est terminée et qu'aucune ne
  // tourne encore (le run est alors persisté dans le store par la page Pipeline).
  const isRunning = Object.values(steps).some((s) => s.status === "running");
  const reportReady =
    !isRunning &&
    Boolean(results.m1 || results.m2 || results.m3 || results.m4 || results.m5);

  const stixTargets: { id: string; label: string; run: () => Promise<Blob> }[] = [];
  if (results.m1 && steps.m1.jobId)
    stixTargets.push({
      id: "m1",
      label: "M1",
      run: () => exportM1(steps.m1.jobId as string, "stix21"),
    });
  if (results.m2 && steps.m2.jobId)
    stixTargets.push({
      id: "m2",
      label: "M2",
      run: () => exportM2(steps.m2.jobId as string, "stix"),
    });
  if (results.m3 && steps.m3.jobId)
    stixTargets.push({
      id: "m3",
      label: "M3",
      run: () => exportM3(steps.m3.jobId as string, "stix"),
    });
  if (results.m4 && steps.m4.jobId)
    stixTargets.push({
      id: "m4",
      label: "M4",
      run: () => exportM4(steps.m4.jobId as string, "stix"),
    });
  if (results.m5 && steps.m5.jobId)
    stixTargets.push({
      id: "m5",
      label: "M5",
      run: () => exportM5(steps.m5.jobId as string, "stix"),
    });

  const handle = async (
    key: string,
    fetcher: () => Promise<Blob>,
    filename: string,
  ): Promise<void> => {
    setActive(key);
    await download(fetcher, filename);
    setActive(null);
  };

  const fullJson = (): Promise<Blob> =>
    Promise.resolve(
      new Blob([JSON.stringify(results, null, 2)], { type: "application/json" }),
    );

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Export du pipeline</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="flex flex-col gap-2">
          <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            Résultat complet
          </span>
          <div className="flex flex-wrap gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={isExporting}
              onClick={() =>
                void handle("full", fullJson, "admap-pipeline.json")
              }
            >
              {active === "full" ? (
                <Loader2 className="animate-spin" />
              ) : (
                <Download />
              )}
              Résultat complet (JSON)
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={!reportReady}
              title={
                reportReady
                  ? "Ouvrir le rapport imprimable"
                  : "Disponible une fois le pipeline terminé"
              }
              onClick={() => navigate("/report")}
            >
              <FileText />
              Rapport PDF
            </Button>
          </div>
        </div>

        {stixTargets.length > 0 && (
          <div className="flex flex-col gap-2">
            <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              STIX par module
            </span>
            <div className="flex flex-wrap gap-2">
              {stixTargets.map(({ id, label, run }) => (
                <Button
                  key={id}
                  variant="outline"
                  size="sm"
                  disabled={isExporting}
                  onClick={() =>
                    void handle(id, run, `admap-${id}.stix.json`)
                  }
                >
                  {active === id ? (
                    <Loader2 className="animate-spin" />
                  ) : (
                    <Download />
                  )}
                  {label}
                </Button>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export interface PipelineResultsProps {
  results: PipelineResultsData;
  steps: PipelineStepMap;
}

export function PipelineResults({ results, steps }: PipelineResultsProps) {
  const sections: string[] = [];
  if (results.m1) sections.push("m1");
  if (results.m2) sections.push("m2");
  if (results.m3) sections.push("m3");
  if (results.m4) sections.push("m4");

  const hasAny =
    results.m1 || results.m2 || results.m3 || results.m4 || results.m5;
  if (!hasAny) return null;

  return (
    <motion.div
      className="flex flex-col gap-6"
      variants={fadeInUp}
      initial="hidden"
      animate="visible"
    >
      {sections.length > 0 && (
        <Accordion type="multiple" defaultValue={sections} className="w-full">
          {results.m1 && (
            <AccordionItem value="m1">
              <AccordionTrigger>M1 · IOC Extractor</AccordionTrigger>
              <AccordionContent>
                <M1Recap bundle={results.m1} />
              </AccordionContent>
            </AccordionItem>
          )}
          {results.m2 && steps.m2.jobId && (
            <AccordionItem value="m2">
              <AccordionTrigger>M2 · C2 Detector</AccordionTrigger>
              <AccordionContent>
                <M2ResultsView bundle={results.m2} jobId={steps.m2.jobId} />
              </AccordionContent>
            </AccordionItem>
          )}
          {results.m3 && (
            <AccordionItem value="m3">
              <AccordionTrigger>M3 · YARA Generator</AccordionTrigger>
              <AccordionContent>
                <M3Recap ruleset={results.m3} />
              </AccordionContent>
            </AccordionItem>
          )}
          {results.m4 && steps.m4.jobId && (
            <AccordionItem value="m4">
              <AccordionTrigger>M4 · APT Mapper</AccordionTrigger>
              <AccordionContent>
                <M4ResultsView report={results.m4} jobId={steps.m4.jobId} />
              </AccordionContent>
            </AccordionItem>
          )}
        </Accordion>
      )}

      {results.m5 && <M5Verdict report={results.m5} />}

      <PipelineExport results={results} steps={steps} />
    </motion.div>
  );
}
