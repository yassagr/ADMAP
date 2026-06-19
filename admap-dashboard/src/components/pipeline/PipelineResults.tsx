/**
 * Résultats agrégés du pipeline.
 *
 * Une section repliable par étape terminée (M1 récap, M2 vue complète réutilisée,
 * M3 récap, M4 vue complète réutilisée), puis le VERDICT M5 mis en évidence comme
 * point culminant (attribution APT), et enfin le panneau d'export consolidé.
 */
import { useState } from "react";
import { motion } from "framer-motion";
import { Download, FileText, Loader2, Trophy } from "lucide-react";

import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScoreGauge } from "@/components/shared";
import { useExport } from "@/hooks/useExport";
import { exportM1 } from "@/api/m1";
import { exportM2 } from "@/api/m2";
import { exportM3 } from "@/api/m3";
import { exportM4 } from "@/api/m4";
import { exportM5 } from "@/api/m5";
import { fadeInUp } from "@/lib/motion";
import { M2ResultsView } from "@/components/m2";
import { M4ResultsView } from "@/components/m4";
import type {
  APTCandidate,
  AttributionReport,
  IOCBundle,
  YaraRuleSet,
} from "@/types";
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

/** Carte d'un candidat APT classé. */
function CandidateCard({ candidate }: { candidate: APTCandidate }) {
  return (
    <div className="flex flex-col gap-2 rounded-lg border border-border p-4">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="flex h-6 w-6 items-center justify-center rounded-full bg-primary/15 text-xs font-bold text-primary">
            {candidate.rank}
          </span>
          <a
            href={candidate.mitre_group_url}
            target="_blank"
            rel="noreferrer"
            className="font-semibold text-foreground hover:text-primary hover:underline"
          >
            {candidate.apt_name}
          </a>
          <span className="font-mono text-xs text-muted-foreground">
            {candidate.apt_id}
          </span>
        </div>
        <span className="font-mono text-sm font-bold text-primary">
          {Math.round(candidate.confidence_score)}
        </span>
      </div>

      <div className="grid grid-cols-2 gap-2 text-xs text-muted-foreground">
        <span>
          XGBoost :{" "}
          <span className="font-mono text-foreground">
            {(candidate.xgb_probability * 100).toFixed(1)}%
          </span>
        </span>
        <span>
          Cosine :{" "}
          <span className="font-mono text-foreground">
            {(candidate.cosine_similarity * 100).toFixed(1)}%
          </span>
        </span>
      </div>

      {candidate.matched_techniques.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {candidate.matched_techniques.slice(0, 8).map((t) => (
            <span
              key={t}
              className="rounded border border-border px-1.5 py-0.5 text-[10px] font-mono"
            >
              {t}
            </span>
          ))}
          {candidate.matched_techniques.length > 8 && (
            <span className="text-[10px] text-muted-foreground">
              +{candidate.matched_techniques.length - 8}
            </span>
          )}
        </div>
      )}

      {candidate.matched_tactics.length > 0 && (
        <p className="text-xs text-muted-foreground">
          Tactiques : {candidate.matched_tactics.join(", ")}
        </p>
      )}

      {candidate.evidence_summary && (
        <p className="text-xs text-slate-400">{candidate.evidence_summary}</p>
      )}
    </div>
  );
}

/** Verdict M5 — point culminant du pipeline. */
function PipelineVerdict({ report }: { report: AttributionReport }) {
  const top = report.top_global_candidate;
  const ranked = report.results
    .flatMap((r) => r.candidates)
    .sort((a, b) => b.confidence_score - a.confidence_score)
    .slice(0, 5);

  return (
    <Card
      style={{
        borderColor: "rgba(0, 212, 255, 0.55)",
        backgroundColor: "rgba(0, 212, 255, 0.05)",
      }}
    >
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-lg">
          <Trophy className="h-5 w-5 text-primary" />
          Verdict d'attribution APT (M5)
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-6">
        {top ? (
          <div className="flex flex-col items-center gap-4 sm:flex-row sm:items-center">
            <ScoreGauge value={top.confidence_score} label="confiance" size={132} />
            <div className="flex flex-1 flex-col gap-2 text-center sm:text-left">
              <div>
                <p className="text-xs uppercase tracking-wide text-muted-foreground">
                  Acteur le plus probable
                </p>
                <a
                  href={top.mitre_group_url}
                  target="_blank"
                  rel="noreferrer"
                  className="text-2xl font-bold text-white hover:text-primary hover:underline"
                >
                  {top.apt_name}
                </a>
                <span className="ml-2 font-mono text-sm text-muted-foreground">
                  {top.apt_id}
                </span>
              </div>
              <div className="flex flex-wrap justify-center gap-4 text-sm sm:justify-start">
                <span className="text-muted-foreground">
                  XGBoost :{" "}
                  <span className="font-mono text-foreground">
                    {(top.xgb_probability * 100).toFixed(1)}%
                  </span>
                </span>
                <span className="text-muted-foreground">
                  Cosine :{" "}
                  <span className="font-mono text-foreground">
                    {(top.cosine_similarity * 100).toFixed(1)}%
                  </span>
                </span>
                <span className="text-muted-foreground">
                  Techniques :{" "}
                  <span className="font-mono text-foreground">
                    {top.matched_techniques.length}
                  </span>
                </span>
              </div>
              {top.evidence_summary && (
                <p className="text-sm text-slate-400">{top.evidence_summary}</p>
              )}
            </div>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">
            Aucun candidat global retenu (clusters insuffisants ou bruit).
          </p>
        )}

        {ranked.length > 0 && (
          <div className="flex flex-col gap-3">
            <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Top {ranked.length} candidats
            </p>
            <div className="grid gap-3 md:grid-cols-2">
              {ranked.map((c) => (
                <CandidateCard key={`${c.apt_id}-${c.rank}`} candidate={c} />
              ))}
            </div>
          </div>
        )}

        <p className="text-xs text-muted-foreground">
          {report.total_clusters_analyzed} cluster(s) analysé(s),{" "}
          {report.noise_clusters_skipped} ignoré(s) (bruit).
        </p>
      </CardContent>
    </Card>
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
  const [active, setActive] = useState<string | null>(null);

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
            <Button variant="outline" size="sm" disabled title="à venir">
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

      {results.m5 && <PipelineVerdict report={results.m5} />}

      <PipelineExport results={results} steps={steps} />
    </motion.div>
  );
}
