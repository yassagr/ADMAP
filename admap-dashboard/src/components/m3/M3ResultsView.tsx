/**
 * Vue résultats M3 : bandeau récapitulatif (règles totales / compilées / en
 * échec), barres de scores discriminants, liste repliable des règles YARA et
 * panneau d'export. Calquée sur `M2ResultsView`.
 */
import { motion } from "framer-motion";
import { CheckCircle2, ScanLine, XCircle } from "lucide-react";
import type { LucideIcon } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ExportPanel, ReportButton } from "@/components/shared";
import { exportM3, type M3ExportFormat } from "@/api/m3";
import { fadeInUp } from "@/lib/motion";
import type { YaraRuleSet } from "@/types";

import { M3RulesList } from "./M3RulesList";
import { M3ScoreBars } from "./M3ScoreBars";

export interface M3ResultsViewProps {
  ruleset: YaraRuleSet;
  jobId: string;
  /** Identifiant de l'analyse enregistrée — active le bouton « Générer le rapport ». */
  reportRecordId?: string | null;
}

/** Formats réellement exposés par l'API M3 (`yar` en plus du commun). */
const M3_FORMATS: readonly M3ExportFormat[] = ["yar", "json", "stix", "csv", "all"];

interface StatCard {
  key: string;
  label: string;
  value: number;
  icon: LucideIcon;
  color: string;
}

export function M3ResultsView({ ruleset, jobId, reportRecordId }: M3ResultsViewProps) {
  const cards: StatCard[] = [
    {
      key: "total",
      label: "Règles",
      value: ruleset.total_rules,
      icon: ScanLine,
      color: "#00d4ff",
    },
    {
      key: "compiled",
      label: "Compilées",
      value: ruleset.compiled_rules,
      icon: CheckCircle2,
      color: "#6ee7b7",
    },
    {
      key: "failed",
      label: "En échec",
      value: ruleset.failed_rules,
      icon: XCircle,
      color: "#ff8aa0",
    },
  ];

  return (
    <motion.div
      className="flex flex-col gap-6"
      variants={fadeInUp}
      initial="hidden"
      animate="visible"
    >
      <div className="flex justify-end">
        <ReportButton recordId={reportRecordId} />
      </div>

      <div className="flex flex-wrap items-center gap-3">
        {cards.map((card) => {
          const Icon = card.icon;
          return (
            <div
              key={card.key}
              className="flex items-center gap-3 rounded-lg border border-border px-4 py-2"
              style={{ backgroundColor: "var(--bg-secondary)" }}
            >
              <Icon className="h-5 w-5" style={{ color: card.color }} />
              <div className="flex flex-col items-start leading-tight">
                <span className="text-xs uppercase tracking-wide text-muted-foreground">
                  {card.label}
                </span>
                <span className="text-lg font-bold text-foreground">
                  {card.value}
                </span>
              </div>
            </div>
          );
        })}
        <span className="text-xs text-muted-foreground">
          Corpus {ruleset.corpus_id} · {ruleset.generation_duration_ms} ms
        </span>
      </div>

      <M3ScoreBars ruleset={ruleset} />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Règles YARA générées</CardTitle>
        </CardHeader>
        <CardContent>
          <M3RulesList rules={ruleset.rules} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Export CTI</CardTitle>
        </CardHeader>
        <CardContent>
          <ExportPanel
            formats={[...M3_FORMATS]}
            fetchExport={(format) => exportM3(jobId, format as M3ExportFormat)}
            filenameBase={`admap-m3-${ruleset.ruleset_id}`}
            title=""
          />
        </CardContent>
      </Card>
    </motion.div>
  );
}
