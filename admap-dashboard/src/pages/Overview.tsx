/**
 * Page Overview — tableau de bord agrégé de toutes les analyses persistées
 * (historique localStorage). KPI, graphes recharts et dernières analyses.
 * État vide propre tant qu'aucune analyse n'a été enregistrée.
 */
import { useMemo } from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { LayoutDashboard } from "lucide-react";

import { useAdmapStore } from "@/store";
import { buildOverviewData } from "@/lib/overview-stats";
import { fadeInUp } from "@/lib/motion";
import { Button } from "@/components/ui/button";
import {
  OverviewAptBars,
  OverviewIocDonut,
  OverviewKPIs,
  OverviewMitreBars,
  OverviewModuleBars,
  OverviewRecent,
  OverviewSeverityDonut,
  OverviewTimeline,
} from "@/components/overview";

function EmptyState() {
  return (
    <section className="flex flex-col items-center justify-center gap-4 py-24 text-center">
      <LayoutDashboard className="h-12 w-12 text-muted-foreground" />
      <div>
        <h1 className="text-xl font-bold text-white">Aucune analyse enregistrée</h1>
        <p className="mt-1 text-slate-400">
          Lancez une analyse depuis un module ou le pipeline complet : les
          statistiques agrégées apparaîtront ici.
        </p>
      </div>
      <div className="flex flex-wrap justify-center gap-2">
        <Button asChild>
          <Link to="/pipeline">Lancer le pipeline</Link>
        </Button>
        <Button asChild variant="outline">
          <Link to="/m1">Analyser un fichier (M1)</Link>
        </Button>
      </div>
    </section>
  );
}

export function Overview() {
  const history = useAdmapStore((s) => s.analysisHistory);
  const data = useMemo(() => buildOverviewData(history), [history]);

  if (history.length === 0) return <EmptyState />;

  return (
    <motion.section
      className="flex flex-col gap-6"
      variants={fadeInUp}
      initial="hidden"
      animate="visible"
    >
      <header>
        <h1 className="text-2xl font-bold text-white">Overview</h1>
        <p className="mt-1 text-slate-400">
          Synthèse de {history.length} analyse(s) enregistrée(s).
        </p>
      </header>

      <OverviewKPIs kpis={data.kpis} />

      <div className="grid gap-6 lg:grid-cols-2">
        <OverviewModuleBars data={data.moduleBars} />
        <OverviewTimeline data={data.timeline} />
        <OverviewSeverityDonut data={data.severity} />
        <OverviewIocDonut data={data.iocTypes} />
        <OverviewMitreBars data={data.mitre} />
        <OverviewAptBars data={data.apt} />
      </div>

      <OverviewRecent records={history} />
    </motion.section>
  );
}
