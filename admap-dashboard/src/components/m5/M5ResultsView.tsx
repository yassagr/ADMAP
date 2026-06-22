/**
 * Vue résultats M5 : verdict d'attribution mis en avant (`M5Verdict`,
 * `top_global_candidate` + ScoreGauge), puis résultats détaillés par cluster et
 * panneau d'export. Calquée sur `M4ResultsView`.
 */
import { motion } from "framer-motion";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ExportPanel, ReportButton } from "@/components/shared";
import { exportM5 } from "@/api/m5";
import { fadeInUp } from "@/lib/motion";
import type { AttributionReport, ExportFormat } from "@/types";

import { M5ClusterResults } from "./M5ClusterResults";
import { M5Verdict } from "./M5Verdict";

export interface M5ResultsViewProps {
  report: AttributionReport;
  jobId: string;
  /** Identifiant de l'analyse enregistrée — active le bouton « Générer le rapport ». */
  reportRecordId?: string | null;
}

export function M5ResultsView({ report, jobId, reportRecordId }: M5ResultsViewProps) {
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

      <M5Verdict report={report} />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            Attribution par cluster ({report.results.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          <M5ClusterResults results={report.results} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Export CTI</CardTitle>
        </CardHeader>
        <CardContent>
          <ExportPanel
            formats={["json", "csv", "stix", "all"]}
            fetchExport={(format) => exportM5(jobId, format as ExportFormat)}
            filenameBase={`admap-m5-${report.report_id}`}
            title=""
          />
        </CardContent>
      </Card>
    </motion.div>
  );
}
