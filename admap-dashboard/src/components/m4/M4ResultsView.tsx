/**
 * Vue résultats M4 : compose le bandeau récapitulatif, le graphe de campagnes
 * (viz centrale), les analyses MITRE (couverture, top techniques, top tactiques),
 * la table des clusters et le panneau d'export. Détient l'état de filtre partagé
 * (cluster sélectionné), piloté par le graphe et réinitialisé par le bandeau.
 */
import { useMemo, useState } from "react";
import { motion } from "framer-motion";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ExportPanel, ReportButton } from "@/components/shared";
import { exportM4 } from "@/api/m4";
import { fadeInUp } from "@/lib/motion";
import type { APTMapReport, ExportFormat } from "@/types";

import { M4CampaignGraph } from "./M4CampaignGraph";
import { M4CampaignSummary } from "./M4CampaignSummary";
import { M4ClusterTable } from "./M4ClusterTable";
import { M4MitreCoverage } from "./M4MitreCoverage";
import { M4TacticDonut } from "./M4TacticDonut";
import { M4TopTechniques } from "./M4TopTechniques";

export interface M4ResultsViewProps {
  report: APTMapReport;
  jobId: string;
  /** Identifiant de l'analyse enregistrée — active le bouton « Générer le rapport ». */
  reportRecordId?: string | null;
}

export function M4ResultsView({ report, jobId, reportRecordId }: M4ResultsViewProps) {
  const [selectedClusterId, setSelectedClusterId] = useState<string | null>(null);

  const clusters = report.cluster_bundle.clusters;
  const filteredClusters = useMemo(
    () =>
      selectedClusterId
        ? clusters.filter((c) => c.cluster_id === selectedClusterId)
        : clusters,
    [clusters, selectedClusterId],
  );

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

      <M4CampaignSummary
        report={report}
        selectedClusterId={selectedClusterId}
        onClear={() => setSelectedClusterId(null)}
      />

      <M4CampaignGraph
        report={report}
        selectedClusterId={selectedClusterId}
        onSelectCluster={setSelectedClusterId}
      />

      <div className="grid gap-6 lg:grid-cols-2">
        <M4MitreCoverage report={report} />
        <M4TacticDonut report={report} />
      </div>

      <M4TopTechniques report={report} />

      <Card>
        <CardHeader className="flex-row items-center justify-between space-y-0">
          <CardTitle className="text-base">
            Clusters ({filteredClusters.length}/{clusters.length})
          </CardTitle>
          {selectedClusterId && (
            <button
              type="button"
              onClick={() => setSelectedClusterId(null)}
              className="text-xs text-primary hover:underline"
            >
              Réinitialiser le filtre
            </button>
          )}
        </CardHeader>
        <CardContent>
          <M4ClusterTable clusters={filteredClusters} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Export CTI</CardTitle>
        </CardHeader>
        <CardContent>
          <ExportPanel
            formats={["json", "csv", "stix", "all"]}
            fetchExport={(format) => exportM4(jobId, format as ExportFormat)}
            filenameBase={`admap-m4-${report.report_id}`}
            title=""
          />
        </CardContent>
      </Card>
    </motion.div>
  );
}
