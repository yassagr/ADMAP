/**
 * Vue résultats M2 : compose le bandeau de sévérité, le donut de types, le
 * graphe réseau, la table d'alertes, les IPs suspectes et le panneau d'export.
 * Détient l'état de filtre partagé (sévérité + IP sélectionnée). Le filtre par
 * type est local à la table.
 */
import { useMemo, useState } from "react";
import { motion } from "framer-motion";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ExportPanel } from "@/components/shared";
import { exportM2 } from "@/api/m2";
import { fadeInUp } from "@/lib/motion";
import type { AlertBundle, AlertSeverity, ExportFormat } from "@/types";

import { M2AlertSummary } from "./M2AlertSummary";
import { M2AlertTable } from "./M2AlertTable";
import { M2NetworkGraph } from "./M2NetworkGraph";
import { M2TypeDonut } from "./M2TypeDonut";

export interface M2ResultsViewProps {
  bundle: AlertBundle;
  jobId: string;
}

export function M2ResultsView({ bundle, jobId }: M2ResultsViewProps) {
  const [severity, setSeverity] = useState<AlertSeverity | null>(null);
  const [ip, setIp] = useState<string | null>(null);

  const filteredAlerts = useMemo(() => {
    return bundle.alerts.filter((a) => {
      if (severity && a.severity !== severity) return false;
      if (ip && a.src_ip !== ip && a.dst_ip !== ip) return false;
      return true;
    });
  }, [bundle.alerts, severity, ip]);

  return (
    <motion.div
      className="flex flex-col gap-6"
      variants={fadeInUp}
      initial="hidden"
      animate="visible"
    >
      <M2AlertSummary
        bundle={bundle}
        activeSeverity={severity}
        onSelectSeverity={setSeverity}
      />

      <div className="grid gap-6 lg:grid-cols-2">
        <M2TypeDonut bundle={bundle} />
        <M2NetworkGraph bundle={bundle} selectedIp={ip} onSelectIp={setIp} />
      </div>

      <Card>
        <CardHeader className="flex-row items-center justify-between space-y-0">
          <CardTitle className="text-base">
            Alertes ({filteredAlerts.length}/{bundle.alerts.length})
          </CardTitle>
          {(severity || ip) && (
            <button
              type="button"
              onClick={() => {
                setSeverity(null);
                setIp(null);
              }}
              className="text-xs text-primary hover:underline"
            >
              Réinitialiser les filtres
            </button>
          )}
        </CardHeader>
        <CardContent>
          <M2AlertTable alerts={filteredAlerts} />
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">IPs les plus suspectes</CardTitle>
          </CardHeader>
          <CardContent>
            {bundle.top_suspicious_ips.length > 0 ? (
              <ul className="flex flex-col gap-1">
                {bundle.top_suspicious_ips.map((suspectIp) => (
                  <li key={suspectIp}>
                    <button
                      type="button"
                      onClick={() => setIp(suspectIp === ip ? null : suspectIp)}
                      className="font-mono text-sm text-foreground hover:text-primary"
                    >
                      {suspectIp}
                    </button>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted-foreground">Aucune.</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Export CTI</CardTitle>
          </CardHeader>
          <CardContent>
            <ExportPanel
              formats={["json", "csv", "stix", "all"]}
              fetchExport={(format) => exportM2(jobId, format as ExportFormat)}
              filenameBase={`admap-m2-${bundle.bundle_id}`}
              title=""
            />
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
