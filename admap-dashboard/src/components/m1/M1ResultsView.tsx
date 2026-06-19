/**
 * Vue résultats M1 : compose le bandeau récapitulatif (métadonnées + stats), le
 * donut de types, les barres par catégorie, les tables d'IOC groupées et le
 * panneau d'export CTI. Calquée sur `M2ResultsView`.
 */
import { motion } from "framer-motion";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ExportPanel } from "@/components/shared";
import { exportM1, type M1ExportFormat } from "@/api/m1";
import { fadeInUp } from "@/lib/motion";
import type { IOCBundle } from "@/types";

import { M1CategoryBars } from "./M1CategoryBars";
import { M1IocTables } from "./M1IocTables";
import { M1Summary } from "./M1Summary";
import { M1TypeDonut } from "./M1TypeDonut";

export interface M1ResultsViewProps {
  bundle: IOCBundle;
  jobId: string;
}

/** Formats CTI réellement exposés par l'API M1 (cf. `M1ExportFormat`). */
const M1_FORMATS: readonly M1ExportFormat[] = [
  "stix21",
  "openioc",
  "misp",
  "cytomic",
];

export function M1ResultsView({ bundle, jobId }: M1ResultsViewProps) {
  return (
    <motion.div
      className="flex flex-col gap-6"
      variants={fadeInUp}
      initial="hidden"
      animate="visible"
    >
      <M1Summary bundle={bundle} />

      <div className="grid gap-6 lg:grid-cols-2">
        <M1TypeDonut bundle={bundle} />
        <M1CategoryBars bundle={bundle} />
      </div>

      <M1IocTables bundle={bundle} />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Export CTI</CardTitle>
        </CardHeader>
        <CardContent>
          <ExportPanel
            formats={[...M1_FORMATS]}
            fetchExport={(format) => exportM1(jobId, format as M1ExportFormat)}
            filenameBase={`admap-m1-${bundle.bundle_id}`}
            title=""
          />
        </CardContent>
      </Card>
    </motion.div>
  );
}
