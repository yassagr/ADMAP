/**
 * Page IA / Modèle — performances du modèle de classification (M5 Attribution).
 *
 * Lit le fichier statique `public/model_metrics.json` (remplaçable sans rebuild)
 * et affiche, lorsque le modèle est entraîné : récap de métriques, matrice de
 * confusion, courbe ROC et importance des features. Gère les états loading /
 * error / vide (modèle non entraîné).
 */
import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { AlertTriangle, Loader2 } from "lucide-react";

import { fadeInUp } from "@/lib/motion";
import {
  AIEmptyState,
  AIMetricsSummary,
  ConfusionMatrix,
  FeatureImportance,
  RocCurve,
} from "@/components/ai";
import { Card, CardContent } from "@/components/ui/card";
import { isModelReady, type ModelMetrics } from "@/types/aiMetrics";

type LoadState =
  | { phase: "loading" }
  | { phase: "error"; message: string }
  | { phase: "ready"; data: ModelMetrics };

const METRICS_URL = "/model_metrics.json";

export function AI() {
  const [state, setState] = useState<LoadState>({ phase: "loading" });

  useEffect(() => {
    let cancelled = false;

    (async () => {
      try {
        const res = await fetch(METRICS_URL, { cache: "no-store" });
        if (!res.ok) {
          throw new Error(`HTTP ${res.status} sur ${METRICS_URL}`);
        }
        const data = (await res.json()) as ModelMetrics;
        if (!cancelled) setState({ phase: "ready", data });
      } catch (e) {
        if (!cancelled) {
          setState({
            phase: "error",
            message: e instanceof Error ? e.message : "Erreur de chargement",
          });
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  const data = state.phase === "ready" ? state.data : null;
  const ready = data !== null && isModelReady(data);

  return (
    <motion.section
      className="flex flex-col gap-6"
      variants={fadeInUp}
      initial="hidden"
      animate="visible"
    >
      <header>
        <h1 className="text-2xl font-bold text-white">IA · Performance du modèle</h1>
        <p className="mt-1 text-slate-400">
          Évaluation du modèle de classification binaire (bénin / malveillant) :
          métriques agrégées, matrice de confusion, courbe ROC et importance des
          features. Données lues depuis{" "}
          <code className="text-slate-300">public/model_metrics.json</code>.
        </p>
      </header>

      {ready && data && (
        <div className="flex flex-wrap items-center gap-x-6 gap-y-1 text-sm text-slate-400">
          {data.model_name && (
            <span>
              Modèle :{" "}
              <span className="font-semibold text-slate-200">
                {data.model_name}
              </span>
            </span>
          )}
          {data.dataset && (
            <span>
              Dataset :{" "}
              <span className="font-semibold text-slate-200">{data.dataset}</span>
            </span>
          )}
          {data.trained_at && (
            <span>
              Entraîné le :{" "}
              <span className="font-semibold text-slate-200">
                {new Date(data.trained_at).toLocaleString("fr-FR")}
              </span>
            </span>
          )}
        </div>
      )}

      {state.phase === "loading" && (
        <Card>
          <CardContent className="flex items-center justify-center gap-3 py-16 text-sm text-muted-foreground">
            <Loader2 className="h-5 w-5 animate-spin" />
            Chargement des métriques…
          </CardContent>
        </Card>
      )}

      {state.phase === "error" && (
        <Card style={{ borderColor: "rgba(255, 45, 85, 0.5)" }}>
          <CardContent className="flex items-center gap-3 py-8 text-sm text-destructive">
            <AlertTriangle className="h-5 w-5 shrink-0" />
            Impossible de charger {METRICS_URL} : {state.message}
          </CardContent>
        </Card>
      )}

      {state.phase === "ready" && !ready && <AIEmptyState />}

      {ready && data && (
        <>
          <AIMetricsSummary metrics={data.metrics} />
          <div className="grid gap-6 lg:grid-cols-2">
            <ConfusionMatrix labels={data.labels} matrix={data.confusion_matrix} />
            <RocCurve roc={data.roc} auc={data.metrics.auc} />
          </div>
          <FeatureImportance features={data.feature_importance} />
        </>
      )}
    </motion.section>
  );
}
