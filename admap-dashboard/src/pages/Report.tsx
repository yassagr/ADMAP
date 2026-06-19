/**
 * Page Rapport (/report) — présente le dernier run de pipeline persisté dans le
 * store sous forme de rapport de threat intelligence formel et imprimable.
 *
 * Lecture seule depuis `lastPipelineRun` : en-tête, résumé exécutif, verdict M5
 * mis en évidence, puis sections statiques M4/M2/M1/M3 (tableaux imprimables,
 * pas de graphes interactifs). Le bouton « Imprimer / Exporter en PDF » déclenche
 * l'impression navigateur ; la feuille `@media print` (index.css) masque la
 * coquille et passe le document en noir sur blanc paginé. Aucune dépendance ajoutée.
 */
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { FileWarning, Printer } from "lucide-react";

import { useAdmapStore } from "@/store";
import { Button } from "@/components/ui/button";
import { fadeInUp } from "@/lib/motion";
import {
  ReportFooter,
  ReportHeader,
  ReportSection,
  ReportSummary,
  ReportVerdict,
} from "@/components/report";
import type {
  AlertBundle,
  APTMapReport,
  IOCBundle,
  YaraRuleSet,
} from "@/types";

/** M4 — clusters de campagnes + couverture MITRE (tableaux statiques). */
function M4Section({ report }: { report: APTMapReport }) {
  const clusters = report.cluster_bundle.clusters;
  const coverage = Object.entries(report.mitre_coverage)
    .map(([tactic, techniques]) => ({ tactic, techniques }))
    .filter((c) => c.techniques.length > 0)
    .sort((a, b) => b.techniques.length - a.techniques.length);

  return (
    <ReportSection
      title="Clustering de campagnes (M4)"
      badge="M4"
      subtitle={`${report.campaign_count} campagne(s), ${report.noise_count} profil(s) en bruit.`}
    >
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
              <th className="px-2 py-2">Cluster</th>
              <th className="px-2 py-2 text-right">Membres</th>
              <th className="px-2 py-2 text-right">Confiance</th>
              <th className="px-2 py-2">Techniques dominantes</th>
              <th className="px-2 py-2">Tactiques</th>
            </tr>
          </thead>
          <tbody>
            {clusters.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-2 py-3 text-muted-foreground">
                  Aucun cluster.
                </td>
              </tr>
            ) : (
              clusters.map((c) => (
                <tr key={c.cluster_id} className="border-b border-border">
                  <td className="px-2 py-2 font-mono text-xs">
                    {c.cluster_label < 0 ? "Bruit (-1)" : `#${c.cluster_label}`}
                  </td>
                  <td className="px-2 py-2 text-right font-mono">
                    {c.member_profile_ids.length}
                  </td>
                  <td className="px-2 py-2 text-right font-mono">
                    {Math.round(c.confidence_score)}
                  </td>
                  <td className="px-2 py-2 font-mono text-xs">
                    {c.dominant_techniques.join(", ") || "—"}
                  </td>
                  <td className="px-2 py-2 text-xs text-muted-foreground">
                    {c.dominant_tactics.join(", ") || "—"}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <p className="mb-2 mt-6 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        Couverture MITRE ATT&amp;CK par tactique
      </p>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
              <th className="px-2 py-2">Tactique</th>
              <th className="px-2 py-2 text-right">Techniques</th>
              <th className="px-2 py-2">Détail</th>
            </tr>
          </thead>
          <tbody>
            {coverage.length === 0 ? (
              <tr>
                <td colSpan={3} className="px-2 py-3 text-muted-foreground">
                  Aucune tactique couverte.
                </td>
              </tr>
            ) : (
              coverage.map((c) => (
                <tr key={c.tactic} className="border-b border-border">
                  <td className="px-2 py-2">{c.tactic}</td>
                  <td className="px-2 py-2 text-right font-mono">
                    {c.techniques.length}
                  </td>
                  <td className="px-2 py-2 font-mono text-xs text-muted-foreground">
                    {c.techniques.join(", ")}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </ReportSection>
  );
}

/** M2 — alertes C2 par sévérité/type + tableau compact des alertes. */
function M2Section({ bundle }: { bundle: AlertBundle }) {
  const bySeverity = Object.entries(bundle.alerts_by_severity).filter(
    ([, n]) => n > 0,
  );
  const byType = Object.entries(bundle.alerts_by_type).filter(([, n]) => n > 0);

  return (
    <ReportSection
      title="Détection C2 (M2)"
      badge="M2"
      subtitle={`${bundle.alerts.length} alerte(s) sur ${bundle.total_flows} flux — source : ${bundle.pcap_filename}.`}
    >
      <div className="flex flex-wrap gap-2">
        {bySeverity.map(([sev, n]) => (
          <span
            key={sev}
            className="rounded-md border border-border px-2 py-1 text-xs"
          >
            {sev} · <span className="font-mono text-primary">{n}</span>
          </span>
        ))}
        {byType.map(([type, n]) => (
          <span
            key={type}
            className="rounded-md border border-border px-2 py-1 text-xs"
          >
            {type} · <span className="font-mono text-primary">{n}</span>
          </span>
        ))}
      </div>

      <div className="mt-4 overflow-x-auto">
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
              <th className="px-2 py-2">Type</th>
              <th className="px-2 py-2">Sévérité</th>
              <th className="px-2 py-2 text-right">Conf.</th>
              <th className="px-2 py-2">Source → Destination</th>
              <th className="px-2 py-2">Description</th>
            </tr>
          </thead>
          <tbody>
            {bundle.alerts.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-2 py-3 text-muted-foreground">
                  Aucune alerte.
                </td>
              </tr>
            ) : (
              bundle.alerts.map((a) => (
                <tr key={a.id} className="border-b border-border">
                  <td className="px-2 py-2 font-mono text-xs">{a.alert_type}</td>
                  <td className="px-2 py-2 text-xs uppercase">{a.severity}</td>
                  <td className="px-2 py-2 text-right font-mono">
                    {Math.round(a.confidence_score)}
                  </td>
                  <td className="px-2 py-2 font-mono text-xs">
                    {a.src_ip}:{a.src_port} → {a.dst_ip}:{a.dst_port}
                  </td>
                  <td className="px-2 py-2 text-xs text-muted-foreground">
                    {a.description}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </ReportSection>
  );
}

/** M1 — IOC extraits, par type + liste compacte (defangée). */
function M1Section({ bundle }: { bundle: IOCBundle }) {
  const byType = Object.entries(bundle.analysis_stats.by_type).filter(
    ([, n]) => n > 0,
  );

  return (
    <ReportSection
      title="Indicateurs de compromission (M1)"
      badge="M1"
      subtitle={`${bundle.analysis_stats.total_iocs} IOC extraits de ${bundle.metadata.filename}.`}
    >
      <div className="flex flex-wrap gap-2">
        {byType.length === 0 ? (
          <span className="text-sm text-muted-foreground">Aucun IOC.</span>
        ) : (
          byType.map(([type, n]) => (
            <span
              key={type}
              className="rounded-md border border-border px-2 py-1 text-xs"
            >
              {type} · <span className="font-mono text-primary">{n}</span>
            </span>
          ))
        )}
      </div>

      {bundle.iocs.length > 0 && (
        <div className="mt-4 overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
                <th className="px-2 py-2">Type</th>
                <th className="px-2 py-2">Valeur</th>
                <th className="px-2 py-2">Niveau</th>
                <th className="px-2 py-2 text-right">Conf.</th>
              </tr>
            </thead>
            <tbody>
              {bundle.iocs.map((ioc) => (
                <tr key={ioc.id} className="border-b border-border">
                  <td className="px-2 py-2 font-mono text-xs">{ioc.type}</td>
                  <td className="px-2 py-2 font-mono text-xs">
                    {ioc.value_defanged}
                  </td>
                  <td className="px-2 py-2 text-xs">{ioc.confidence_level}</td>
                  <td className="px-2 py-2 text-right font-mono">
                    {Math.round(ioc.confidence_score)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </ReportSection>
  );
}

/** M3 — règles YARA générées (noms, compilation, confiance). */
function M3Section({ ruleset }: { ruleset: YaraRuleSet }) {
  return (
    <ReportSection
      title="Signatures YARA (M3)"
      badge="M3"
      subtitle={`${ruleset.total_rules} règle(s) — ${ruleset.compiled_rules} compilée(s), ${ruleset.failed_rules} en échec.`}
    >
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
              <th className="px-2 py-2">Règle</th>
              <th className="px-2 py-2">Compilée</th>
              <th className="px-2 py-2 text-right">Conf.</th>
            </tr>
          </thead>
          <tbody>
            {ruleset.rules.length === 0 ? (
              <tr>
                <td colSpan={3} className="px-2 py-3 text-muted-foreground">
                  Aucune règle.
                </td>
              </tr>
            ) : (
              ruleset.rules.map((rule) => (
                <tr key={rule.rule_id} className="border-b border-border">
                  <td className="px-2 py-2 font-mono text-xs">
                    {rule.rule_name}
                  </td>
                  <td className="px-2 py-2 text-xs">
                    {rule.compiled ? "Oui" : "Non"}
                  </td>
                  <td className="px-2 py-2 text-right font-mono">
                    {Math.round(rule.confidence_score)}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </ReportSection>
  );
}

export function Report() {
  const run = useAdmapStore((s) => s.lastPipelineRun);

  if (!run) {
    return (
      <section className="flex flex-col items-center justify-center gap-4 py-24 text-center">
        <FileWarning className="h-12 w-12 text-muted-foreground" />
        <div>
          <h1 className="text-xl font-bold text-white">Aucune analyse à exporter</h1>
          <p className="mt-1 text-slate-400">
            Lancez d'abord un pipeline pour générer un rapport.
          </p>
        </div>
        <Button asChild>
          <Link to="/pipeline">Aller au pipeline</Link>
        </Button>
      </section>
    );
  }

  const { results, meta, runId, createdAt } = run;

  return (
    <motion.section
      className="flex flex-col gap-6"
      variants={fadeInUp}
      initial="hidden"
      animate="visible"
    >
      <div className="no-print flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Rapport</h1>
          <p className="mt-1 text-slate-400">
            Dernier run de pipeline, prêt pour impression ou export PDF.
          </p>
        </div>
        <Button onClick={() => window.print()}>
          <Printer className="h-4 w-4" />
          Imprimer / Exporter en PDF
        </Button>
      </div>

      <div className="print-area flex flex-col gap-6">
        <ReportHeader meta={meta} runId={runId} createdAt={createdAt} />
        <ReportSummary results={results} />
        {results.m5 && <ReportVerdict report={results.m5} />}
        {results.m4 && <M4Section report={results.m4} />}
        {results.m2 && <M2Section bundle={results.m2} />}
        {results.m1 && <M1Section bundle={results.m1} />}
        {results.m3 && <M3Section ruleset={results.m3} />}
        <ReportFooter generatedAt={createdAt} />
      </div>
    </motion.section>
  );
}
