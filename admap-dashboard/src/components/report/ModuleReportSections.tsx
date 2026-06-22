/**
 * Sections riches et STATIQUES (imprimables) pour le rapport d'une analyse
 * mono-module (/report depuis un `AnalysisRecord` M1-M5).
 *
 * Contrairement aux récaps compacts du rapport pipeline (`Report.tsx`), ces
 * sections rendent la sortie COMPLÈTE du module — toutes les lignes, sans
 * pagination, recherche ni interactivité (les vues live `Mx*Table` reposent sur
 * `DataTable` paginé à 10 lignes, inadapté à l'impression). Elles réutilisent
 * les primitives d'affichage partagées (`SeverityBadge`, taxonomie IOC,
 * `ReportVerdict`) et exposent le détail par ligne (raisons de scoring, evidence,
 * YARA brut, membres de cluster, candidats par cluster).
 */
import type { ReactNode } from "react";

import { SeverityBadge } from "@/components/shared";
import {
  CONFIDENCE_COLOR,
  IOC_TYPE_LABEL,
} from "@/components/m1/ioc-taxonomy";
import type {
  AlertBundle,
  AnalysisRecord,
  APTMapReport,
  AttributionReport,
  IOCBundle,
  IOCType,
  YaraRuleSet,
} from "@/types";

import { ReportSection } from "./ReportSection";
import { ReportVerdict } from "./ReportVerdict";

/** Octets → libellé lisible (aligné sur `M1Summary`). */
function humanSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} o`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} Ko`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} Mo`;
}

/** Chip de comptage réutilisée (type/sévérité). */
function CountChip({ label, value }: { label: string; value: number | string }) {
  return (
    <span className="rounded-md border border-border px-2 py-1 text-xs">
      {label} · <span className="font-mono text-primary">{value}</span>
    </span>
  );
}

/** Carte de métrique mise en avant. */
function MetricCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-border p-3 text-center">
      <dd className="font-mono text-2xl font-bold text-primary">{value}</dd>
      <dt className="mt-1 text-xs text-muted-foreground">{label}</dt>
    </div>
  );
}

const MODULE_TITLE: Record<string, string> = {
  M1: "Extraction d'IOC (M1)",
  M2: "Détection C2 (M2)",
  M3: "Génération YARA (M3)",
  M4: "Clustering APT (M4)",
  M5: "Attribution APT (M5)",
};

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString("fr-FR", {
    dateStyle: "long",
    timeStyle: "short",
  });
}

/** En-tête du rapport mono-module : plateforme, module, date, identifiant, entrée. */
export function ModuleReportHeader({ record }: { record: AnalysisRecord }) {
  return (
    <header className="report-section report-card rounded-lg border border-border bg-card p-6">
      <div className="flex items-center justify-between gap-2">
        <span className="text-sm font-bold uppercase tracking-widest text-primary">
          ADMAP
        </span>
        <span className="text-xs text-muted-foreground">
          Advanced Detection &amp; Malware Analysis Platform
        </span>
      </div>
      <h1 className="mt-3 text-2xl font-bold text-white">
        Rapport — {MODULE_TITLE[record.module] ?? record.module}
      </h1>
      <dl className="mt-4 grid gap-x-8 gap-y-2 text-sm sm:grid-cols-2">
        <div className="flex justify-between gap-4 sm:block">
          <dt className="text-muted-foreground">Date de génération</dt>
          <dd className="text-foreground">{formatDate(record.createdAt)}</dd>
        </div>
        <div className="flex justify-between gap-4 sm:block">
          <dt className="text-muted-foreground">Identifiant</dt>
          <dd className="font-mono text-xs text-foreground">{record.id}</dd>
        </div>
        <div className="sm:col-span-2">
          <dt className="text-muted-foreground">Entrée analysée</dt>
          <dd className="mt-1 font-mono text-xs text-foreground">
            {record.inputName}
          </dd>
        </div>
      </dl>
    </header>
  );
}

/** Résumé exécutif mono-module : métrique clé + détails issus du `summary`. */
export function ModuleReportSummary({ record }: { record: AnalysisRecord }) {
  return (
    <section className="report-section report-card rounded-lg border border-border bg-card p-6">
      <div className="flex items-baseline justify-between gap-3">
        <h2 className="text-lg font-bold text-white">Résumé exécutif</h2>
        <span className="rounded border border-border px-2 py-0.5 font-mono text-xs text-muted-foreground">
          {record.module}
        </span>
      </div>
      <p className="mt-3 text-3xl font-bold text-primary">
        {record.summary.headline}
      </p>
      {record.summary.details.length > 0 && (
        <div className="mt-4 flex flex-wrap gap-2">
          {record.summary.details.map((d) => (
            <span
              key={d}
              className="rounded-md border border-border px-2 py-1 text-xs text-foreground"
            >
              {d}
            </span>
          ))}
        </div>
      )}
    </section>
  );
}

/** M1 — IOC complets : métadonnées fichier, stats, comptes par type, table détaillée. */
function M1FullSection({ bundle }: { bundle: IOCBundle }) {
  const { metadata, analysis_stats: stats } = bundle;
  const byType = Object.entries(stats.by_type ?? {}).filter(([, n]) => n > 0);

  return (
    <ReportSection
      title="Indicateurs de compromission (M1)"
      badge="M1"
      subtitle={`${stats.total_iocs} IOC extraits de ${metadata.filename}.`}
    >
      <div className="mb-4 flex flex-wrap gap-x-6 gap-y-1 text-xs text-muted-foreground">
        <span>Type : <span className="text-foreground">{metadata.filetype}</span></span>
        <span>Taille : <span className="font-mono text-foreground">{humanSize(metadata.filesize)}</span></span>
        <span>Entropie : <span className="font-mono text-foreground">{metadata.entropy.toFixed(2)}</span></span>
        <span>
          Packé :{" "}
          <span className="font-mono text-foreground">
            {metadata.is_packed
              ? `oui${metadata.packer_name ? ` (${metadata.packer_name})` : ""}`
              : "non"}
          </span>
        </span>
        <span>SHA256 : <span className="font-mono text-foreground">{metadata.hashes.sha256}</span></span>
      </div>

      <dl className="mb-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <MetricCard label="IOC extraits" value={String(stats.total_iocs)} />
        <MetricCard label="Filtrés (bruit)" value={String(stats.filtered_out)} />
        <MetricCard label="Couches déobf." value={String(stats.deobfuscation_layers)} />
        <MetricCard label="Enrichis VT" value={String(stats.vt_enriched)} />
      </dl>

      <div className="mb-4 flex flex-wrap gap-2">
        {byType.length === 0 ? (
          <span className="text-sm text-muted-foreground">Aucun IOC.</span>
        ) : (
          byType.map(([type, n]) => (
            <CountChip key={type} label={IOC_TYPE_LABEL[type as IOCType] ?? type} value={n} />
          ))
        )}
      </div>

      {bundle.iocs.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
                <th className="px-2 py-2">Type</th>
                <th className="px-2 py-2">Valeur</th>
                <th className="px-2 py-2">Niveau</th>
                <th className="px-2 py-2 text-right">Conf.</th>
                <th className="px-2 py-2">Méthode</th>
              </tr>
            </thead>
            <tbody>
              {bundle.iocs.map((ioc) => {
                const color = CONFIDENCE_COLOR[ioc.confidence_level] ?? "#64748b";
                const hasDetail =
                  ioc.scoring_reasons.length > 0 ||
                  ioc.tags.length > 0 ||
                  Boolean(ioc.context_snippet);
                return (
                  <tr key={ioc.id} className="border-b border-border align-top">
                    <td className="px-2 py-2 text-xs text-muted-foreground">
                      {IOC_TYPE_LABEL[ioc.type] ?? ioc.type}
                    </td>
                    <td className="px-2 py-2">
                      <span className="font-mono text-xs text-foreground">
                        {ioc.value_defanged}
                      </span>
                      {hasDetail && (
                        <div className="mt-1 flex flex-col gap-0.5 text-[11px] text-muted-foreground">
                          {ioc.scoring_reasons.length > 0 && (
                            <span>Raisons : {ioc.scoring_reasons.join(", ")}</span>
                          )}
                          {ioc.tags.length > 0 && (
                            <span className="font-mono">Tags : {ioc.tags.join(", ")}</span>
                          )}
                          {ioc.context_snippet && (
                            <span className="break-all font-mono">
                              Contexte : {ioc.context_snippet}
                            </span>
                          )}
                        </div>
                      )}
                    </td>
                    <td className="px-2 py-2 text-xs" style={{ color }}>
                      {ioc.confidence_level}
                    </td>
                    <td className="px-2 py-2 text-right font-mono">
                      {Math.round(ioc.confidence_score)}
                    </td>
                    <td className="px-2 py-2 text-xs text-muted-foreground">
                      {ioc.extraction_method}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </ReportSection>
  );
}

/** M2 — alertes C2 complètes : comptes + table détaillée (evidence, IOC matches). */
function M2FullSection({ bundle }: { bundle: AlertBundle }) {
  const bySeverity = Object.entries(bundle.alerts_by_severity ?? {}).filter(
    ([, n]) => n > 0,
  );
  const byType = Object.entries(bundle.alerts_by_type ?? {}).filter(
    ([, n]) => n > 0,
  );

  return (
    <ReportSection
      title="Détection C2 (M2)"
      badge="M2"
      subtitle={`${bundle.alerts.length} alerte(s) sur ${bundle.total_flows} flux — source : ${bundle.pcap_filename}.`}
    >
      <div className="mb-4 flex flex-wrap gap-2">
        {bySeverity.map(([sev, n]) => (
          <CountChip key={sev} label={sev} value={n} />
        ))}
        {byType.map(([type, n]) => (
          <CountChip key={type} label={type} value={n} />
        ))}
      </div>

      {bundle.top_suspicious_ips.length > 0 && (
        <p className="mb-4 text-xs text-muted-foreground">
          IPs les plus suspectes :{" "}
          <span className="font-mono text-foreground">
            {bundle.top_suspicious_ips.join(", ")}
          </span>
        </p>
      )}

      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
              <th className="px-2 py-2">Type</th>
              <th className="px-2 py-2">Sévérité</th>
              <th className="px-2 py-2 text-right">Conf.</th>
              <th className="px-2 py-2">Source → Destination</th>
              <th className="px-2 py-2">Détail</th>
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
                <tr key={a.id} className="border-b border-border align-top">
                  <td className="px-2 py-2 font-mono text-xs">{a.alert_type}</td>
                  <td className="px-2 py-2">
                    <SeverityBadge severity={a.severity} />
                  </td>
                  <td className="px-2 py-2 text-right font-mono">
                    {Math.round(a.confidence_score)}
                  </td>
                  <td className="px-2 py-2 font-mono text-xs">
                    {a.src_ip}:{a.src_port} → {a.dst_ip}:{a.dst_port}
                    <div className="text-[11px] text-muted-foreground">
                      {a.protocol}
                    </div>
                  </td>
                  <td className="px-2 py-2 text-xs text-muted-foreground">
                    {a.description && <div>{a.description}</div>}
                    {a.evidence.length > 0 && (
                      <div className="mt-1">Evidence : {a.evidence.join("; ")}</div>
                    )}
                    {a.ioc_matches.length > 0 && (
                      <div className="mt-1 font-mono">
                        IOC : {a.ioc_matches.join(", ")}
                      </div>
                    )}
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

/** M3 — règles YARA complètes : statut + texte brut, chaînes, condition. */
function M3FullSection({ ruleset }: { ruleset: YaraRuleSet }) {
  return (
    <ReportSection
      title="Signatures YARA (M3)"
      badge="M3"
      subtitle={`${ruleset.total_rules} règle(s) — ${ruleset.compiled_rules} compilée(s), ${ruleset.failed_rules} en échec · corpus ${ruleset.corpus_id}.`}
    >
      {ruleset.rules.length === 0 ? (
        <p className="text-sm text-muted-foreground">Aucune règle générée.</p>
      ) : (
        <div className="flex flex-col gap-4">
          {ruleset.rules.map((rule) => (
            <div
              key={rule.rule_id}
              className="report-card rounded-md border border-border p-4"
            >
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <span className="font-mono text-sm font-semibold text-foreground">
                  {rule.rule_name}
                </span>
                <span className="text-xs text-muted-foreground">
                  {rule.compiled ? "compilée" : "échec compilation"} · score{" "}
                  <span className="font-mono">
                    {Math.round(rule.confidence_score)}
                  </span>{" "}
                  · {rule.token_count} tokens
                </span>
              </div>
              <pre className="mt-3 overflow-x-auto rounded bg-black/30 px-3 py-2 text-xs leading-relaxed text-foreground">
                <code>{rule.raw_yara}</code>
              </pre>
            </div>
          ))}
        </div>
      )}
    </ReportSection>
  );
}

/** M4 — clusters complets (membres, IPs, techniques, tactiques) + couverture MITRE. */
function M4FullSection({ report }: { report: APTMapReport }) {
  const clusters = report.cluster_bundle.clusters;
  const coverage = Object.entries(report.mitre_coverage)
    .map(([tactic, techniques]) => ({ tactic, techniques }))
    .filter((c) => c.techniques.length > 0)
    .sort((a, b) => b.techniques.length - a.techniques.length);

  return (
    <ReportSection
      title="Clustering de campagnes (M4)"
      badge="M4"
      subtitle={`${report.campaign_count} campagne(s), ${report.noise_count} profil(s) en bruit, ${report.cluster_bundle.total_profiles} profil(s) au total.`}
    >
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
              <th className="px-2 py-2">Cluster</th>
              <th className="px-2 py-2 text-right">Membres</th>
              <th className="px-2 py-2 text-right">Confiance</th>
              <th className="px-2 py-2">Techniques / Tactiques / IPs</th>
            </tr>
          </thead>
          <tbody>
            {clusters.length === 0 ? (
              <tr>
                <td colSpan={4} className="px-2 py-3 text-muted-foreground">
                  Aucun cluster.
                </td>
              </tr>
            ) : (
              clusters.map((c) => (
                <tr key={c.cluster_id} className="border-b border-border align-top">
                  <td className="px-2 py-2 font-mono text-xs">
                    {c.cluster_label < 0 ? "Bruit (-1)" : `#${c.cluster_label}`}
                  </td>
                  <td className="px-2 py-2 text-right font-mono">
                    {c.member_profile_ids.length}
                  </td>
                  <td className="px-2 py-2 text-right font-mono">
                    {Math.round(c.confidence_score)}
                  </td>
                  <td className="px-2 py-2 text-xs text-muted-foreground">
                    <div className="font-mono">
                      Tech. : {c.dominant_techniques.join(", ") || "—"}
                    </div>
                    <div>Tactiques : {c.dominant_tactics.join(", ") || "—"}</div>
                    {c.involved_ips.length > 0 && (
                      <div className="font-mono">IPs : {c.involved_ips.join(", ")}</div>
                    )}
                    {c.yara_tags.length > 0 && (
                      <div className="font-mono">Tags YARA : {c.yara_tags.join(", ")}</div>
                    )}
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

/** M5 — verdict + top-k (via ReportVerdict) puis détail d'attribution par cluster. */
function M5FullSection({ report }: { report: AttributionReport }) {
  return (
    <>
      <ReportVerdict report={report} />
      <ReportSection
        title="Attribution par cluster (M5)"
        badge="M5"
        subtitle={`${report.results.length} cluster(s) attribué(s).`}
      >
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-muted-foreground">
                <th className="px-2 py-2">Cluster</th>
                <th className="px-2 py-2">Méthode</th>
                <th className="px-2 py-2 text-right">Features</th>
                <th className="px-2 py-2">Candidats (acteur · score)</th>
              </tr>
            </thead>
            <tbody>
              {report.results.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-2 py-3 text-muted-foreground">
                    Aucun cluster attribué.
                  </td>
                </tr>
              ) : (
                report.results.map((res) => (
                  <tr
                    key={res.cluster_id}
                    className="border-b border-border align-top"
                  >
                    <td className="px-2 py-2 font-mono text-xs">
                      {res.cluster_label < 0
                        ? "Bruit (-1)"
                        : `#${res.cluster_label}`}
                    </td>
                    <td className="px-2 py-2 text-xs">{res.analysis_method}</td>
                    <td className="px-2 py-2 text-right font-mono">
                      {res.feature_vector_size}
                    </td>
                    <td className="px-2 py-2 text-xs text-muted-foreground">
                      {res.candidates.length > 0
                        ? res.candidates
                            .map(
                              (c) =>
                                `${c.apt_name} (${Math.round(c.confidence_score)})`,
                            )
                            .join(", ")
                        : "—"}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </ReportSection>
    </>
  );
}

/** Section riche complète selon le module du record. */
export function ModuleRichSection({ record }: { record: AnalysisRecord }): ReactNode {
  switch (record.module) {
    case "M1":
      return <M1FullSection bundle={record.result as IOCBundle} />;
    case "M2":
      return <M2FullSection bundle={record.result as AlertBundle} />;
    case "M3":
      return <M3FullSection ruleset={record.result as YaraRuleSet} />;
    case "M4":
      return <M4FullSection report={record.result as APTMapReport} />;
    case "M5":
      return <M5FullSection report={record.result as AttributionReport} />;
    default:
      return null;
  }
}
