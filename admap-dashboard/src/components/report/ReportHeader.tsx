/**
 * En-tête du rapport de threat intelligence : titre, plateforme, date de
 * génération, identifiant de run et fichiers analysés.
 */
import type { PipelineRunMeta } from "@/store";

export interface ReportHeaderProps {
  meta: PipelineRunMeta;
  runId: string;
  createdAt: string;
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString("fr-FR", {
    dateStyle: "long",
    timeStyle: "short",
  });
}

export function ReportHeader({ meta, runId, createdAt }: ReportHeaderProps) {
  const files: string[] = [`PCAP : ${meta.pcapName}`];
  if (meta.suspectFileName) files.push(`Fichier suspect : ${meta.suspectFileName}`);
  if (meta.corpusMalwareCount > 0 || meta.corpusBenignCount > 0) {
    files.push(
      `Corpus YARA : ${meta.corpusMalwareCount} malveillant(s) / ${meta.corpusBenignCount} bénin(s)`,
    );
  }

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
        Rapport d'analyse de menace
      </h1>

      <dl className="mt-4 grid gap-x-8 gap-y-2 text-sm sm:grid-cols-2">
        <div className="flex justify-between gap-4 sm:block">
          <dt className="text-muted-foreground">Date de génération</dt>
          <dd className="text-foreground">{formatDate(createdAt)}</dd>
        </div>
        <div className="flex justify-between gap-4 sm:block">
          <dt className="text-muted-foreground">Identifiant du run</dt>
          <dd className="font-mono text-xs text-foreground">{runId}</dd>
        </div>
        <div className="sm:col-span-2">
          <dt className="text-muted-foreground">Fichiers analysés</dt>
          <dd className="mt-1 flex flex-col gap-0.5 font-mono text-xs text-foreground">
            {files.map((f) => (
              <span key={f}>{f}</span>
            ))}
          </dd>
        </div>
      </dl>
    </header>
  );
}
