/**
 * Bandeau récapitulatif M1 : métadonnées du fichier analysé + statistiques
 * d'extraction (IOC totaux, filtrés, couches de désobfuscation, enrichis VT).
 */
import { FileWarning, Filter, Layers, ShieldCheck, Boxes } from "lucide-react";
import type { LucideIcon } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { IOCBundle } from "@/types";

export interface M1SummaryProps {
  bundle: IOCBundle;
}

interface StatCard {
  key: string;
  label: string;
  value: number;
  icon: LucideIcon;
  color: string;
}

/** Octets → libellé lisible. */
function humanSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} o`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} Ko`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} Mo`;
}

export function M1Summary({ bundle }: M1SummaryProps) {
  const { metadata, analysis_stats: stats } = bundle;

  const cards: StatCard[] = [
    {
      key: "total",
      label: "IOC extraits",
      value: stats.total_iocs,
      icon: Boxes,
      color: "#00d4ff",
    },
    {
      key: "filtered",
      label: "Filtrés (bruit)",
      value: stats.filtered_out,
      icon: Filter,
      color: "#64748b",
    },
    {
      key: "deob",
      label: "Couches déobf.",
      value: stats.deobfuscation_layers,
      icon: Layers,
      color: "#a3e635",
    },
    {
      key: "vt",
      label: "Enrichis VT",
      value: stats.vt_enriched,
      icon: ShieldCheck,
      color: "#facc15",
    },
  ];

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <FileWarning className="h-5 w-5 text-primary" />
            <span className="font-mono">{metadata.filename}</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-x-6 gap-y-2 text-sm text-muted-foreground">
            <span>
              Type : <span className="text-foreground">{metadata.filetype}</span>
            </span>
            <span>
              Taille :{" "}
              <span className="font-mono text-foreground">
                {humanSize(metadata.filesize)}
              </span>
            </span>
            <span>
              Entropie :{" "}
              <span className="font-mono text-foreground">
                {metadata.entropy.toFixed(2)}
              </span>
            </span>
            <span>
              Packé :{" "}
              <span
                className="font-mono"
                style={{ color: metadata.is_packed ? "#ff8aa0" : "#6ee7b7" }}
              >
                {metadata.is_packed
                  ? `oui${metadata.packer_name ? ` (${metadata.packer_name})` : ""}`
                  : "non"}
              </span>
            </span>
            <span>
              SHA256 :{" "}
              <span className="font-mono text-xs text-foreground">
                {metadata.hashes.sha256.slice(0, 24)}…
              </span>
            </span>
            <span>
              Durée :{" "}
              <span className="font-mono text-foreground">
                {stats.duration_ms} ms
              </span>
            </span>
          </div>
        </CardContent>
      </Card>

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
      </div>
    </div>
  );
}
