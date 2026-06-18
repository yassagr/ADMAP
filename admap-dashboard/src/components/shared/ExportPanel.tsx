/**
 * Panneau de boutons d'export CTI.
 *
 * Délègue le téléchargement à `useExport`. Le parent fournit `fetchExport` qui
 * renvoie le Blob pour un format donné (typiquement `(f) => exportM1(jobId, f)`).
 * Agnostique du module : la liste `formats` et `fetchExport` décident du reste.
 */
import { useState } from "react";
import { Download, Loader2 } from "lucide-react";

import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { useExport } from "@/hooks/useExport";

/** Extension de fichier suggérée selon le format d'export. */
const FORMAT_EXTENSION: Record<string, string> = {
  json: "json",
  csv: "csv",
  stix: "stix.json",
  stix21: "stix.json",
  openioc: "xml",
  misp: "json",
  cytomic: "csv",
  yar: "yar",
  all: "zip",
};

export interface ExportPanelProps {
  /** Formats proposés (ex. ["json", "csv", "stix", "all"]). */
  formats: string[];
  /** Renvoie le Blob correspondant au format demandé. */
  fetchExport: (format: string) => Promise<Blob>;
  /** Base du nom de fichier téléchargé (sans extension). */
  filenameBase?: string;
  title?: string;
  disabled?: boolean;
  className?: string;
}

export function ExportPanel({
  formats,
  fetchExport,
  filenameBase = "admap-export",
  title = "Exporter",
  disabled = false,
  className,
}: ExportPanelProps) {
  const { download, isExporting, error } = useExport();
  const [activeFormat, setActiveFormat] = useState<string | null>(null);

  const handleExport = async (format: string): Promise<void> => {
    setActiveFormat(format);
    const ext = FORMAT_EXTENSION[format] ?? format;
    await download(() => fetchExport(format), `${filenameBase}.${ext}`);
    setActiveFormat(null);
  };

  return (
    <div className={cn("flex flex-col gap-2", className)}>
      {title && (
        <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          {title}
        </span>
      )}
      <div className="flex flex-wrap gap-2">
        {formats.map((format) => {
          const busy = isExporting && activeFormat === format;
          return (
            <Button
              key={format}
              variant="outline"
              size="sm"
              disabled={disabled || isExporting}
              onClick={() => void handleExport(format)}
            >
              {busy ? (
                <Loader2 className="animate-spin" />
              ) : (
                <Download />
              )}
              {format.toUpperCase()}
            </Button>
          );
        })}
      </div>
      {error && <p className="text-xs text-destructive">{error}</p>}
    </div>
  );
}
