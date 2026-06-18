/**
 * Hook de gestion des téléchargements d'export.
 *
 * Reçoit un `fetcher` (typiquement une fonction `exportM{n}` de la couche API
 * renvoyant un `Blob`), déclenche le téléchargement navigateur et expose l'état
 * de chargement / d'erreur. Aucun recours à localStorage / sessionStorage.
 */
import { useCallback, useState } from "react";

export interface UseExportResult {
  isExporting: boolean;
  error: string | null;
  /** Récupère le Blob via `fetcher` puis force son téléchargement sous `filename`. */
  download: (fetcher: () => Promise<Blob>, filename: string) => Promise<void>;
}

export function useExport(): UseExportResult {
  const [isExporting, setIsExporting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const download = useCallback(
    async (fetcher: () => Promise<Blob>, filename: string): Promise<void> => {
      setIsExporting(true);
      setError(null);
      try {
        const blob = await fetcher();
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.download = filename;
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        URL.revokeObjectURL(url);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Échec de l'export");
      } finally {
        setIsExporting(false);
      }
    },
    [],
  );

  return { isExporting, error, download };
}
