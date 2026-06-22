/**
 * Persistance localStorage (sans dépendance externe) de l'historique d'analyses.
 * Robustesse quota : toute écriture est encapsulée dans un try/catch et, en cas
 * de dépassement, on évince les entrées les plus anciennes puis on réessaie.
 * Aucune de ces fonctions ne lève. L'URL du Gateway n'est plus persistée ici :
 * elle provient de la config statique (`@/lib/config`).
 */
import type { AnalysisRecord } from "@/types";

const HISTORY_KEY = "admap.history.v1";

/** Nombre maximal d'analyses conservées (les plus anciennes sont évincées). */
export const HISTORY_CAP = 25;

function isRecord(value: unknown): value is AnalysisRecord {
  if (typeof value !== "object" || value === null) return false;
  const r = value as Partial<AnalysisRecord>;
  return typeof r.id === "string" && typeof r.module === "string";
}

/** Charge l'historique persisté (plus récent en tête). Renvoie `[]` si vide/corrompu. */
export function loadHistory(): AnalysisRecord[] {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(isRecord).slice(0, HISTORY_CAP);
  } catch {
    return [];
  }
}

/**
 * Persiste l'historique (ordre conservé, plus récent en tête, capé à
 * {@link HISTORY_CAP}). En cas d'échec d'écriture (quota), évince les entrées
 * les plus anciennes (queue du tableau) et réessaie. Renvoie la liste
 * réellement écrite afin que l'état mémoire reste cohérent avec localStorage.
 */
export function persistHistory(records: AnalysisRecord[]): AnalysisRecord[] {
  let toWrite = records.slice(0, HISTORY_CAP);
  while (toWrite.length > 0) {
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(toWrite));
      return toWrite;
    } catch {
      toWrite = toWrite.slice(0, -1); // évince la plus ancienne
    }
  }
  try {
    localStorage.removeItem(HISTORY_KEY);
  } catch {
    /* ignore */
  }
  return [];
}
