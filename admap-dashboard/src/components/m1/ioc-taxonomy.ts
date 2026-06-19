/**
 * Taxonomie partagée des IOC M1 : libellés/couleurs par `IOCType` et
 * regroupement en catégories. Source unique consommée par le donut, les barres
 * et les tables — évite la duplication des maps entre composants.
 */
import type { IOCType, IOCConfidenceLevel } from "@/types";

/** Libellé court d'affichage par type d'IOC. */
export const IOC_TYPE_LABEL: Record<IOCType, string> = {
  ipv4: "IPv4",
  ipv6: "IPv6",
  domain: "Domaine",
  url: "URL",
  email: "Email",
  hash_md5: "MD5",
  hash_sha1: "SHA1",
  hash_sha256: "SHA256",
  hash_ssdeep: "SSDeep",
  hash_imphash: "IMPHASH",
  filepath: "Chemin",
  filename: "Fichier",
  registry_key: "Registre",
  mutex: "Mutex",
  command: "Commande",
};

/** Couleur par type d'IOC (palette thème, purple réservé à l'IA). */
export const IOC_TYPE_COLOR: Record<IOCType, string> = {
  ipv4: "#00d4ff",
  ipv6: "#22d3ee",
  domain: "#38bdf8",
  url: "#0ea5e9",
  email: "#a3e635",
  hash_md5: "#facc15",
  hash_sha1: "#f59e0b",
  hash_sha256: "#ff6b35",
  hash_ssdeep: "#fb7185",
  hash_imphash: "#ff2d55",
  filepath: "#94a3b8",
  filename: "#64748b",
  registry_key: "#c084fc",
  mutex: "#2dd4bf",
  command: "#f472b6",
};

/** Couleur d'un niveau de confiance (rouge = plus sûr d'être malveillant). */
export const CONFIDENCE_COLOR: Record<IOCConfidenceLevel, string> = {
  confirmed: "#ff2d55",
  high: "#ff6b35",
  medium: "#facc15",
  low: "#38bdf8",
  noise: "#64748b",
};

/** Catégorie de regroupement des IOC pour les tables et les barres. */
export interface IocCategory {
  key: string;
  label: string;
  types: readonly IOCType[];
}

/** Ordre d'affichage des catégories d'IOC. */
export const IOC_CATEGORIES: readonly IocCategory[] = [
  { key: "ip", label: "Adresses IP", types: ["ipv4", "ipv6"] },
  { key: "domain", label: "Domaines", types: ["domain"] },
  { key: "url", label: "URLs", types: ["url"] },
  { key: "email", label: "Emails", types: ["email"] },
  {
    key: "hash",
    label: "Hashes",
    types: ["hash_md5", "hash_sha1", "hash_sha256", "hash_ssdeep", "hash_imphash"],
  },
  { key: "file", label: "Fichiers", types: ["filepath", "filename"] },
  { key: "registry", label: "Clés de registre", types: ["registry_key"] },
  { key: "mutex", label: "Mutex", types: ["mutex"] },
  { key: "command", label: "Commandes suspectes", types: ["command"] },
];
