/**
 * Configuration statique du dashboard.
 *
 * L'URL racine du Gateway BFF est figée à la compilation : par défaut
 * `http://localhost:9000`, surchargeable via la variable d'environnement Vite
 * `VITE_GATEWAY_URL` (build/dev). Plus de configuration runtime persistée — le
 * dashboard ne joint les microservices que via ce point d'entrée unique.
 */
const env = import.meta.env as Record<string, string | undefined>;

/** URL racine du Gateway (sans le suffixe `/api`, sans `/` final). */
export const GATEWAY_URL: string = (
  env.VITE_GATEWAY_URL ?? "http://localhost:9000"
).replace(/\/$/, "");
