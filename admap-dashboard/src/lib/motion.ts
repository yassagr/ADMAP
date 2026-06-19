/**
 * Variants framer-motion partagés pour les entrées de page/section.
 * Réutilisables par toutes les pages module (gabarit M2 → M1/M3/M4/M5).
 */
import type { Variants } from "framer-motion";

/** Apparition douce de bas en haut. */
export const fadeInUp: Variants = {
  hidden: { opacity: 0, y: 16 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.4, ease: "easeOut" },
  },
};

/** Conteneur qui décale l'apparition de ses enfants (`fadeInUp`). */
export const staggerContainer: Variants = {
  hidden: {},
  visible: { transition: { staggerChildren: 0.06 } },
};
