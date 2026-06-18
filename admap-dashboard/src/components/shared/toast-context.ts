/**
 * Contexte + hook du système de toasts.
 *
 * Séparé de `ToastProvider.tsx` pour respecter
 * `react-refresh/only-export-components` : un fichier qui exporte un composant
 * ne doit pas exporter aussi un hook/une valeur. Ici, aucun composant —
 * seulement le contexte, le hook et les types.
 */
import { createContext, useContext } from "react";

export type ToastVariant = "default" | "success" | "error" | "warning" | "info";

export interface ToastOptions {
  title: string;
  description?: string;
  variant?: ToastVariant;
  /** Durée avant auto-fermeture en ms (0 = persistant). */
  duration?: number;
}

export interface ToastContextValue {
  toast: (options: ToastOptions) => string;
  dismiss: (id: string) => void;
}

export const ToastContext = createContext<ToastContextValue | null>(null);

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    throw new Error("useToast doit être utilisé à l'intérieur de <ToastProvider>");
  }
  return ctx;
}
