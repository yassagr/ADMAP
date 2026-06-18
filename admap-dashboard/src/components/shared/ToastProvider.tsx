/**
 * Système de notifications toast (top-right, dismissables, auto-fermeture).
 *
 * `ToastProvider` se monte une fois en haut de l'arbre. Le hook `useToast()`
 * (dans `./toast-context`) permet de déclencher un toast de n'importe où. Pile
 * maintenue en mémoire (aucun storage).
 */
import { useCallback, useState, type ReactNode } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { AlertTriangle, CheckCircle2, Info, X, XCircle } from "lucide-react";

import {
  ToastContext,
  type ToastOptions,
  type ToastVariant,
} from "./toast-context";

interface ToastItem extends Required<Omit<ToastOptions, "description">> {
  id: string;
  description?: string;
}

const VARIANT_STYLE: Record<
  ToastVariant,
  { icon: typeof Info; color: string; border: string }
> = {
  default: { icon: Info, color: "#cbd5e1", border: "rgba(148, 163, 184, 0.4)" },
  info: { icon: Info, color: "#7dd3fc", border: "rgba(0, 212, 255, 0.45)" },
  success: { icon: CheckCircle2, color: "#6ee7b7", border: "rgba(0, 255, 136, 0.4)" },
  warning: { icon: AlertTriangle, color: "#fcd34d", border: "rgba(245, 158, 11, 0.5)" },
  error: { icon: XCircle, color: "#ff8aa0", border: "rgba(255, 45, 85, 0.55)" },
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const dismiss = useCallback((id: string): void => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const toast = useCallback(
    (options: ToastOptions): string => {
      const id =
        typeof crypto !== "undefined" && "randomUUID" in crypto
          ? crypto.randomUUID()
          : `${Date.now()}-${Math.random()}`;
      const item: ToastItem = {
        id,
        title: options.title,
        description: options.description,
        variant: options.variant ?? "default",
        duration: options.duration ?? 5000,
      };
      setToasts((prev) => [...prev, item]);
      if (item.duration > 0) {
        window.setTimeout(() => dismiss(id), item.duration);
      }
      return id;
    },
    [dismiss],
  );

  return (
    <ToastContext.Provider value={{ toast, dismiss }}>
      {children}
      <div className="pointer-events-none fixed right-4 top-4 z-50 flex w-80 flex-col gap-2">
        <AnimatePresence initial={false}>
          {toasts.map((t) => {
            const { icon: Icon, color, border } = VARIANT_STYLE[t.variant];
            return (
              <motion.div
                key={t.id}
                layout
                initial={{ opacity: 0, x: 40 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 40 }}
                transition={{ duration: 0.2 }}
                className="pointer-events-auto flex items-start gap-2 rounded-lg border p-3 shadow-lg"
                style={{
                  borderColor: border,
                  backgroundColor: "var(--bg-secondary)",
                }}
              >
                <Icon className="mt-0.5 h-4 w-4 shrink-0" style={{ color }} />
                <div className="flex-1">
                  <p className="text-sm font-semibold text-foreground">{t.title}</p>
                  {t.description && (
                    <p className="text-xs text-muted-foreground">{t.description}</p>
                  )}
                </div>
                <button
                  type="button"
                  onClick={() => dismiss(t.id)}
                  className="text-muted-foreground hover:text-foreground"
                  aria-label="Fermer"
                >
                  <X className="h-4 w-4" />
                </button>
              </motion.div>
            );
          })}
        </AnimatePresence>
      </div>
    </ToastContext.Provider>
  );
}
