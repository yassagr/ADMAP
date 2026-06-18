/**
 * Emplacement réservé pour les fonctionnalités IA de la Phase 2.
 *
 * Bordure purple en pointillés, badge « AI · Phase 2 », contenu présenté comme
 * désactivé (grisé, non interactif). Réutilisable partout où une capacité IA
 * future viendra s'insérer.
 */
import type { ReactNode } from "react";
import { Sparkles } from "lucide-react";

import { cn } from "@/lib/utils";

export interface AIPhaseSlotProps {
  title: string;
  description?: string;
  /** Aperçu désactivé de la future fonctionnalité. */
  children?: ReactNode;
  className?: string;
}

export function AIPhaseSlot({
  title,
  description,
  children,
  className,
}: AIPhaseSlotProps) {
  return (
    <div
      className={cn("relative rounded-lg border-2 border-dashed p-4", className)}
      style={{
        borderColor: "rgba(139, 92, 246, 0.5)",
        backgroundColor: "rgba(139, 92, 246, 0.06)",
      }}
    >
      <div className="mb-2 flex items-center gap-2">
        <span
          className="inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-semibold"
          style={{
            color: "#c4b5fd",
            backgroundColor: "rgba(139, 92, 246, 0.16)",
            border: "1px solid rgba(139, 92, 246, 0.5)",
          }}
        >
          <Sparkles className="h-3 w-3" />
          AI · Phase 2
        </span>
        <span className="text-sm font-medium text-foreground">{title}</span>
      </div>
      {description && (
        <p className="mb-3 text-xs text-muted-foreground">{description}</p>
      )}
      {children && (
        <div
          className="pointer-events-none select-none opacity-40"
          aria-disabled
        >
          {children}
        </div>
      )}
    </div>
  );
}
