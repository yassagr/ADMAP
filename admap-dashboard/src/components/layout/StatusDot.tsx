import { cn } from "@/lib/utils";
import type { ModuleHealthStatus } from "@/types";

/**
 * Pastille de statut d'un module (ok / error / unknown).
 *
 * Purement visuelle : la valeur provient du store Zustand. Le polling qui
 * alimente ce store sera branché dans un lot ultérieur.
 */
export function StatusDot({
  status,
  className,
}: {
  status: ModuleHealthStatus;
  className?: string;
}) {
  const color: Record<ModuleHealthStatus, string> = {
    ok: "bg-emerald-400",
    error: "bg-rose-500",
    unknown: "bg-slate-500",
  };

  return (
    <span
      className={cn(
        "inline-block h-2 w-2 rounded-full",
        color[status],
        className,
      )}
      aria-label={`status: ${status}`}
      title={status}
    />
  );
}
