/**
 * Hook de polling de la santé des modules.
 *
 * Interroge périodiquement `GET /api/status` (Gateway) et alimente
 * `moduleStatus` dans le store Zustand. L'intervalle vient de
 * `settings.pollInterval` ; le polling est inactif si `settings.autoRefresh`
 * est faux. À monter UNE seule fois (typiquement dans `AppLayout`).
 */
import { useEffect } from "react";

import { getStatus } from "@/api/gateway";
import { useAdmapStore } from "@/store";
import { MODULE_IDS } from "@/types";

export function useModuleHealth(): void {
  const autoRefresh = useAdmapStore((s) => s.settings.autoRefresh);
  const pollInterval = useAdmapStore((s) => s.settings.pollInterval);
  const updateModuleStatus = useAdmapStore((s) => s.updateModuleStatus);

  useEffect(() => {
    if (!autoRefresh) return;

    let cancelled = false;

    const poll = async (): Promise<void> => {
      try {
        const status = await getStatus();
        if (cancelled) return;
        for (const id of MODULE_IDS) {
          const health = status[id];
          if (health) updateModuleStatus(id, health);
        }
      } catch {
        if (cancelled) return;
        // Gateway injoignable -> tous les modules en "unknown".
        const ts = Date.now();
        for (const id of MODULE_IDS) {
          updateModuleStatus(id, { status: "unknown", last_checked: ts });
        }
      }
    };

    void poll(); // premier tir immédiat
    const handle = window.setInterval(() => void poll(), pollInterval);

    return () => {
      cancelled = true;
      window.clearInterval(handle);
    };
  }, [autoRefresh, pollInterval, updateModuleStatus]);
}
