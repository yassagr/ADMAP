import { Outlet } from "react-router-dom";
import { Sidebar } from "./Sidebar";
import { useModuleHealth } from "@/hooks/useModuleHealth";

/** Coquille applicative : sidebar fixe + zone de contenu routée. */
export function AppLayout() {
  // Alimente `moduleStatus` (StatusDot du Sidebar) par polling du Gateway.
  useModuleHealth();

  return (
    <div className="flex min-h-screen bg-slate-900 text-slate-100">
      <Sidebar />
      <main className="flex-1 overflow-y-auto">
        <div className="mx-auto max-w-7xl px-8 py-8">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
