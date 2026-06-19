import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  FileSearch,
  Radar,
  ScanLine,
  Network,
  Fingerprint,
  Workflow,
  ListChecks,
  Settings,
  type LucideIcon,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useAdmapStore } from "@/store";
import type { ModuleId } from "@/types";
import { StatusDot } from "./StatusDot";

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  /** Renseigné pour les écrans liés à un microservice : affiche une pastille de statut. */
  module?: ModuleId;
}

const NAV_ITEMS: readonly NavItem[] = [
  { to: "/", label: "Overview", icon: LayoutDashboard },
  { to: "/pipeline", label: "Pipeline", icon: Workflow },
  { to: "/m1", label: "M1 · IOC Extractor", icon: FileSearch, module: "m1" },
  { to: "/m2", label: "M2 · C2 Detector", icon: Radar, module: "m2" },
  { to: "/m3", label: "M3 · YARA Generator", icon: ScanLine, module: "m3" },
  { to: "/m4", label: "M4 · APT Mapper", icon: Network, module: "m4" },
  { to: "/m5", label: "M5 · Attribution", icon: Fingerprint, module: "m5" },
  { to: "/jobs", label: "Jobs", icon: ListChecks },
  { to: "/settings", label: "Settings", icon: Settings },
];

export function Sidebar() {
  const moduleStatus = useAdmapStore((s) => s.moduleStatus);

  return (
    <aside className="flex h-screen w-64 shrink-0 flex-col border-r border-slate-800 bg-slate-950 text-slate-200">
      <div className="flex items-center gap-2 px-5 py-5">
        <span className="text-lg font-bold tracking-tight text-cyan-400">
          ADMAP
        </span>
        <span className="text-xs text-slate-500">SOC / CERT</span>
      </div>

      <nav className="flex-1 space-y-1 px-3">
        {NAV_ITEMS.map(({ to, label, icon: Icon, module }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
                isActive
                  ? "bg-slate-800 text-white"
                  : "text-slate-400 hover:bg-slate-900 hover:text-slate-200",
              )
            }
          >
            <Icon className="h-4 w-4 shrink-0" />
            <span className="flex-1 truncate">{label}</span>
            {module && <StatusDot status={moduleStatus[module].status} />}
          </NavLink>
        ))}
      </nav>

      <div className="px-5 py-4 text-xs text-slate-600">
        Gateway · :9000
      </div>
    </aside>
  );
}
