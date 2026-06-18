/** Point d'entrée unique des composants partagés du dashboard ADMAP. */
export { SeverityBadge } from "./SeverityBadge";
export type { Severity, SeverityBadgeProps } from "./SeverityBadge";

export { JobStatusBadge } from "./JobStatusBadge";
export type { JobStatusBadgeProps } from "./JobStatusBadge";

export { ScoreGauge } from "./ScoreGauge";
export type { ScoreGaugeProps } from "./ScoreGauge";

export { FileDropZone } from "./FileDropZone";
export type { FileDropZoneProps } from "./FileDropZone";

export { JobProgressSteps } from "./JobProgressSteps";
export type {
  JobProgressStepsProps,
  ProgressStep,
  StepStatus,
} from "./JobProgressSteps";

export { DataTable } from "./DataTable";
export type { DataTableColumn, DataTableProps } from "./DataTable";

export { JsonViewer } from "./JsonViewer";
export type { JsonViewerProps } from "./JsonViewer";

export { ExportPanel } from "./ExportPanel";
export type { ExportPanelProps } from "./ExportPanel";

export { AIPhaseSlot } from "./AIPhaseSlot";
export type { AIPhaseSlotProps } from "./AIPhaseSlot";

export { ToastProvider } from "./ToastProvider";
export { useToast } from "./toast-context";
export type { ToastOptions, ToastVariant } from "./toast-context";
