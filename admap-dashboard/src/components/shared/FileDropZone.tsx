/**
 * Zone de dépôt de fichiers réutilisable (drag & drop + clic).
 * Autonome : ne stocke rien, remonte les fichiers via `onFiles`.
 */
import { useRef, useState, type DragEvent, type ChangeEvent } from "react";
import { UploadCloud } from "lucide-react";

import { cn } from "@/lib/utils";

export interface FileDropZoneProps {
  /** Attribut `accept` du champ fichier (ex. ".pcap,.json"). */
  accept?: string;
  /** Libellé principal affiché dans la zone. */
  label?: string;
  /** Autorise la sélection multiple. */
  multiple?: boolean;
  /** Désactive l'interaction. */
  disabled?: boolean;
  /** Callback recevant les fichiers sélectionnés / déposés. */
  onFiles: (files: File[]) => void;
  className?: string;
}

export function FileDropZone({
  accept,
  label = "Glissez un fichier ici ou cliquez pour parcourir",
  multiple = false,
  disabled = false,
  onFiles,
  className,
}: FileDropZoneProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [isDragging, setIsDragging] = useState(false);

  const emit = (fileList: FileList | null): void => {
    if (!fileList || fileList.length === 0) return;
    const files = Array.from(fileList);
    onFiles(multiple ? files : files.slice(0, 1));
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>): void => {
    e.preventDefault();
    setIsDragging(false);
    if (disabled) return;
    emit(e.dataTransfer.files);
  };

  const handleChange = (e: ChangeEvent<HTMLInputElement>): void => {
    emit(e.target.files);
    e.target.value = ""; // permet de re-sélectionner le même fichier
  };

  return (
    <div
      role="button"
      tabIndex={disabled ? -1 : 0}
      aria-disabled={disabled}
      onClick={() => !disabled && inputRef.current?.click()}
      onKeyDown={(e) => {
        if (!disabled && (e.key === "Enter" || e.key === " ")) {
          e.preventDefault();
          inputRef.current?.click();
        }
      }}
      onDragOver={(e) => {
        e.preventDefault();
        if (!disabled) setIsDragging(true);
      }}
      onDragLeave={() => setIsDragging(false)}
      onDrop={handleDrop}
      className={cn(
        "flex flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed px-6 py-8 text-center text-sm transition-colors",
        disabled
          ? "cursor-not-allowed opacity-50"
          : "cursor-pointer hover:border-primary",
        className,
      )}
      style={{
        borderColor: isDragging ? "var(--accent-cyan)" : "var(--border)",
        backgroundColor: isDragging ? "rgba(0, 212, 255, 0.06)" : "transparent",
      }}
    >
      <UploadCloud className="h-8 w-8 text-muted-foreground" />
      <span className="text-foreground">{label}</span>
      {accept && (
        <span className="text-xs text-muted-foreground">Formats : {accept}</span>
      )}
      <input
        ref={inputRef}
        type="file"
        accept={accept}
        multiple={multiple}
        disabled={disabled}
        onChange={handleChange}
        className="hidden"
      />
    </div>
  );
}
