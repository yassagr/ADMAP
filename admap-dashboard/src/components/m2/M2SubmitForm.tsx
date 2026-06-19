/**
 * Formulaire de soumission M2 : dépôt PCAP + corrélation M1 optionnelle +
 * toggles de détecteurs + seuil de confiance. Émet `(file, options)` au parent.
 */
import { useState } from "react";
import { Radar } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Slider } from "@/components/ui/slider";
import { Toggle } from "@/components/ui/toggle";
import { FileDropZone } from "@/components/shared";
import type { M2AnalyzeOptions } from "@/api/m2";

/** Clés locales des 7 détecteurs (mappées vers `M2AnalyzeOptions`). */
type DetectorKey =
  | "beaconing"
  | "dga"
  | "dnsTunnel"
  | "httpC2"
  | "tls"
  | "irc"
  | "portScan";

const DETECTORS: readonly { key: DetectorKey; label: string }[] = [
  { key: "beaconing", label: "Beaconing" },
  { key: "dga", label: "DGA" },
  { key: "dnsTunnel", label: "DNS Tunnel" },
  { key: "httpC2", label: "HTTP C2" },
  { key: "tls", label: "TLS / JA3" },
  { key: "irc", label: "IRC" },
  { key: "portScan", label: "Port Scan" },
];

const ALL_ON: Record<DetectorKey, boolean> = {
  beaconing: true,
  dga: true,
  dnsTunnel: true,
  httpC2: true,
  tls: true,
  irc: true,
  portScan: true,
};

export interface M2SubmitFormProps {
  onSubmit: (file: File, options: M2AnalyzeOptions) => void;
  /** Désactive le formulaire (soumission/analyse en cours). */
  disabled?: boolean;
}

export function M2SubmitForm({ onSubmit, disabled = false }: M2SubmitFormProps) {
  const [file, setFile] = useState<File | null>(null);
  const [m1BundlePath, setM1BundlePath] = useState("");
  const [detectors, setDetectors] = useState<Record<DetectorKey, boolean>>(ALL_ON);
  const [minConfidence, setMinConfidence] = useState(20);

  const toggle = (key: DetectorKey): void =>
    setDetectors((prev) => ({ ...prev, [key]: !prev[key] }));

  const handleAnalyze = (): void => {
    if (!file) return;
    onSubmit(file, {
      enableBeaconing: detectors.beaconing,
      enableDga: detectors.dga,
      enableDnsTunnel: detectors.dnsTunnel,
      enableHttpC2: detectors.httpC2,
      enableTls: detectors.tls,
      enableIrc: detectors.irc,
      enablePortScan: detectors.portScan,
      m1BundlePath: m1BundlePath.trim() || undefined,
      minConfidence,
    });
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Radar className="h-5 w-5 text-primary" />
          Analyse PCAP
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-5">
        <FileDropZone
          accept=".pcap,.pcapng"
          label={
            file
              ? `Fichier sélectionné : ${file.name}`
              : "Glissez un PCAP ici ou cliquez pour parcourir"
          }
          disabled={disabled}
          onFiles={(files) => setFile(files[0] ?? null)}
        />

        <div className="flex flex-col gap-2">
          <Label htmlFor="m1-bundle-path">
            Chemin IOCBundle M1 (optionnel — corrélation)
          </Label>
          <Input
            id="m1-bundle-path"
            value={m1BundlePath}
            onChange={(e) => setM1BundlePath(e.target.value)}
            placeholder="/chemin/serveur/vers/ioc_bundle.json"
            disabled={disabled}
          />
        </div>

        <div className="flex flex-col gap-2">
          <Label>Détecteurs activés</Label>
          <div className="flex flex-wrap gap-2">
            {DETECTORS.map(({ key, label }) => (
              <Toggle
                key={key}
                variant="outline"
                size="sm"
                pressed={detectors[key]}
                onPressedChange={() => toggle(key)}
                disabled={disabled}
              >
                {label}
              </Toggle>
            ))}
          </div>
        </div>

        <div className="flex flex-col gap-2">
          <Label>
            Confiance minimale :{" "}
            <span className="font-mono text-primary">{minConfidence}</span>
          </Label>
          <Slider
            value={[minConfidence]}
            min={0}
            max={100}
            step={5}
            disabled={disabled}
            onValueChange={(v) => setMinConfidence(v[0] ?? 0)}
            className="max-w-sm"
          />
        </div>

        <div>
          <Button onClick={handleAnalyze} disabled={disabled || !file}>
            <Radar className="h-4 w-4" />
            Analyser
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
