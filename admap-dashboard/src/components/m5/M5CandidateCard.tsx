/**
 * Carte d'un candidat APT classé (`APTCandidate`) : rang, lien MITRE, scores
 * XGBoost / cosinus, techniques / tactiques / tags YARA / IPs appariés et
 * résumé de preuve. Composant partagé entre la page M5 et le verdict pipeline.
 */
import type { APTCandidate } from "@/types";

export interface M5CandidateCardProps {
  candidate: APTCandidate;
}

/** Liste compacte de puces, tronquée au-delà de `max`. */
function ChipRow({
  label,
  items,
  max = 8,
}: {
  label: string;
  items: string[];
  max?: number;
}) {
  if (items.length === 0) return null;
  return (
    <div className="flex flex-wrap items-center gap-1">
      <span className="text-[10px] uppercase tracking-wide text-muted-foreground">
        {label} :
      </span>
      {items.slice(0, max).map((item, i) => (
        <span
          key={`${item}-${i}`}
          className="rounded border border-border px-1.5 py-0.5 font-mono text-[10px] text-foreground"
        >
          {item}
        </span>
      ))}
      {items.length > max && (
        <span className="text-[10px] text-muted-foreground">
          +{items.length - max}
        </span>
      )}
    </div>
  );
}

export function M5CandidateCard({ candidate }: M5CandidateCardProps) {
  return (
    <div className="flex flex-col gap-2 rounded-lg border border-border p-4">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="flex h-6 w-6 items-center justify-center rounded-full bg-primary/15 text-xs font-bold text-primary">
            {candidate.rank}
          </span>
          <a
            href={candidate.mitre_group_url}
            target="_blank"
            rel="noreferrer"
            className="font-semibold text-foreground hover:text-primary hover:underline"
          >
            {candidate.apt_name}
          </a>
          <span className="font-mono text-xs text-muted-foreground">
            {candidate.apt_id}
          </span>
        </div>
        <span className="font-mono text-sm font-bold text-primary">
          {Math.round(candidate.confidence_score)}
        </span>
      </div>

      <div className="grid grid-cols-2 gap-2 text-xs text-muted-foreground">
        <span>
          XGBoost :{" "}
          <span className="font-mono text-foreground">
            {(candidate.xgb_probability * 100).toFixed(1)}%
          </span>
        </span>
        <span>
          Cosine :{" "}
          <span className="font-mono text-foreground">
            {(candidate.cosine_similarity * 100).toFixed(1)}%
          </span>
        </span>
      </div>

      <ChipRow label="Techniques" items={candidate.matched_techniques} />
      <ChipRow label="Tags YARA" items={candidate.matched_yara_tags} />
      <ChipRow label="IPs" items={candidate.matched_ips} max={6} />

      {candidate.matched_tactics.length > 0 && (
        <p className="text-xs text-muted-foreground">
          Tactiques : {candidate.matched_tactics.join(", ")}
        </p>
      )}

      {candidate.evidence_summary && (
        <p className="text-xs text-slate-400">{candidate.evidence_summary}</p>
      )}
    </div>
  );
}
