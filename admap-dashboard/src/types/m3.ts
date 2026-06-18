/**
 * Contrats M3 — YARA Signature Generator (FastAPI port 8002).
 * Source de vérité : `admap_m3/admap_m3/models/rule.py` (YaraRuleSet v1.0.0).
 */

/** Niveau TLP (Traffic Light Protocol) (`TLPLevel`). */
export type TLPLevel = "TLP:WHITE" | "TLP:GREEN" | "TLP:AMBER" | "TLP:RED";

/** Métadonnées intégrées dans une règle YARA (`RuleMetadata`, frozen). */
export interface RuleMetadata {
  author: string;
  description: string;
  date: string;
  version: string;
  tlp: TLPLevel;
  corpus_id: string;
  malware_family: string | null;
  mitre_attack: string[];
  hash_corpus: string;
}

/** Règle YARA générée et (potentiellement) compilée (`YaraRule`, frozen). */
export interface YaraRule {
  rule_id: string;
  rule_name: string;
  metadata: RuleMetadata;
  strings: string[];
  condition: string;
  raw_yara: string;
  compiled: boolean;
  token_count: number;
  confidence_score: number;
}

/** Contrat de sortie principal de M3 (`YaraRuleSet`, frozen). */
export interface YaraRuleSet {
  ruleset_id: string;
  corpus_id: string;
  rules: YaraRule[];
  total_rules: number;
  compiled_rules: number;
  failed_rules: number;
  generation_duration_ms: number;
  created_at: string;
}
