/**
 * Contrats M1 — IOC Extractor (FastAPI port 8000).
 * Source de vérité : `admap_m1/admap_m1/models/ioc.py` (IOCBundle v3.0.0).
 */

/** Types d'IOC supportés par M1 (`IOCType`). */
export type IOCType =
  | "ipv4"
  | "ipv6"
  | "domain"
  | "url"
  | "email"
  | "hash_md5"
  | "hash_sha1"
  | "hash_sha256"
  | "hash_ssdeep"
  | "hash_imphash"
  | "filepath"
  | "filename"
  | "registry_key"
  | "mutex"
  | "command";

/** Niveau de confiance dérivé du score 0-100 (`IOCConfidenceLevel`). */
export type IOCConfidenceLevel =
  | "confirmed"
  | "high"
  | "medium"
  | "low"
  | "noise";

/** Résultat d'enrichissement VirusTotal pour un IOC (`VTResult`). */
export interface VTResult {
  value: string;
  ioc_type: string;
  found: boolean;
  malicious: number;
  suspicious: number;
  undetected: number;
  harmless: number;
  confidence_score: number;
  verdict: string;
  file_type: string | null;
  country: string | null;
  as_owner: string | null;
  reputation: number | null;
  vt_link: string | null;
  error: string | null;
}

/** IOC finalisé après scoring, filtrage et defanging (`IOC`, frozen). */
export interface IOC {
  id: string;
  type: IOCType;
  value: string;
  value_defanged: string;
  confidence_score: number;
  confidence_level: IOCConfidenceLevel;
  context_snippet: string;
  source_offset: number | null;
  entropy_context: number | null;
  tags: string[];
  extraction_method: string;
  scoring_reasons: string[];
  vt_result: VTResult | null;
  first_seen: string;
}

/** Empreintes cryptographiques d'un fichier (`FileHashes`). */
export interface FileHashes {
  md5: string;
  sha1: string;
  sha256: string;
  ssdeep: string | null;
}

/** Section PE (`PESection`). */
export interface PESection {
  name: string;
  virtual_address: string;
  raw_size: number;
  entropy: number;
  characteristics: string[];
  is_suspicious: boolean;
}

/** Métadonnées d'un Portable Executable (`PEInfo`). */
export interface PEInfo {
  compilation_timestamp: string | null;
  entry_point: string;
  sections: PESection[];
  imports: Record<string, string[]>;
  exports: string[];
  resources: string[];
  is_dotnet: boolean;
  is_64bit: boolean;
  suspicious_imports: string[];
  import_suspicion_score: number;
}

/** Métadonnées complètes d'un fichier analysé (`FileMetadata`). */
export interface FileMetadata {
  filename: string;
  filesize: number;
  filetype: string;
  magic_bytes: string;
  hashes: FileHashes;
  entropy: number;
  is_packed: boolean;
  packer_name: string | null;
  pe_info: PEInfo | null;
  extracted_from: string | null;
}

/** Statistiques d'une analyse M1 (`AnalysisStats`). */
export interface AnalysisStats {
  total_iocs: number;
  by_type: Record<string, number>;
  filtered_out: number;
  deobfuscation_layers: number;
  vt_enriched: number;
  duration_ms: number;
}

/** Contrat de sortie principal de M1 (`IOCBundle`). */
export interface IOCBundle {
  bundle_id: string;
  metadata: FileMetadata;
  iocs: IOC[];
  analysis_stats: AnalysisStats;
  created_at: string;
  pipeline_version: string;
}
