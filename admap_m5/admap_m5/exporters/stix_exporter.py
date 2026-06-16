from __future__ import annotations
import uuid
from datetime import datetime, timezone
import structlog
from admap_m5.models.output import AttributionReport, APTCandidate

logger = structlog.get_logger(__name__)

STIX_MIN_CONFIDENCE = 30.0  # Seuil minimum pour inclure un candidat dans STIX


class STIXExporter:
    """Exporte un AttributionReport en STIX 2.1.
    
    Produit : ThreatActor + AttributedTo Relationship + AttackPattern
    pour chaque candidat APT avec confidence >= STIX_MIN_CONFIDENCE.
    Ne lève jamais RuntimeError — retourne JSON d'erreur structuré.
    """

    def export(self, report: AttributionReport) -> dict:
        try:
            now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            objects: list[dict] = []

            # Identity "ADMAP Platform M5"
            identity_id = f"identity--{uuid.uuid4()}"
            objects.append({
                "type": "identity",
                "spec_version": "2.1",
                "id": identity_id,
                "created": now_str,
                "modified": now_str,
                "name": "ADMAP Platform M5",
                "identity_class": "system",
            })

            seen_apt_ids: set[str] = set()

            for result in report.results:
                for candidate in result.candidates:
                    if candidate.confidence_score < STIX_MIN_CONFIDENCE:
                        continue

                    apt_stix_id = f"threat-actor--{uuid.uuid5(uuid.NAMESPACE_DNS, candidate.apt_id)}"

                    if candidate.apt_id not in seen_apt_ids:
                        seen_apt_ids.add(candidate.apt_id)
                        objects.append({
                            "type": "threat-actor",
                            "spec_version": "2.1",
                            "id": apt_stix_id,
                            "created": now_str,
                            "modified": now_str,
                            "name": candidate.apt_name,
                            "labels": ["apt"],
                            "confidence": int(candidate.confidence_score),
                            "external_references": [
                                {"source_name": "mitre-attack", "url": candidate.mitre_group_url}
                            ],
                            "description": f"APT group identified by ADMAP M5. Matched techniques: {', '.join(candidate.matched_techniques[:5])}",
                        })

                    for technique in candidate.matched_techniques[:5]:
                        pattern_id = f"attack-pattern--{uuid.uuid5(uuid.NAMESPACE_DNS, technique)}"
                        objects.append({
                            "type": "attack-pattern",
                            "spec_version": "2.1",
                            "id": pattern_id,
                            "created": now_str,
                            "modified": now_str,
                            "name": technique,
                            "external_references": [
                                {"source_name": "mitre-attack",
                                 "url": f"https://attack.mitre.org/techniques/{technique}/"}
                            ],
                        })

                        relationship_id = f"relationship--{uuid.uuid4()}"
                        objects.append({
                            "type": "relationship",
                            "spec_version": "2.1",
                            "id": relationship_id,
                            "created": now_str,
                            "modified": now_str,
                            "relationship_type": "uses",
                            "source_ref": apt_stix_id,
                            "target_ref": pattern_id,
                            "confidence": int(candidate.confidence_score),
                        })

            bundle = {
                "type": "bundle",
                "id": f"bundle--{uuid.uuid4()}",
                "objects": objects,
            }
            return bundle

        except Exception as exc:
            logger.error("stix_exporter.failed", error=str(exc))
            return {"error": str(exc), "report_id": getattr(report, "report_id", "unknown")}
