from __future__ import annotations
import stix2
from datetime import datetime, timezone
from admap_m4.models.report import APTMapReport

class STIXExporter:
    """Exporteur STIX 2.1 pour M4."""

    def export(self, report: APTMapReport) -> dict[str, object]:
        """
        Exporte le rapport au format STIX 2.1.
        Ne lève jamais RuntimeError.
        """
        try:
            objects = []
            
            identity = stix2.Identity(
                name="ADMAP Platform M4",
                identity_class="system"
            )
            objects.append(identity)

            # Attack patterns cache
            attack_patterns: dict[str, stix2.AttackPattern] = {}

            for cluster in report.cluster_bundle.clusters:
                if cluster.confidence_score >= 40:
                    intrusion_set = stix2.IntrusionSet(
                        name=f"APT Cluster {cluster.cluster_id[:8]}",
                        description=f"Automated APT clustering. Label: {cluster.cluster_label}",
                        first_seen=cluster.first_seen,
                        last_seen=cluster.last_seen,
                        confidence=int(cluster.confidence_score),
                        created_by_ref=identity.id
                    )
                    objects.append(intrusion_set)

                    for technique in cluster.dominant_techniques:
                        if technique not in attack_patterns:
                            ap = stix2.AttackPattern(
                                name=f"MITRE {technique}",
                                description=f"MITRE ATT&CK Technique {technique}",
                                external_references=[
                                    {"source_name": "mitre-attack", "external_id": technique}
                                ],
                                created_by_ref=identity.id
                            )
                            attack_patterns[technique] = ap
                            objects.append(ap)
                        else:
                            ap = attack_patterns[technique]
                        
                        rel = stix2.Relationship(
                            source_ref=intrusion_set.id,
                            target_ref=ap.id,
                            relationship_type="uses",
                            created_by_ref=identity.id
                        )
                        objects.append(rel)

            bundle = stix2.Bundle(objects=objects)
            import json
            return json.loads(bundle.serialize())
            # Serialize returns a JSON string by default, we need a dict
        except Exception as e:
            return {
                "error": str(e),
                "code": "STIX_EXPORT_FAILED",
                "context": {}
            }
