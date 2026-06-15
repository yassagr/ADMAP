from __future__ import annotations
import structlog
from admap_m4.models.cluster import ClusterBundle
from admap_m4.config import Settings
from admap_m4.core.ttp_extractor import TECHNIQUE_TO_TACTIC

logger = structlog.get_logger(__name__)

class MITREMapper:
    """Stage 5 : Mappe les clusters détectés aux tactiques MITRE ATT&CK."""

    @property
    def mapper_name(self) -> str:
        return "MITREMapper"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._log = structlog.get_logger(self.__class__.__name__)

    def map_coverage(self, cluster_bundle: ClusterBundle) -> dict[str, list[str]]:
        """
        Génère un dictionnaire Tactique -> liste de Techniques couvertes
        par les clusters du bundle.
        """
        coverage: dict[str, set[str]] = {}

        for cluster in cluster_bundle.clusters:
            for tech in cluster.dominant_techniques:
                tactic = TECHNIQUE_TO_TACTIC.get(tech, "unknown")
                if tactic not in coverage:
                    coverage[tactic] = set()
                coverage[tactic].add(tech)

        result: dict[str, list[str]] = {}
        for tactic, techniques in coverage.items():
            result[tactic] = sorted(techniques)

        self._log.info(
            "mitre_mapping_complete",
            tactics_covered=len(result),
            total_techniques=sum(len(t) for t in result.values())
        )
        return result
