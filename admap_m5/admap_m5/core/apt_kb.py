from __future__ import annotations
import json
from dataclasses import dataclass, field
from pathlib import Path
import structlog

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class APTGroup:
    """Représente un groupe APT dans la knowledge base."""
    apt_id: str
    apt_name: str
    aliases: list[str]
    origin: str
    mitre_url: str
    signature_techniques: list[str]
    signature_tactics: list[str]
    signature_ips: list[str]
    signature_domains_patterns: list[str]
    signature_yara_tags: list[str]
    signature_imphash_patterns: list[str]
    malware_families: list[str]
    description: str


class APTKnowledgeBase:
    """Base de connaissances statique des groupes APT.
    
    Chargée depuis un fichier JSON à l'initialisation.
    Expose des méthodes de recherche et de scoring.
    """

    def __init__(self, kb_path: Path) -> None:
        self._path: Path = kb_path
        self._groups: dict[str, APTGroup] = {}
        self._load()

    def _load(self) -> None:
        """Charge la KB depuis le fichier JSON. Lève ValueError si invalide."""
        if not self._path.exists():
            raise FileNotFoundError(f"APT KB not found: {self._path}")
        try:
            raw = self._path.read_bytes()
            data = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Failed to load APT KB: {exc}") from exc

        for grp in data.get("apt_groups", []):
            try:
                apt = APTGroup(
                    apt_id=grp["apt_id"],
                    apt_name=grp["apt_name"],
                    aliases=grp.get("aliases", []),
                    origin=grp.get("origin", "Unknown"),
                    mitre_url=grp.get("mitre_url", ""),
                    signature_techniques=grp.get("signature_techniques", []),
                    signature_tactics=grp.get("signature_tactics", []),
                    signature_ips=grp.get("signature_ips", []),
                    signature_domains_patterns=grp.get("signature_domains_patterns", []),
                    signature_yara_tags=grp.get("signature_yara_tags", []),
                    signature_imphash_patterns=grp.get("signature_imphash_patterns", []),
                    malware_families=grp.get("malware_families", []),
                    description=grp.get("description", ""),
                )
                self._groups[apt.apt_id] = apt
            except KeyError as exc:
                logger.warning("apt_kb.group_skip", reason=str(exc), group=grp)

        logger.info("apt_kb.loaded", count=len(self._groups), path=str(self._path))

    @property
    def groups(self) -> list[APTGroup]:
        return list(self._groups.values())

    def get_by_id(self, apt_id: str) -> APTGroup | None:
        return self._groups.get(apt_id)

    def all_technique_vectors(self) -> dict[str, list[str]]:
        """Retourne {apt_id: [techniques]} pour tous les groupes."""
        return {apt_id: list(grp.signature_techniques) for apt_id, grp in self._groups.items()}

    def all_tactic_vectors(self) -> dict[str, list[str]]:
        return {apt_id: list(grp.signature_tactics) for apt_id, grp in self._groups.items()}
