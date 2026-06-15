from __future__ import annotations
import uuid
import structlog
from admap_m4.models.ttp import TTPProfile
from admap_m4.config import Settings

logger = structlog.get_logger(__name__)

# Table de mapping obligatoire (reproduire exactement depuis section 2.1)
ALERT_TYPE_TO_TTPS: dict[str, list[str]] = {
    "beaconing":       ["T1071", "T1071.001", "T1573", "T1008"],
    "dns_tunnel":      ["T1071.004", "T1048", "T1048.003"],
    "dga":             ["T1568", "T1568.002", "T1071.004"],
    "http_c2":         ["T1071.001", "T1573.001", "T1105"],
    "tls_suspect":     ["T1573.002", "T1071.001", "T1486"],
    "irc_c2":          ["T1071.003", "T1573"],
    "port_scan":       ["T1046", "T1595", "T1595.001"],
    "ioc_match":       ["T1071", "T1105", "T1027"],
    "large_upload":    ["T1048", "T1041", "T1030"],
    "custom_protocol": ["T1095", "T1571", "T1573"],
}

TECHNIQUE_TO_TACTIC: dict[str, str] = {
    "T1071":     "command-and-control",
    "T1071.001": "command-and-control",
    "T1071.003": "command-and-control",
    "T1071.004": "command-and-control",
    "T1573":     "command-and-control",
    "T1573.001": "command-and-control",
    "T1573.002": "command-and-control",
    "T1008":     "command-and-control",
    "T1095":     "command-and-control",
    "T1571":     "command-and-control",
    "T1048":     "exfiltration",
    "T1048.003": "exfiltration",
    "T1041":     "exfiltration",
    "T1030":     "exfiltration",
    "T1568":     "command-and-control",
    "T1568.002": "command-and-control",
    "T1105":     "lateral-movement",
    "T1046":     "discovery",
    "T1595":     "reconnaissance",
    "T1595.001": "reconnaissance",
    "T1027":     "defense-evasion",
    "T1486":     "impact",
}

class TTPExtractor:
    """Stage 2 : extrait les TTPProfiles depuis un AlertBundle M2."""

    @property
    def extractor_name(self) -> str:
        return "TTPExtractor"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._log = structlog.get_logger(self.__class__.__name__)

    def extract(
        self,
        alert_bundle: dict[str, object],
        yara_ruleset: dict[str, object] | None = None,
    ) -> list[TTPProfile]:
        """
        Extrait les TTPProfiles depuis un AlertBundle M2.

        Args:
            alert_bundle: dict parsé depuis JSON AlertBundle M2.
            yara_ruleset: dict parsé depuis JSON YaraRuleSet M3 (optionnel).

        Returns:
            Liste de TTPProfile, un par alerte dont confidence_score
            >= settings.min_confidence_score.
        """
        profiles: list[TTPProfile] = []
        alerts = alert_bundle.get("alerts", [])
        yara_tags = self._extract_yara_tags(yara_ruleset) if yara_ruleset else []

        for alert in alerts:
            score = alert.get("confidence_score", 0)
            if score < self._settings.min_confidence_score:
                self._log.debug(
                    "alert_skipped_low_confidence",
                    alert_type=alert.get("alert_type"),
                    score=score,
                )
                continue

            alert_type = alert.get("alert_type", "")
            techniques = ALERT_TYPE_TO_TTPS.get(alert_type, [])
            if not techniques:
                self._log.warning("unknown_alert_type", alert_type=alert_type)
                continue

            tactics = list({
                TECHNIQUE_TO_TACTIC.get(t, "unknown") for t in techniques
            })

            profile = TTPProfile(
                alert_id=str(uuid.uuid4()),
                alert_type=alert_type,
                techniques=techniques,
                tactics=tactics,
                confidence_score=int(score),
                src_ip=alert.get("src_ip", ""),
                dst_ip=alert.get("dst_ip", ""),
                timestamp=alert.get("first_seen"),  # string ISO -> Pydantic parse
                yara_tags=yara_tags,
                metadata={
                    "severity": alert.get("severity"),
                    "protocol": alert.get("protocol"),
                    "evidence": alert.get("evidence", []),
                },
            )
            profiles.append(profile)

        self._log.info(
            "ttp_extraction_complete",
            total_alerts=len(alerts),
            profiles_extracted=len(profiles),
        )
        return profiles

    def _extract_yara_tags(self, yara_ruleset: dict[str, object]) -> list[str]:
        """Extrait les tags uniques depuis un YaraRuleSet M3."""
        tags: set[str] = set()
        for rule in yara_ruleset.get("rules", []):
            tags.update(rule.get("tags", []))
        return sorted(tags)
