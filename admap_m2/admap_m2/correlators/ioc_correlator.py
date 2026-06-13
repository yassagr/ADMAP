"""
Module   : admap_m2.correlators.ioc_correlator
Version  : 1.0.0
Dépend   : [json, pathlib, admap_m2.correlators.base, admap_m2.core.config,
            admap_m2.core.scoring, admap_m2.models.alert, admap_m2.models.flow]
"""
from __future__ import annotations

import json
from pathlib import Path

from admap_m2.correlators.base import BaseCorrelator
from admap_m2.core.config import Settings
from admap_m2.core.scoring import score_to_severity
from admap_m2.models.alert import AlertSeverity, AlertType, C2Alert
from admap_m2.models.flow import NetworkFlow

try:
    from admap_m1.models.ioc import IOCBundle  # type: ignore[import-not-found]  # noqa: F401
    M1_AVAILABLE = True
except ImportError:
    M1_AVAILABLE = False


class IOCCorrelator(BaseCorrelator):
    """
    Corrélation des flux PCAP avec les IOCs extraits par M1.

    Score M2 = min(100, score_M1 * 0.9 + 10).
    Severity calculée depuis le score M2 résultant.
    """

    @property
    def correlator_name(self) -> str:
        return "ioc_correlator"

    def __init__(
        self,
        settings: Settings,
        m1_bundle_path: str | None = None,
    ) -> None:
        super().__init__(settings)
        self.bundle_id: str | None = None
        self.iocs_ip: set[str] = set()
        self.iocs_domain: set[str] = set()
        self.iocs_url: set[str] = set()
        # Stocke le score M1 par valeur d'IOC
        self._ioc_scores: dict[str, int] = {}

        path = m1_bundle_path or settings.M1_BUNDLE_DEFAULT_PATH
        if path:
            self._load_bundle(path)

    def _load_bundle(self, path: str) -> None:
        """
        Charge un IOCBundle M1 depuis un fichier JSON.

        Args:
            path: Chemin vers le fichier IOCBundle JSON.
        """
        bundle_path = Path(path)
        if not bundle_path.is_file():
            self._logger.warning("m1_bundle_not_found", path=path)
            return

        try:
            data = json.loads(bundle_path.read_text(encoding="utf-8"))
            self.bundle_id = data.get("bundle_id")

            for ioc in data.get("iocs", []):
                ioc_type = ioc.get("type", "").lower()
                ioc_value = ioc.get("value", "").lower()
                ioc_score = int(ioc.get("confidence_score", 20))

                self._ioc_scores[ioc_value] = ioc_score

                if ioc_type in ("ipv4", "ipv6"):
                    self.iocs_ip.add(ioc_value)
                elif ioc_type == "domain":
                    self.iocs_domain.add(ioc_value)
                elif ioc_type == "url":
                    self.iocs_url.add(ioc_value)

            self._logger.info(
                "m1_bundle_loaded",
                bundle_id=self.bundle_id,
                ips=len(self.iocs_ip),
                domains=len(self.iocs_domain),
                urls=len(self.iocs_url),
            )
        except Exception as e:
            self._logger.error("m1_bundle_load_failed", error=str(e))

    def _m1_score_to_m2(self, m1_score: int) -> int:
        """
        Convertit un score M1 en score M2.

        Args:
            m1_score: Score de confiance M1 (0-100).

        Returns:
            Score M2 correspondant (0-100).
        """
        return min(100, int(m1_score * 0.9 + 10))

    @staticmethod
    def _score_to_severity(score: int) -> AlertSeverity:
        """
        Convertit un score en sévérité.

        Délègue à admap_m2.core.scoring.score_to_severity (mapping canonique
        partagé entre BaseDetector, C2Scorer et IOCCorrelator).

        Args:
            score: Score entre 0 et 100.

        Returns:
            AlertSeverity correspondante.
        """
        return score_to_severity(score)

    def correlate(
        self, flows: list[NetworkFlow], alerts: list[C2Alert]
    ) -> list[C2Alert]:
        """
        Corrèle les flux avec les IOCs M1 et retourne de nouvelles alertes.

        Le score de chaque alerte est basé sur le score M1 le plus élevé
        parmi les IOCs correspondants.

        Args:
            flows: Flux réseau analysés.
            alerts: Alertes existantes (non modifiées).

        Returns:
            Nouvelles alertes IOC_MATCH avec score basé sur M1.
        """
        if not self.bundle_id:
            return []

        new_alerts: list[C2Alert] = []

        for flow in flows:
            matches: list[str] = []
            max_m1_score = 20  # Score minimal par défaut

            # IPs
            for ip in (flow.dst_ip, flow.src_ip):
                ip_lower = ip.lower()
                if ip_lower in self.iocs_ip:
                    matches.append(f"IP match: {ip}")
                    max_m1_score = max(
                        max_m1_score,
                        self._ioc_scores.get(ip_lower, 20),
                    )

            # Domaines DNS
            for dns in flow.dns_queries:
                domain = dns.query_name.lower().rstrip(".")
                if domain in self.iocs_domain:
                    matches.append(f"DNS Query matched M1 IOC: {domain}")
                    max_m1_score = max(
                        max_m1_score,
                        self._ioc_scores.get(domain, 20),
                    )
                parts = domain.split(".")
                if len(parts) >= 2:
                    root = ".".join(parts[-2:])
                    if root in self.iocs_domain and root != domain:
                        matches.append(f"Root domain matched M1 IOC: {root}")
                        max_m1_score = max(
                            max_m1_score,
                            self._ioc_scores.get(root, 20),
                        )

            # TLS SNI
            if flow.tls_info and flow.tls_info.sni:
                sni = flow.tls_info.sni.lower()
                if sni in self.iocs_domain:
                    matches.append(f"TLS SNI matched M1 IOC: {sni}")
                    max_m1_score = max(
                        max_m1_score,
                        self._ioc_scores.get(sni, 20),
                    )

            # HTTP Host et URLs
            for http in flow.http_requests:
                if http.host and http.host.lower() in self.iocs_domain:
                    matches.append(f"HTTP Host matched M1 IOC: {http.host}")
                    max_m1_score = max(
                        max_m1_score,
                        self._ioc_scores.get(http.host.lower(), 20),
                    )
                url = f"{http.host}{http.uri}".lower()
                for ioc_url in self.iocs_url:
                    if ioc_url in url:
                        matches.append(f"HTTP URI matched M1 IOC URL: {ioc_url}")
                        max_m1_score = max(
                            max_m1_score,
                            self._ioc_scores.get(ioc_url, 20),
                        )

            if matches:
                score = self._m1_score_to_m2(max_m1_score)
                severity = self._score_to_severity(score)
                new_alerts.append(C2Alert(
                    alert_type=AlertType.IOC_MATCH,
                    severity=severity,
                    confidence_score=score,
                    src_ip=flow.src_ip,
                    dst_ip=flow.dst_ip,
                    src_port=flow.src_port,
                    dst_port=flow.dst_port,
                    protocol=flow.protocol.value,
                    first_seen=flow.first_seen,
                    last_seen=flow.last_seen,
                    packet_count=flow.packet_count,
                    byte_count=flow.byte_count_src_to_dst + flow.byte_count_dst_to_src,
                    description=f"Flow matched {len(matches)} M1 IOC(s)",
                    evidence=list(dict.fromkeys(matches)),
                    ioc_matches=list(dict.fromkeys(matches)),
                    metadata={
                        "m1_bundle_id": self.bundle_id,
                        "m1_max_score": max_m1_score,
                    },
                ))

        return new_alerts
