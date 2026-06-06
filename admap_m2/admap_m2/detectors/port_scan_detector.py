"""
Module   : admap_m2.detectors.port_scan_detector
Version  : 1.0.0
Dépend   : [admap_m2.detectors.base]
"""
from __future__ import annotations

from collections import defaultdict

from admap_m2.detectors.base import BaseDetector
from admap_m2.models.alert import AlertType, C2Alert
from admap_m2.models.flow import NetworkFlow


class PortScanDetector(BaseDetector):
    """
    Détecte le port scanning (reconnaissance).
    Identifie si une seule IP source contacte un grand nombre de ports
    différents sur la même IP de destination.
    """

    @property
    def detector_name(self) -> str:
        return "port_scan_detector"

    def detect(self, flows: list[NetworkFlow]) -> list[C2Alert]:
        alerts = []
        threshold = self._settings.PORT_SCAN_THRESHOLD

        # Agrégation par (src_ip, dst_ip) -> set(dst_port)
        scans: dict[tuple[str, str], set[int]] = defaultdict(set)
        # Conserver un flux de référence pour créer l'alerte
        ref_flows: dict[tuple[str, str], NetworkFlow] = {}

        for flow in flows:
            key = (flow.src_ip, flow.dst_ip)
            scans[key].add(flow.dst_port)
            if key not in ref_flows:
                ref_flows[key] = flow

        for key, ports in scans.items():
            if len(ports) >= threshold:
                src_ip, dst_ip = key
                flow = ref_flows[key]
                score = min(100, 40 + len(ports))
                evidence = [
                    f"Scanned {len(ports)} distinct ports on {dst_ip}",
                    f"Threshold: {threshold}"
                ]
                alert = self._build_alert(
                    flow=flow,
                    alert_type=AlertType.PORT_SCAN,
                    score=score,
                    description=f"Port Scan detected: {src_ip} -> {dst_ip} ({len(ports)} ports)",
                    evidence=evidence,
                    metadata={"scanned_ports_count": len(ports)}
                )
                alerts.append(alert)

        return alerts
