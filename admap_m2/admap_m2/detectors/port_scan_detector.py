"""
Module   : admap_m2.detectors.port_scan_detector
Version  : 1.0.0
Dépend   : [collections, admap_m2.detectors.base,
            admap_m2.models.alert, admap_m2.models.flow]
"""
from __future__ import annotations

from collections import defaultdict

from admap_m2.detectors.base import BaseDetector
from admap_m2.models.alert import AlertType, C2Alert
from admap_m2.models.flow import NetworkFlow


class PortScanDetector(BaseDetector):
    """
    Détecte les scans de ports (reconnaissance réseau).

    Algorithme :
    1. Grouper par (src_ip, dst_ip)
    2. Trier par timestamp
    3. Fenêtre glissante 60s : si >= THRESHOLD ports distincts → scan détecté
    """

    @property
    def detector_name(self) -> str:
        return "port_scan"

    def detect(self, flows: list[NetworkFlow]) -> list[C2Alert]:
        """
        Détecte les scans de ports dans les flux.

        Args:
            flows: Liste des flux réseau.

        Returns:
            Liste de C2Alert de type PORT_SCAN.
        """
        alerts: list[C2Alert] = []
        pair_flows: dict[tuple[str, str], list[NetworkFlow]] = defaultdict(list)

        for flow in flows:
            pair_flows[(flow.src_ip, flow.dst_ip)].append(flow)

        threshold = self._settings.PORT_SCAN_THRESHOLD

        for (src_ip, dst_ip), group in pair_flows.items():
            if len(group) < threshold:
                continue

            sorted_group = sorted(group, key=lambda f: f.first_seen)

            for i, start_flow in enumerate(sorted_group):
                window_flows = [
                    f for f in sorted_group[i:]
                    if (f.first_seen - start_flow.first_seen).total_seconds() <= 60.0
                ]
                unique_ports = {f.dst_port for f in window_flows}

                if len(unique_ports) >= threshold:
                    score = min(100, 40 + len(unique_ports))
                    evidence = [
                        f"Ports scanned: {len(unique_ports)} distinct ports in 60s",
                        f"Sample ports: {sorted(list(unique_ports))[:10]}",
                        f"Packets: {sum(f.packet_count for f in window_flows)}",
                    ]
                    alerts.append(self._build_alert(
                        start_flow,
                        AlertType.PORT_SCAN,
                        score,
                        f"Port scan: {src_ip} scanned {len(unique_ports)} ports on {dst_ip}",
                        evidence,
                        metadata={
                            "unique_ports_count": len(unique_ports),
                            "scan_duration_s": (
                                window_flows[-1].first_seen - window_flows[0].first_seen
                            ).total_seconds(),
                        },
                    ))
                    break  # Une alerte par paire IP

        return alerts
