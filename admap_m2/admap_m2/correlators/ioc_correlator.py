"""
Module   : admap_m2.correlators.ioc_correlator
Version  : 1.0.0
Dépend   : [json, pathlib, admap_m2.correlators.base]
"""
from __future__ import annotations

import json
from pathlib import Path

from admap_m2.correlators.base import BaseCorrelator
from admap_m2.models.alert import AlertSeverity, AlertType, C2Alert
from admap_m2.models.flow import NetworkFlow

try:
    from admap_m1.models.ioc import IOCBundle, IOCType
    M1_AVAILABLE = True
except ImportError:
    M1_AVAILABLE = False


class IOCCorrelator(BaseCorrelator):
    """
    Corrélation des flux PCAP avec les IOCs extraits par M1.
    """

    @property
    def correlator_name(self) -> str:
        return "ioc_correlator"

    def __init__(self, settings):
        super().__init__(settings)
        self.bundle_id = None
        self.iocs_ip = set()
        self.iocs_domain = set()
        self.iocs_url = set()
        self._load_bundle()

    def _load_bundle(self) -> None:
        if not self._settings.M1_BUNDLE_DEFAULT_PATH:
            return
        
        path = Path(self._settings.M1_BUNDLE_DEFAULT_PATH)
        if not path.is_file():
            self._logger.warning("m1_bundle_not_found", path=str(path))
            return

        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)

            self.bundle_id = data.get("bundle_id")
            
            for ioc in data.get("iocs", []):
                t = ioc.get("type")
                v = ioc.get("value", "").lower()
                if t in ("ipv4", "ipv6"):
                    self.iocs_ip.add(v)
                elif t == "domain":
                    self.iocs_domain.add(v)
                elif t == "url":
                    self.iocs_url.add(v)
            
            self._logger.info(
                "m1_bundle_loaded",
                ips=len(self.iocs_ip),
                domains=len(self.iocs_domain),
                urls=len(self.iocs_url)
            )
        except Exception as e:
            self._logger.error("m1_bundle_load_failed", error=str(e))

    def correlate(self, flows: list[NetworkFlow], alerts: list[C2Alert]) -> list[C2Alert]:
        if not self.bundle_id:
            return []

        new_alerts = []

        for flow in flows:
            matches = []

            # Match IP
            if flow.dst_ip in self.iocs_ip:
                matches.append(f"Destination IP matched M1 IOC: {flow.dst_ip}")
            if flow.src_ip in self.iocs_ip:
                matches.append(f"Source IP matched M1 IOC: {flow.src_ip}")

            # Match Domain
            for dns in flow.dns_queries:
                if dns.query_name.lower() in self.iocs_domain:
                    matches.append(f"DNS Query matched M1 IOC: {dns.query_name}")
            
            if flow.tls_info and flow.tls_info.sni:
                if flow.tls_info.sni.lower() in self.iocs_domain:
                    matches.append(f"TLS SNI matched M1 IOC: {flow.tls_info.sni}")

            for http in flow.http_requests:
                if http.host and http.host.lower() in self.iocs_domain:
                    matches.append(f"HTTP Host matched M1 IOC: {http.host}")
                
                # Basic URL matching
                url = f"{http.host}{http.uri}".lower()
                for ioc_url in self.iocs_url:
                    if ioc_url in url:
                        matches.append(f"HTTP URI matched M1 IOC URL: {ioc_url}")

            if matches:
                alert = C2Alert(
                    alert_type=AlertType.IOC_MATCH,
                    severity=AlertSeverity.CRITICAL,
                    confidence_score=100,
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
                    evidence=list(set(matches)),
                    ioc_matches=list(set(matches)),
                    metadata={"m1_bundle_id": self.bundle_id}
                )
                new_alerts.append(alert)

        return new_alerts
