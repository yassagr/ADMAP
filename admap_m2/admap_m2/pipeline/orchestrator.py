"""
Module   : admap_m2.pipeline.orchestrator
Version  : 1.0.0
Dépend   : [admap_m2.core.config, admap_m2.models.alert]
"""
from __future__ import annotations

import time
from typing import Any

from admap_m2.analyzers.flow_analyzer import FlowAnalyzer
from admap_m2.analyzers.traffic_profiler import TrafficProfiler
from admap_m2.core.config import Settings
from admap_m2.core.logging import get_logger
from admap_m2.correlators.geo_correlator import GeoCorrelator
from admap_m2.correlators.ioc_correlator import IOCCorrelator
from admap_m2.detectors.beaconing_detector import BeaconingDetector
from admap_m2.detectors.dga_detector import DGADetector
from admap_m2.detectors.dns_tunnel_detector import DNSTunnelDetector
from admap_m2.detectors.http_c2_detector import HTTPC2Detector
from admap_m2.detectors.irc_detector import IRCDetector
from admap_m2.detectors.port_scan_detector import PortScanDetector
from admap_m2.detectors.tls_detector import TLSDetector
from admap_m2.models.alert import AlertBundle
from admap_m2.models.job import AnalysisJob
from admap_m2.parsers.flow_builder import FlowBuilder
from admap_m2.parsers.pcap_parser import PCAPParser
from admap_m2.scorers.c2_scorer import C2Scorer


class AnalysisPipeline:
    """
    Orchestre l'analyse complète d'un PCAP (6 stages).
    1. Validation & Hash
    2. Extraction des paquets
    3. Construction des flux
    4. Détection C2
    5. Corrélation
    6. Assemblage AlertBundle
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._logger = get_logger("pipeline.orchestrator")
        
        # Initialisation composants
        self.pcap_parser = PCAPParser()
        self.traffic_profiler = TrafficProfiler()
        self.scorer = C2Scorer()
        
        self.detectors = [
            BeaconingDetector(settings),
            DGADetector(settings),
            DNSTunnelDetector(settings),
            HTTPC2Detector(settings),
            TLSDetector(settings),
            IRCDetector(settings),
            PortScanDetector(settings)
        ]
        
        self.correlators = [
            IOCCorrelator(settings),
            GeoCorrelator(settings)
        ]
        
        self.flow_analyzer = FlowAnalyzer(settings, self.detectors, self.correlators)

    def run(self, job: AnalysisJob, file_bytes: bytes) -> AlertBundle:
        """Exécute le pipeline d'analyse pour un job."""
        start_time = time.time()
        
        # Stage 1: Parse & Build Flows
        flow_builder = FlowBuilder()
        packet_count = 0
        
        # Optionnel: on pourrait mettre à jour job.progress ici
        for ts, buf, link_type in self.pcap_parser.stream_packets(file_bytes):
            flow_builder.process_packet(ts, buf, link_type)
            packet_count += 1
            
        flows = flow_builder.finalize()
        
        # Stage 2: Profile Traffic
        stats = self.traffic_profiler.profile(flows)
        
        # Stage 3: Analyze Flows
        alerts = self.flow_analyzer.analyze(flows)
        
        # Stage 4: Scoring and Aggregation
        alerts_by_type = self.scorer.group_by_severity(alerts)
        
        duration_ms = int((time.time() - start_time) * 1000)
        
        # Assembler AlertBundle
        bundle = AlertBundle(
            pcap_filename=job.filename,
            pcap_sha256=job.pcap_sha256,
            pcap_size_bytes=len(file_bytes),
            analysis_duration_ms=duration_ms,
            total_packets=packet_count,
            total_flows=len(flows),
            alerts=alerts,
            alerts_by_type={a.alert_type.value: 1 for a in alerts},  # Simplified
            alerts_by_severity=alerts_by_type,
            top_suspicious_ips=[ip for ip, _ in stats.top_dst_ips],
            ioc_hits=sum(1 for a in alerts if a.alert_type.value == "ioc_match")
        )
        
        return bundle
