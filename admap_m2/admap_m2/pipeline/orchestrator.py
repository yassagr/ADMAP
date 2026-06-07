"""
Module   : admap_m2.pipeline.orchestrator
Version  : 1.0.0
Dépend   : [admap_m2.core.config, admap_m2.models.alert, admap_m2.models.job,
            admap_m2.parsers, admap_m2.detectors, admap_m2.correlators,
            admap_m2.scorers, admap_m2.analyzers]
"""
from __future__ import annotations

import asyncio
import time
from collections import Counter
from typing import Callable

from admap_m2.core.config import get_settings
from admap_m2.core.exceptions import PCAPEmptyError, PCAPParsingError, PCAPTooLargeError
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
from admap_m2.models.alert import AlertBundle, AlertType
from admap_m2.models.job import AnalysisOptions
from admap_m2.parsers.flow_builder import FlowBuilder
from admap_m2.parsers.pcap_parser import PCAPParser
from admap_m2.scorers.c2_scorer import C2Scorer


class AnalysisPipeline:
    """
    Pipeline M2 en 6 stages :
    1. VALIDATION      (5%)  : Validation PCAP + SHA256
    2. PARSING         (20%) : Extraction des paquets
    3. FLOW_BUILD      (40%) : Reconstruction des flux réseau
    4. DETECTION       (65%) : Exécution des détecteurs
    5. CORRELATION     (80%) : Corrélation IOC M1 + agrégation scores
    6. BUNDLE          (100%): Construction AlertBundle final
    """

    def __init__(self, options: AnalysisOptions | None = None) -> None:
        self._settings = get_settings()
        self.options = options or AnalysisOptions()
        self._logger = get_logger("pipeline.orchestrator")

        self.pcap_parser = PCAPParser()
        self.scorer = C2Scorer()

        self.detectors = []
        if self.options.enable_beaconing:
            self.detectors.append(BeaconingDetector(self._settings))
        if self.options.enable_dga:
            self.detectors.append(DGADetector(self._settings))
        if self.options.enable_dns_tunnel:
            self.detectors.append(DNSTunnelDetector(self._settings))
        if self.options.enable_http_c2:
            self.detectors.append(HTTPC2Detector(self._settings))
        if self.options.enable_tls:
            self.detectors.append(TLSDetector(self._settings))
        if self.options.enable_irc:
            self.detectors.append(IRCDetector(self._settings))
        if self.options.enable_port_scan:
            self.detectors.append(PortScanDetector(self._settings))

        self.ioc_correlator = IOCCorrelator(
            self._settings,
            m1_bundle_path=self.options.m1_bundle_path,
        )
        self.geo_correlator = GeoCorrelator(self._settings)

    async def run(
        self,
        file_bytes: bytes,
        filename: str,
        progress_callback: Callable[[int, str], None] | None = None,
    ) -> AlertBundle:
        """
        Exécute le pipeline M2 complet de manière asynchrone.

        Args:
            file_bytes: Contenu brut du fichier PCAP.
            filename: Nom du fichier PCAP.
            progress_callback: Callback (pct: int, stage: str) pour la progression.

        Returns:
            AlertBundle contenant toutes les alertes détectées.

        Raises:
            PCAPEmptyError: Si le PCAP est vide.
            PCAPTooLargeError: Si le PCAP dépasse la limite.
            PCAPParsingError: Si le PCAP est invalide.
        """
        start_time = time.perf_counter()

        def _report(pct: int, stage: str) -> None:
            if progress_callback:
                progress_callback(pct, stage)
            self._logger.info("pipeline_stage", stage=stage, progress=pct)

        # ── STAGE 1 : VALIDATION ─────────────────────────────────────────────
        _report(5, "Validation du PCAP")
        self.pcap_parser.validate(file_bytes, filename)
        sha256 = self.pcap_parser.compute_sha256(file_bytes)

        # ── STAGE 2 : PARSING ────────────────────────────────────────────────
        _report(20, "Parsing des paquets PCAP")
        packets: list[tuple[float, bytes, int]] = []
        loop = asyncio.get_event_loop()
        try:
            raw_packets = await loop.run_in_executor(
                None, lambda: list(self.pcap_parser.stream_packets(file_bytes))
            )
            for ts, buf, ltype in raw_packets:
                packets.append((ts, buf, ltype))
                if len(packets) >= self.options.max_flows * 10:
                    self._logger.warning("pcap_packet_limit_reached", limit=len(packets))
                    break
        except Exception as e:
            raise PCAPParsingError(f"Parsing error: {e}", "PCAP_PARSING_ERROR")

        total_packets = len(packets)

        # ── STAGE 3 : FLOW BUILD ─────────────────────────────────────────────
        _report(40, "Reconstruction des flux réseau")
        flows = []
        try:
            builder = FlowBuilder()
            for ts, buf, ltype in packets:
                builder.process_packet(ts, buf, ltype)
                if len(builder._flows) > self.options.max_flows:
                    self._logger.warning("flow_limit_reached")
                    break
            flows = builder.finalize()
        except Exception as e:
            self._logger.error("flow_build_failed", error=str(e))

        # ── STAGE 4 : DETECTION ──────────────────────────────────────────────
        _report(65, "Détection C2")
        all_alerts = []
        timeout_per_detector = max(
            10.0,
            self.options.analysis_timeout_seconds / max(1, len(self.detectors))
        )
        for detector in self.detectors:
            try:
                detector_alerts = await asyncio.wait_for(
                    loop.run_in_executor(None, detector.detect, flows),
                    timeout=timeout_per_detector,
                )
                all_alerts.extend(detector_alerts)
                self._logger.info(
                    "detector_completed",
                    detector=detector.detector_name,
                    alerts=len(detector_alerts),
                )
            except asyncio.TimeoutError:
                self._logger.warning("detector_timeout", detector=detector.detector_name)
            except Exception as e:
                self._logger.error("detector_error", detector=detector.detector_name, error=str(e))

        # ── STAGE 5 : CORRELATION + SCORING ──────────────────────────────────
        _report(80, "Corrélation IOC M1 + Agrégation scores")
        try:
            ioc_alerts = await loop.run_in_executor(
                None, self.ioc_correlator.correlate, flows, all_alerts
            )
            all_alerts.extend(ioc_alerts)
            all_alerts = [
                a for a in all_alerts
                if a.confidence_score >= self.options.min_confidence_threshold
            ]
            all_alerts = self.scorer.aggregate_alerts(all_alerts)
        except Exception as e:
            self._logger.error("correlation_error", error=str(e))

        # ── STAGE 6 : BUNDLE ─────────────────────────────────────────────────
        _report(100, "Construction du bundle final")
        duration_ms = int((time.perf_counter() - start_time) * 1000)

        type_counter: Counter[str] = Counter(a.alert_type.value for a in all_alerts)
        sev_counter: Counter[str] = Counter(a.severity.value for a in all_alerts)

        ip_scores: dict[str, int] = {}
        for alert in all_alerts:
            ip_scores[alert.dst_ip] = max(ip_scores.get(alert.dst_ip, 0), alert.confidence_score)
        top_ips = sorted(ip_scores, key=lambda ip: ip_scores[ip], reverse=True)[:10]

        bundle = AlertBundle(
            pcap_filename=filename,
            pcap_sha256=sha256,
            pcap_size_bytes=len(file_bytes),
            analysis_duration_ms=duration_ms,
            total_packets=total_packets,
            total_flows=len(flows),
            alerts=all_alerts,
            alerts_by_type=dict(type_counter),
            alerts_by_severity=dict(sev_counter),
            top_suspicious_ips=top_ips,
            m1_bundle_id=str(self.ioc_correlator.bundle_id) if self.ioc_correlator.bundle_id else None,
            ioc_hits=len([a for a in all_alerts if a.alert_type == AlertType.IOC_MATCH]),
        )

        self._logger.info(
            "pipeline_completed",
            filename=filename,
            total_alerts=len(all_alerts),
            duration_ms=duration_ms,
            total_flows=len(flows),
        )
        return bundle
