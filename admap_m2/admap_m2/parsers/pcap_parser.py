"""
Module   : admap_m2.parsers.pcap_parser
Version  : 1.0.0
Dépend   : [dpkt, scapy (optionnel), admap_m2.models.flow]
"""
from __future__ import annotations

import hashlib
import io
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import ClassVar, Generator

import dpkt

from admap_m2.core.exceptions import PCAPParsingError, PCAPEmptyError, PCAPTooLargeError
from admap_m2.core.logging import get_logger
from admap_m2.models.flow import NetworkFlow, Protocol


try:
    from scapy.all import rdpcap, Scapy_Exception
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False


class PCAPParser:
    """
    Parser de fichiers PCAP.
    Utilise dpkt en mode stream (économie mémoire).
    Fallback vers scapy si dpkt échoue.
    Supporte PCAP classique (.pcap) et PCAP-NG (.pcapng).
    """

    MAX_PCAP_SIZE: ClassVar[int] = 500 * 1024 * 1024  # 500 MB
    SUPPORTED_MAGIC: ClassVar[set[bytes]] = {
        b'\xd4\xc3\xb2\xa1',  # PCAP little-endian
        b'\xa1\xb2\xc3\xd4',  # PCAP big-endian
        b'\x0a\x0d\x0d\x0a',  # PCAP-NG
        b'\xa1\xb2\x3c\x4d',  # PCAP nanosecond
    }

    def __init__(self) -> None:
        self._logger = get_logger("parsers.pcap")

    def validate(self, file_bytes: bytes, filename: str) -> None:
        """
        Valide un PCAP avant analyse.
        Lève PCAPTooLargeError, PCAPEmptyError, PCAPParsingError.
        """
        if len(file_bytes) == 0:
            raise PCAPEmptyError("PCAP file is empty", "PCAP_EMPTY")
        if len(file_bytes) > self.MAX_PCAP_SIZE:
            raise PCAPTooLargeError(
                f"PCAP exceeds {self.MAX_PCAP_SIZE // (1024*1024)} MB",
                "PCAP_TOO_LARGE",
                {"size_mb": len(file_bytes) // (1024 * 1024)}
            )
        magic = file_bytes[:4]
        if magic not in self.SUPPORTED_MAGIC:
            raise PCAPParsingError(
                f"Invalid PCAP magic bytes: {magic.hex()}",
                "PCAP_INVALID_MAGIC",
                {"magic": magic.hex(), "filename": filename}
            )

    def compute_sha256(self, file_bytes: bytes) -> str:
        """Calcule le SHA256 du PCAP."""
        return hashlib.sha256(file_bytes).hexdigest()

    def stream_packets(
        self,
        file_bytes: bytes,
    ) -> Generator[tuple[float, bytes, int], None, None]:
        """
        Génère les paquets bruts depuis le PCAP en mode stream.

        Yields:
            (timestamp_float, raw_packet_bytes, link_type)
        """
        try:
            fobj = io.BytesIO(file_bytes)
            pcap = dpkt.pcap.Reader(fobj)
            link_type = pcap.datalink()
            for ts, buf in pcap:
                yield (ts, buf, link_type)
        except Exception as e:
            if SCAPY_AVAILABLE:
                self._logger.warning("dpkt_failed_using_scapy", error=str(e))
                yield from self._stream_via_scapy(file_bytes)
            else:
                raise PCAPParsingError(
                    f"PCAP parsing failed: {e}",
                    "PCAP_PARSING_ERROR",
                    {"error": str(e)}
                )

    def _stream_via_scapy(
        self,
        file_bytes: bytes,
    ) -> Generator[tuple[float, bytes, int], None, None]:
        """Fallback scapy pour les PCAP non supportés par dpkt."""
        try:
            from scapy.all import PcapReader
            from io import BytesIO
            for pkt in PcapReader(BytesIO(file_bytes)):
                ts = float(pkt.time)
                raw = bytes(pkt)
                yield (ts, raw, 1)  # link_type=1 (Ethernet) par défaut
        except Exception as e:
            raise PCAPParsingError(f"Scapy fallback failed: {e}", "PCAP_SCAPY_FAILED")

    def count_packets(self, file_bytes: bytes) -> int:
        """Compte rapidement les paquets sans les analyser."""
        count = 0
        for _ in self.stream_packets(file_bytes):
            count += 1
        return count
