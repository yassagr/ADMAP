"""
Module   : admap_m2.parsers.flow_builder
Version  : 1.0.0
Dépend   : [dpkt, admap_m2.models.flow]
"""
from __future__ import annotations

import socket
import struct
from collections import defaultdict
from datetime import datetime, timezone
from typing import ClassVar

import dpkt

from admap_m2.models.flow import (
    DNSQuery, HTTPRequest, NetworkFlow, Protocol, TLSInfo
)

# Clé de flux : (src_ip, dst_ip, src_port, dst_port, proto)
FlowKey = tuple[str, str, int, int, str]


class FlowBuilder:
    """
    Reconstruit les flux réseau depuis des paquets bruts.

    Un flux est défini par le 5-tuple :
    (src_ip, dst_ip, src_port, dst_port, protocole).
    Les flux bidirectionnels sont normalisés :
    la src_ip est toujours la plus petite IP (canonique).
    """

    FLOW_TIMEOUT_SECONDS: ClassVar[float] = 300.0  # 5 minutes sans paquet → fin de flux
    MAX_PAYLOAD_SAMPLE: ClassVar[int] = 256         # Bytes de payload à conserver
    MAX_INTERVALS: ClassVar[int] = 1000             # Max intervalles pour beaconing

    # Ports applicatifs connus
    PORT_PROTOCOLS: ClassVar[dict[int, Protocol]] = {
        53:   Protocol.DNS,
        80:   Protocol.HTTP,
        443:  Protocol.TLS,
        8080: Protocol.HTTP,
        8443: Protocol.TLS,
        6667: Protocol.IRC,
        6668: Protocol.IRC,
        6669: Protocol.IRC,
        7000: Protocol.IRC,
        21:   Protocol.FTP,
        25:   Protocol.SMTP,
        587:  Protocol.SMTP,
    }

    def __init__(self) -> None:
        self._flows: dict[FlowKey, NetworkFlow] = {}
        self._last_seen: dict[FlowKey, float] = {}
        self._completed_flows: list[NetworkFlow] = []

    def process_packet(
        self,
        timestamp: float,
        raw_bytes: bytes,
        link_type: int = 1,  # 1 = Ethernet
    ) -> None:
        """
        Traite un paquet brut et met à jour les flux.

        Args:
            timestamp: Timestamp Unix du paquet.
            raw_bytes: Contenu brut du paquet.
            link_type: Type de lien PCAP (1=Ethernet, 113=Linux cooked).
        """
        try:
            eth = self._parse_ethernet(raw_bytes, link_type)
            if eth is None:
                return

            ip = self._extract_ip(eth)
            if ip is None:
                return

            src_ip = self._ip_to_str(ip.src)
            dst_ip = self._ip_to_str(ip.dst)
            proto, src_port, dst_port, payload = self._extract_transport(ip)

            if proto is None:
                return

            key = self._make_flow_key(src_ip, dst_ip, src_port, dst_port, proto)
            dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)

            if key in self._flows:
                flow = self._flows[key]
                # Vérifier timeout
                if timestamp - self._last_seen[key] > self.FLOW_TIMEOUT_SECONDS:
                    self._completed_flows.append(flow)
                    del self._flows[key]
                    flow = self._create_flow(key, dt, proto, payload)
                    self._flows[key] = flow
                else:
                    self._update_flow(flow, key, src_ip, timestamp, dt, payload)
            else:
                flow = self._create_flow(key, dt, proto, payload)
                self._flows[key] = flow

            self._last_seen[key] = timestamp

            # Extraction données applicatives
            if proto == Protocol.DNS or dst_port == 53 or src_port == 53:
                self._extract_dns(flow, payload, dt)
            elif proto in (Protocol.HTTP, Protocol.TLS) and payload:
                self._extract_http_tls(flow, payload, dst_port, dt)

        except Exception:
            pass  # Paquet malformé → ignorer silencieusement

    def finalize(self) -> list[NetworkFlow]:
        """Finalise tous les flux ouverts et retourne la liste complète."""
        all_flows = self._completed_flows + list(self._flows.values())
        self._flows.clear()
        self._last_seen.clear()
        self._completed_flows.clear()
        return all_flows

    def _make_flow_key(
        self, src_ip: str, dst_ip: str,
        src_port: int, dst_port: int, proto: Protocol
    ) -> FlowKey:
        """
        Normalise la clé de flux (bidirectionnel).
        Toujours : (ip_min, ip_max, port_min, port_max, proto) si bidirectionnel.
        Pour les flux client→serveur : (src_ip, dst_ip, src_port, dst_port).
        On utilise dst_port comme discriminant (le serveur a le port connu).
        """
        if dst_port in self.PORT_PROTOCOLS or dst_port < 1024:
            return (src_ip, dst_ip, src_port, dst_port, proto.value)
        if src_port in self.PORT_PROTOCOLS or src_port < 1024:
            return (dst_ip, src_ip, dst_port, src_port, proto.value)
        # Si aucun port connu, le port le plus bas est probablement le serveur
        if src_port > dst_port:
            return (src_ip, dst_ip, src_port, dst_port, proto.value)
        return (dst_ip, src_ip, dst_port, src_port, proto.value)

    def _create_flow(
        self, key: FlowKey, dt: datetime, proto: Protocol, payload: bytes
    ) -> NetworkFlow:
        """Crée un nouveau NetworkFlow depuis une clé."""
        src_ip, dst_ip, src_port, dst_port, _ = key
        detected_proto = self.PORT_PROTOCOLS.get(dst_port, proto)
        return NetworkFlow(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=detected_proto,
            first_seen=dt,
            last_seen=dt,
            packet_count=1,
            byte_count_src_to_dst=len(payload),
            payload_sample=payload[:self.MAX_PAYLOAD_SAMPLE] if payload else None,
        )

    def _update_flow(
        self, flow: NetworkFlow, key: FlowKey,
        src_ip: str, timestamp: float, dt: datetime, payload: bytes
    ) -> None:
        """Met à jour un flux existant (Pydantic frozen → object.__setattr__)."""
        object.__setattr__(flow, 'last_seen', dt)
        object.__setattr__(flow, 'packet_count', flow.packet_count + 1)
        object.__setattr__(flow, 'duration_ms',
            int((dt - flow.first_seen).total_seconds() * 1000))

        # Intervalles inter-paquets (pour beaconing)
        if len(flow.inter_packet_intervals) < self.MAX_INTERVALS:
            if flow.packet_count > 1:
                last_ts = flow.first_seen.timestamp() + sum(flow.inter_packet_intervals)
                interval = timestamp - last_ts
                if interval > 0:
                    flow.inter_packet_intervals.append(interval)

        # Comptage bytes
        src_key_ip = key[0]
        if src_ip == src_key_ip:
            object.__setattr__(flow, 'byte_count_src_to_dst',
                flow.byte_count_src_to_dst + len(payload))
        else:
            object.__setattr__(flow, 'byte_count_dst_to_src',
                flow.byte_count_dst_to_src + len(payload))

    def _parse_ethernet(self, raw: bytes, link_type: int) -> dpkt.ethernet.Ethernet | None:
        """Parse la couche Ethernet (ou Linux cooked capture)."""
        try:
            if link_type == 1:
                return dpkt.ethernet.Ethernet(raw)
            elif link_type == 113:  # Linux cooked
                return dpkt.ethernet.Ethernet(raw[2:])
            elif link_type == 228:  # Raw IPv4
                class FakeEth:
                    def __init__(self, r):
                        self.data = dpkt.ip.IP(r)
                return FakeEth(raw)
        except Exception:
            return None

    def _extract_ip(self, eth) -> dpkt.ip.IP | dpkt.ip6.IP6 | None:
        """Extrait la couche IP depuis Ethernet."""
        try:
            if isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                return eth.data
        except Exception:
            pass
        return None

    def _ip_to_str(self, ip_bytes: bytes) -> str:
        """Convertit bytes IP en string."""
        try:
            if len(ip_bytes) == 4:
                return socket.inet_ntoa(ip_bytes)
            elif len(ip_bytes) == 16:
                return socket.inet_ntop(socket.AF_INET6, ip_bytes)
        except Exception:
            return ip_bytes.hex()
        return ""

    def _extract_transport(
        self, ip
    ) -> tuple[Protocol | None, int, int, bytes]:
        """
        Extrait protocole, ports source/dest et payload.

        Returns:
            (protocol, src_port, dst_port, payload_bytes)
        """
        try:
            transport = ip.data
            if isinstance(transport, dpkt.tcp.TCP):
                return (Protocol.TCP, transport.sport, transport.dport, bytes(transport.data))
            elif isinstance(transport, dpkt.udp.UDP):
                return (Protocol.UDP, transport.sport, transport.dport, bytes(transport.data))
            elif isinstance(transport, dpkt.icmp.ICMP):
                return (Protocol.ICMP, 0, 0, b"")
        except Exception:
            pass
        return (None, 0, 0, b"")

    def _extract_dns(self, flow: NetworkFlow, payload: bytes, dt: datetime) -> None:
        """
        Extrait les requêtes/réponses DNS du payload.
        Gère DNS sur UDP (payload direct) et DNS sur TCP (2 bytes de longueur).
        """
        if not payload:
            return
        try:
            # DNS sur TCP : préfixé par 2 bytes de longueur
            dns_payload = payload
            if flow.protocol == Protocol.TCP and len(payload) > 2:
                length = struct.unpack('!H', payload[:2])[0]
                dns_payload = payload[2:2 + length]

            dns = dpkt.dns.DNS(dns_payload)
            for question in dns.qd:
                query_name = question.name if isinstance(question.name, str) else question.name.decode('utf-8', errors='replace')
                qtype = question.type

                response_ips: list[str] = []
                is_nxdomain = (dns.rcode == dpkt.dns.DNS_RCODE_NXDOMAIN)

                for answer in dns.an:
                    if answer.type == dpkt.dns.DNS_A:
                        response_ips.append(socket.inet_ntoa(answer.rdata))
                    elif answer.type == dpkt.dns.DNS_AAAA:
                        response_ips.append(
                            socket.inet_ntop(socket.AF_INET6, answer.rdata)
                        )

                dns_query = DNSQuery(
                    timestamp=dt,
                    query_name=query_name,
                    query_type=self._dns_type_name(qtype),
                    response_ips=response_ips,
                    ttl=dns.an[0].ttl if dns.an else 0,
                    is_nxdomain=is_nxdomain,
                )
                flow.dns_queries.append(dns_query)
        except Exception:
            pass

    def _extract_http_tls(
        self, flow: NetworkFlow, payload: bytes, dst_port: int, dt: datetime
    ) -> None:
        """Extrait requêtes HTTP ou infos TLS selon le port et le payload."""
        http_methods = (b'GET ', b'POST ', b'HEAD ', b'PUT ', b'DELETE ', b'PATCH ')
        is_http_payload = any(payload.startswith(m) for m in http_methods)
        
        if is_http_payload:
            self._parse_http(flow, payload, dt)
        elif dst_port in (443, 8443) or payload[:1] == b'\x16':
            self._parse_tls_hello(flow, payload)

    def _parse_http(self, flow: NetworkFlow, payload: bytes, dt: datetime) -> None:
        """Parse basique d'une requête HTTP."""
        try:
            lines = payload.split(b'\r\n')
            if not lines:
                return
            first_line = lines[0].decode('utf-8', errors='replace')
            parts = first_line.split(' ', 2)
            if len(parts) < 2:
                return
            method, uri = parts[0], parts[1]

            headers: dict[str, str] = {}
            host = ""
            ua = ""
            content_length = 0
            for line in lines[1:]:
                if b':' in line:
                    k, _, v = line.partition(b':')
                    key = k.strip().decode('utf-8', errors='replace').lower()
                    val = v.strip().decode('utf-8', errors='replace')
                    headers[key] = val
                    if key == 'host':
                        host = val
                    elif key == 'user-agent':
                        ua = val
                    elif key == 'content-length':
                        try:
                            content_length = int(val)
                        except ValueError:
                            pass

            http_req = HTTPRequest(
                timestamp=dt,
                method=method,
                host=host,
                uri=uri,
                user_agent=ua,
                content_length=content_length,
                headers=headers,
            )
            flow.http_requests.append(http_req)
        except Exception:
            pass

    def _parse_tls_hello(self, flow: NetworkFlow, payload: bytes) -> None:
        """
        Parse le ClientHello TLS pour extraire SNI et JA3.
        Format TLS record : type(1) + version(2) + length(2) + handshake...
        """
        try:
            if len(payload) < 5:
                return
            record_type = payload[0]
            if record_type != 0x16:  # Handshake
                return
            version = (payload[1] << 8) | payload[2]
            record_length = (payload[3] << 8) | payload[4]
            if len(payload) < 5 + record_length:
                return

            handshake = payload[5:5 + record_length]
            if not handshake:
                return
            handshake_type = handshake[0]
            if handshake_type != 1:  # ClientHello
                return

            # Extraire SNI (Server Name Indication)
            sni = self._extract_sni(handshake)

            if flow.tls_info is None:
                object.__setattr__(flow, 'tls_info', TLSInfo(sni=sni))
            else:
                object.__setattr__(flow.tls_info, 'sni', sni)
        except Exception:
            pass

    def _extract_sni(self, handshake: bytes) -> str:
        """Extrait le SNI depuis un ClientHello TLS."""
        try:
            # Offset dans ClientHello : type(1)+length(3)+version(2)+random(32)+
            # session_id_length(1)+session_id+cipher_suites_length(2)+
            # cipher_suites+compression_methods_length(1)+compression_methods
            # +extensions_length(2)+extensions
            pos = 4  # Après type + length
            pos += 2  # version
            pos += 32  # random
            session_id_len = handshake[pos]
            pos += 1 + session_id_len
            cipher_len = (handshake[pos] << 8) | handshake[pos + 1]
            pos += 2 + cipher_len
            comp_len = handshake[pos]
            pos += 1 + comp_len
            if pos + 2 > len(handshake):
                return ""
            ext_total_len = (handshake[pos] << 8) | handshake[pos + 1]
            pos += 2
            end = pos + ext_total_len
            while pos + 4 <= end:
                ext_type = (handshake[pos] << 8) | handshake[pos + 1]
                ext_len = (handshake[pos + 2] << 8) | handshake[pos + 3]
                pos += 4
                if ext_type == 0:  # SNI extension
                    # server_name_list_length(2) + type(1) + name_length(2) + name
                    sni_data = handshake[pos:pos + ext_len]
                    if len(sni_data) > 5:
                        name_len = (sni_data[3] << 8) | sni_data[4]
                        sni = sni_data[5:5 + name_len].decode('utf-8', errors='replace')
                        return sni
                pos += ext_len
        except Exception:
            pass
        return ""

    @staticmethod
    def _dns_type_name(qtype: int) -> str:
        types = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX",
                 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}
        return types.get(qtype, f"TYPE{qtype}")
