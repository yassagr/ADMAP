"""
Module   : admap_m2.analyzers.traffic_profiler
Version  : 1.0.0
Dépend   : [admap_m2.models.flow]
"""
from __future__ import annotations

from collections import Counter

from admap_m2.models.flow import FlowStats, NetworkFlow, Protocol


class TrafficProfiler:
    """
    Profile globalement le trafic réseau et extrait des statistiques (FlowStats).
    """

    def profile(self, flows: list[NetworkFlow]) -> FlowStats:
        stats = FlowStats()
        stats.total_flows = len(flows)
        
        src_ips = set()
        dst_ips = set()
        dst_ports_counter = Counter()
        dst_ips_counter = Counter()
        
        for flow in flows:
            src_ips.add(flow.src_ip)
            dst_ips.add(flow.dst_ip)
            dst_ports_counter[flow.dst_port] += 1
            dst_ips_counter[flow.dst_ip] += 1

            if flow.protocol == Protocol.TCP:
                stats.tcp_flows += 1
            elif flow.protocol == Protocol.UDP:
                stats.udp_flows += 1

            stats.dns_queries_total += len(flow.dns_queries)
            stats.http_requests_total += len(flow.http_requests)
            if flow.tls_info:
                stats.tls_sessions_total += 1

        stats.unique_src_ips = len(src_ips)
        stats.unique_dst_ips = len(dst_ips)
        stats.unique_dst_ports = len(dst_ports_counter)

        stats.top_dst_ips = dst_ips_counter.most_common(10)
        stats.top_dst_ports = dst_ports_counter.most_common(10)

        return stats
