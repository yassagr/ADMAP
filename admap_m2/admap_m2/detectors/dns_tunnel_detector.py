"""
Module   : admap_m2.detectors.dns_tunnel_detector
Version  : 1.0.0
Dépend   : [math, collections, admap_m2.detectors.base,
            admap_m2.models.alert, admap_m2.models.flow]
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from typing import ClassVar

from admap_m2.detectors.base import BaseDetector
from admap_m2.models.alert import AlertType, C2Alert
from admap_m2.models.flow import DNSQuery, NetworkFlow


class DNSTunnelDetector(BaseDetector):
    """
    Détecte le tunneling DNS (exfiltration de données ou C2).

    Indicateurs :
    1. Sous-domaines très longs (données encodées Base32/Base64)
    2. Volume élevé de requêtes vers un même domaine racine
    3. Types de requêtes inhabituels (TXT, NULL)
    4. Haute entropie des labels de sous-domaines
    5. Forte diversité des sous-domaines (chaque requête = payload différent)
    """

    TUNNEL_QUERY_TYPES: ClassVar[set[str]] = {"TXT", "MX", "NULL", "CNAME", "A"}

    @property
    def detector_name(self) -> str:
        return "dns_tunnel"

    def detect(self, flows: list[NetworkFlow]) -> list[C2Alert]:
        """
        Détecte le tunneling DNS dans les flux.

        Args:
            flows: Liste des flux réseau.

        Returns:
            Liste de C2Alert de type DNS_TUNNEL.
        """
        alerts: list[C2Alert] = []
        domain_queries: dict[str, list[tuple[NetworkFlow, DNSQuery]]] = defaultdict(list)

        for flow in flows:
            for dns_query in flow.dns_queries:
                root = self._extract_root_domain(dns_query.query_name)
                domain_queries[root].append((flow, dns_query))

        for root_domain, query_pairs in domain_queries.items():
            if len(query_pairs) < self._settings.DNS_TUNNEL_MIN_QUERIES:
                continue

            queries = [q for _, q in query_pairs]
            representative_flow = query_pairs[0][0]

            score, evidence = self._analyze_queries(root_domain, queries)
            if score >= 20:
                alerts.append(self._build_alert(
                    representative_flow,
                    AlertType.DNS_TUNNEL,
                    score,
                    f"DNS tunneling suspected to {root_domain}: {len(queries)} queries",
                    evidence,
                    metadata={
                        "root_domain": root_domain,
                        "query_count": len(queries),
                        "unique_subdomains": len(set(q.query_name for q in queries)),
                    },
                ))

        return alerts

    def _analyze_queries(
        self, root_domain: str, queries: list[DNSQuery]
    ) -> tuple[int, list[str]]:
        """
        Analyse un ensemble de requêtes DNS vers un domaine racine.

        Args:
            root_domain: Domaine racine (eTLD+1).
            queries: Liste des requêtes DNS.

        Returns:
            Tuple (score_0_100, liste_evidence).
        """
        score = 0
        evidence: list[str] = []

        # 1. Longueur moyenne des requêtes
        avg_len = sum(len(q.query_name) for q in queries) / len(queries)
        if avg_len >= self._settings.DNS_TUNNEL_QUERY_LENGTH:
            score += 25
            evidence.append(
                f"Avg query length: {avg_len:.1f} chars "
                f"(threshold: {self._settings.DNS_TUNNEL_QUERY_LENGTH})"
            )

        # 2. Entropie moyenne des sous-domaines
        labels = [
            q.query_name.replace(f".{root_domain}", "").rstrip(".")
            for q in queries
        ]
        valid_labels = [lb for lb in labels if lb]
        if valid_labels:
            avg_entropy = sum(
                self._shannon_entropy(lb) for lb in valid_labels
            ) / len(valid_labels)
            if avg_entropy > 3.5:
                score += 20
                evidence.append(f"High avg subdomain entropy: {avg_entropy:.2f}")

        # 3. Diversité des sous-domaines
        unique_subdomains = len(set(q.query_name for q in queries))
        diversity_ratio = unique_subdomains / len(queries)
        if diversity_ratio > 0.9:
            score += 15
            evidence.append(f"High subdomain diversity: {diversity_ratio:.2f}")

        # 4. Types de requêtes suspects
        query_types = {q.query_type for q in queries}
        tunnel_types = query_types & self.TUNNEL_QUERY_TYPES
        if "TXT" in tunnel_types or "NULL" in tunnel_types:
            score += 20
            evidence.append(f"Suspicious query types: {tunnel_types}")

        # 5. Volume élevé
        if len(queries) >= 100:
            score += 20
            evidence.append(f"High volume: {len(queries)} queries")
        elif len(queries) >= 50:
            score += 10
            evidence.append(f"Elevated volume: {len(queries)} queries")

        return min(100, score), evidence

    @staticmethod
    def _extract_root_domain(fqdn: str) -> str:
        """
        Extrait le domaine racine (eTLD+1) d'un FQDN.

        Args:
            fqdn: Nom de domaine pleinement qualifié.

        Returns:
            Domaine racine (ex: 'evil.com' depuis 'sub.evil.com').
        """
        parts = fqdn.rstrip(".").split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return fqdn

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """
        Calcule l'entropie de Shannon d'une chaîne.

        Args:
            text: Chaîne à analyser.

        Returns:
            Entropie en bits.
        """
        if not text:
            return 0.0
        freq = Counter(text)
        n = len(text)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())
