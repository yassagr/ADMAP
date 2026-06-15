from __future__ import annotations
import uuid
import structlog
from datetime import datetime, timezone
from admap_m4.models.ttp import TTPVector, TTPProfile
from admap_m4.models.cluster import CampaignCluster, ClusterBundle
from admap_m4.core.tfidf_vectorizer import ManualTFIDFVectorizer
from admap_m4.config import Settings

logger = structlog.get_logger(__name__)

class ManualDBSCANClusterer:
    """
    DBSCAN implémenté manuellement — ZÉRO scikit-learn.

    Algorithme :
    1. Pour chaque point P non visité :
       a. Marquer P comme visité.
       b. Trouver tous les voisins Q tels que cosine_similarity(P, Q) >= (1 - epsilon)
          (epsilon = distance max, ici on travaille en similarité donc seuil = 1 - epsilon).
       c. Si |voisins| < min_samples : marquer P comme bruit (label=-1).
       d. Sinon : créer un nouveau cluster, étendre récursivement.

    Note : on utilise la DISTANCE cosinus = 1 - similarité cosinus.
    Deux points sont voisins si leur distance cosinus <= epsilon.
    Soit similarité >= 1 - epsilon.
    """

    @property
    def clusterer_name(self) -> str:
        return "ManualDBSCANClusterer"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._log = structlog.get_logger(self.__class__.__name__)

    def cluster(
        self,
        vectors: list[TTPVector],
        profiles: list[TTPProfile],
        epsilon: float | None = None,
        min_samples: int | None = None,
    ) -> ClusterBundle:
        """
        Applique DBSCAN sur les TTPVectors.

        Args:
            vectors: liste de TTPVector (sortie de ManualTFIDFVectorizer).
            profiles: liste de TTPProfile correspondants (même ordre que vectors).
            epsilon: distance cosinus max pour être voisin (default: settings.dbscan_epsilon).
            min_samples: nombre minimum de voisins pour être un core point.

        Returns:
            ClusterBundle avec tous les CampaignCluster.
        """
        eps = epsilon if epsilon is not None else self._settings.dbscan_epsilon
        min_s = min_samples if min_samples is not None else self._settings.dbscan_min_samples
        n = len(vectors)

        if n == 0:
            return ClusterBundle(
                bundle_id=str(uuid.uuid4()),
                source_bundle_id="",
                clusters=[],
                noise_profile_ids=[],
                total_profiles=0,
                total_clusters=0,
                noise_count=0,
                created_at=datetime.now(timezone.utc),
            )

        # Matrice de similarité (n x n), calculée manuellement
        sim: list[list[float]] = []
        for i in range(n):
            row: list[float] = []
            for j in range(n):
                if i == j:
                    row.append(1.0)
                else:
                    row.append(ManualTFIDFVectorizer.cosine_similarity(vectors[i], vectors[j]))
            sim.append(row)

        # DBSCAN
        labels: list[int] = [-1] * n
        visited: list[bool] = [False] * n
        cluster_id = 0

        for i in range(n):
            if visited[i]:
                continue
            visited[i] = True

            neighbors = self._get_neighbors(sim, i, eps, n)

            if len(neighbors) < min_s:
                labels[i] = -1  # bruit
            else:
                self._expand_cluster(sim, labels, visited, i, neighbors, cluster_id, eps, min_s, n)
                cluster_id += 1

        # Construction des CampaignCluster
        clusters = self._build_clusters(labels, vectors, profiles, cluster_id)
        noise_ids = [
            vectors[i].profile_id
            for i in range(n)
            if labels[i] == -1
        ]

        self._log.info(
            "dbscan_complete",
            n_profiles=n,
            n_clusters=cluster_id,
            n_noise=len(noise_ids),
            epsilon=eps,
            min_samples=min_s,
        )

        return ClusterBundle(
            bundle_id=str(uuid.uuid4()),
            source_bundle_id="",
            clusters=clusters,
            noise_profile_ids=noise_ids,
            total_profiles=n,
            total_clusters=len(clusters),
            noise_count=len(noise_ids),
            created_at=datetime.now(timezone.utc),
        )

    def _get_neighbors(
        self,
        sim: list[list[float]],
        idx: int,
        eps: float,
        n: int,
    ) -> list[int]:
        """Retourne les indices des voisins de idx (similarité >= 1 - eps)."""
        threshold = 1.0 - eps
        return [j for j in range(n) if sim[idx][j] >= threshold]

    def _expand_cluster(
        self,
        sim: list[list[float]],
        labels: list[int],
        visited: list[bool],
        core_idx: int,
        neighbors: list[int],
        cluster_id: int,
        eps: float,
        min_samples: int,
        n: int,
    ) -> None:
        """Étend le cluster à partir d'un core point."""
        labels[core_idx] = cluster_id
        queue: list[int] = list(neighbors)
        processed: set[int] = {core_idx}

        while queue:
            q = queue.pop(0)
            if q in processed:
                continue
            processed.add(q)

            if not visited[q]:
                visited[q] = True
                q_neighbors = self._get_neighbors(sim, q, eps, n)
                if len(q_neighbors) >= min_samples:
                    queue.extend([nb for nb in q_neighbors if nb not in processed])

            if labels[q] == -1:
                labels[q] = cluster_id

    def _build_clusters(
        self,
        labels: list[int],
        vectors: list[TTPVector],
        profiles: list[TTPProfile],
        n_clusters: int,
    ) -> list[CampaignCluster]:
        """Construit les CampaignCluster depuis les labels DBSCAN."""
        clusters: list[CampaignCluster] = []

        for cid in range(n_clusters):
            indices = [i for i, lbl in enumerate(labels) if lbl == cid]
            if not indices:
                continue

            member_ids = [vectors[i].profile_id for i in indices]
            member_profiles = [profiles[i] for i in indices]

            # Techniques dominantes (top 5 par fréquence)
            tech_count: dict[str, int] = {}
            tactic_count: dict[str, int] = {}
            ips: set[str] = set()
            yara_tags: set[str] = set()
            timestamps: list[datetime] = []

            for p in member_profiles:
                for t in p.techniques:
                    tech_count[t] = tech_count.get(t, 0) + 1
                for tac in p.tactics:
                    tactic_count[tac] = tactic_count.get(tac, 0) + 1
                ips.add(p.src_ip)
                ips.add(p.dst_ip)
                yara_tags.update(p.yara_tags)
                timestamps.append(p.timestamp)

            dominant_techniques = sorted(tech_count, key=lambda t: -tech_count[t])[:5]
            dominant_tactics = sorted(tactic_count, key=lambda t: -tactic_count[t])

            # Score de confiance calculé dynamiquement
            avg_confidence = sum(p.confidence_score for p in member_profiles) / len(member_profiles)
            cluster_density = min(1.0, len(member_profiles) / max(1, len(labels)))
            dynamic_score = min(100.0, avg_confidence * 0.7 + cluster_density * 30.0)

            clusters.append(CampaignCluster(
                cluster_id=str(uuid.uuid4()),
                cluster_label=cid,
                member_profile_ids=member_ids,
                dominant_techniques=dominant_techniques,
                dominant_tactics=dominant_tactics,
                confidence_score=round(dynamic_score, 2),
                involved_ips=sorted(ips - {""}),
                yara_tags=sorted(yara_tags),
                first_seen=min(timestamps),
                last_seen=max(timestamps),
                metadata={
                    "technique_counts": tech_count,
                    "tactic_counts": tactic_count,
                    "member_count": len(member_profiles),
                },
            ))

        return clusters
