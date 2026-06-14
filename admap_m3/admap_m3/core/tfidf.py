"""
Module   : admap_m3.core.tfidf
Version  : 1.0.0
Dépend   : [collections, math, structlog, admap_m3.models.token]

Moteur TF-IDF discriminant MANUEL.  Aucun import de scikit-learn.

L'algorithme calcule pour chaque token *t* :
  μ_malware(t) = moyenne des tf(t, d) sur les documents malware contenant *t*
  max_benign(t) = max des tf(t, d) sur les documents bénins contenant *t*
  Δ(t)          = μ_malware(t) − max_benign(t)
"""
from __future__ import annotations

import collections

import structlog

from admap_m3.config import Settings
from admap_m3.models.token import TokenFeature

logger: structlog.stdlib.BoundLogger = structlog.get_logger()


class TFIDFEngine:
    """Moteur TF-IDF discriminant implémenté manuellement.

    Pas d'IDF classique — seuls les TF moyens (malware) et le TF max
    (bénin) sont utilisés pour calculer le score discriminant Δ.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings: Settings = settings

    def compute_corpus_tfidf(
        self,
        malware_token_lists: list[list[str]],
        benign_token_lists: list[list[str]],
        corpus_id: str,
    ) -> list[TokenFeature]:
        """Calcule les features TF-IDF discriminantes du corpus.

        Algorithme (6 étapes, zéro déviation) :

        1. Pour chaque document malware *d*, calculer tf(t, d) =
           count(t, d) / len(d).
        2. μ_malware(t) = mean(tf(t, d) pour d dans malware contenant t).
           Si absent de tout malware : μ = 0.0.
        3. max_benign(t) = max(tf(t, d) pour d dans bénin contenant t).
           Si absent de tout bénin : max_benign = 0.0.
        4. Δ(t) = μ_malware(t) − max_benign(t).
        5. df_malware(t) = nb de fichiers malware contenant t.
           df_benign(t)  = nb de fichiers bénins contenant t.
        6. Retourner un ``TokenFeature`` pour chaque token présent dans au
           moins un document malware.

        Args:
            malware_token_lists: Liste de listes de tokens malware.
            benign_token_lists: Liste de listes de tokens bénins.
            corpus_id: Identifiant du corpus.

        Returns:
            Liste de ``TokenFeature`` pour tous les tokens vus dans ≥ 1
            document malware.
        """
        if not malware_token_lists:
            return []

        # ── Étape 1 : TF par document malware ───────────────────────────
        malware_tf_docs: list[dict[str, float]] = []
        for token_list in malware_token_lists:
            malware_tf_docs.append(self._compute_tf(token_list))

        # ── TF par document bénin ────────────────────────────────────────
        benign_tf_docs: list[dict[str, float]] = []
        for token_list in benign_token_lists:
            benign_tf_docs.append(self._compute_tf(token_list))

        # Collecter tous les tokens présents dans au moins 1 doc malware
        all_malware_tokens: set[str] = set()
        for tf_doc in malware_tf_docs:
            all_malware_tokens.update(tf_doc.keys())

        # ── Étapes 2-5 : calculer les métriques par token ───────────────
        features: list[TokenFeature] = []

        for token in all_malware_tokens:
            # Étape 2 : μ_malware
            tf_values_malware: list[float] = [
                doc[token] for doc in malware_tf_docs if token in doc
            ]
            tf_malware_mean: float = (
                sum(tf_values_malware) / len(tf_values_malware)
                if tf_values_malware
                else 0.0
            )

            # Étape 3 : max_benign
            tf_values_benign: list[float] = [
                doc[token] for doc in benign_tf_docs if token in doc
            ]
            tf_benign_max: float = max(tf_values_benign) if tf_values_benign else 0.0

            # Étape 4 : Δ
            delta_score: float = tf_malware_mean - tf_benign_max

            # Étape 5 : df
            df_malware: int = sum(1 for doc in malware_tf_docs if token in doc)
            df_benign: int = sum(1 for doc in benign_tf_docs if token in doc)

            # Déterminer le type de token heuristiquement
            token_type: str = self._infer_token_type(token)

            # Étape 6 : construire le TokenFeature
            features.append(
                TokenFeature(
                    token=token,
                    token_type=token_type,
                    tf_malware=tf_malware_mean,
                    tf_benign_max=tf_benign_max,
                    delta_score=delta_score,
                    df_malware=df_malware,
                    df_benign=df_benign,
                    corpus_id=corpus_id,
                )
            )

        logger.info(
            "tfidf_computation_complete",
            corpus_id=corpus_id,
            total_tokens=len(features),
            malware_docs=len(malware_token_lists),
            benign_docs=len(benign_token_lists),
        )

        return features

    def _compute_tf(self, token_list: list[str]) -> dict[str, float]:
        """Calcule les term-frequency relatives pour un document.

        tf(t, d) = count(t, d) / len(d)
        """
        if not token_list:
            return {}

        counter: dict[str, int] = self._tokenize(token_list)
        total: int = len(token_list)
        return {token: count / total for token, count in counter.items()}

    def _tokenize(self, token_list: list[str]) -> dict[str, int]:
        """Compteur simple : ``{token: count}``."""
        return dict(collections.Counter(token_list))

    def _infer_token_type(self, token: str) -> str:
        """Infère le type de token d'après son contenu.

        - Que des caractères hex majuscules et longueur exacte
          ``ngram_size * 2`` → ``opcode_ngram``.
        - Que des caractères hex → ``hex_pattern``.
        - Préfixe ``m1_ioc:`` → ``m1_ioc``.
        - Sinon → ``string``.
        """
        if token.startswith("m1_ioc:"):
            return "m1_ioc"

        hex_chars: set[str] = set("0123456789ABCDEFabcdef")
        if all(c in hex_chars for c in token):
            expected_ngram_len: int = self._settings.ngram_size * 2
            if len(token) == expected_ngram_len:
                return "opcode_ngram"
            return "hex_pattern"

        return "string"
