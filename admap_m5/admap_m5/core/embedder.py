from __future__ import annotations
import math
from collections import Counter
import structlog

logger = structlog.get_logger(__name__)


class CosineEmbedder:
    """Calcule des vecteurs TF-IDF et la similarité cosinus entre TTPs.
    
    Implémentation 100% Python standard, zéro dépendance scikit-learn.
    Formule IDF : log((1 + N) / (1 + df)) + 1 (smooth IDF, identique à sklearn).
    """

    def __init__(self) -> None:
        self._vocabulary: dict[str, int] = {}
        self._idf: dict[str, float] = {}
        self._fitted: bool = False

    def fit(self, documents: list[list[str]]) -> None:
        """Ajuste le vocabulaire et calcule les IDF sur un corpus de documents.
        
        Chaque document est une liste de tokens (techniques/tactiques MITRE).
        """
        if not documents:
            logger.warning("embedder.fit_empty_corpus")
            return

        n = len(documents)
        df: Counter[str] = Counter()
        vocab: set[str] = set()

        for doc in documents:
            unique_tokens = set(doc)
            vocab.update(unique_tokens)
            for token in unique_tokens:
                df[token] += 1

        self._vocabulary = {token: idx for idx, token in enumerate(sorted(vocab))}
        self._idf = {
            token: math.log((1 + n) / (1 + df_val)) + 1.0
            for token, df_val in df.items()
        }
        self._fitted = True
        logger.info("embedder.fitted", vocab_size=len(self._vocabulary), n_docs=n)

    def transform(self, tokens: list[str]) -> list[float]:
        """Transforme une liste de tokens en vecteur TF-IDF normalisé.
        
        Retourne un vecteur de taille len(vocabulary), normalisé L2.
        """
        if not self._fitted:
            raise RuntimeError("CosineEmbedder.fit() must be called before transform()")

        tf: Counter[str] = Counter(tokens)
        size = len(self._vocabulary)
        vector = [0.0] * size

        for token, tf_val in tf.items():
            if token in self._vocabulary:
                idx = self._vocabulary[token]
                idf_val = self._idf.get(token, 1.0)
                vector[idx] = tf_val * idf_val

        # Normalisation L2
        norm = math.sqrt(sum(v * v for v in vector))
        if norm > 0:
            vector = [v / norm for v in vector]

        return vector

    @staticmethod
    def cosine_similarity(v1: list[float], v2: list[float]) -> float:
        """Calcule la similarité cosinus entre deux vecteurs.
        
        Retourne 0.0 si l'un des vecteurs est nul.
        Lève ValueError si les vecteurs n'ont pas la même dimension.
        """
        if len(v1) != len(v2):
            raise ValueError(f"Vector dimension mismatch: {len(v1)} vs {len(v2)}")

        dot = sum(a * b for a, b in zip(v1, v2))
        norm1 = math.sqrt(sum(a * a for a in v1))
        norm2 = math.sqrt(sum(b * b for b in v2))

        if norm1 == 0.0 or norm2 == 0.0:
            return 0.0

        return max(0.0, min(1.0, dot / (norm1 * norm2)))
