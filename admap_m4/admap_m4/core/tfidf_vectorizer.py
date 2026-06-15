from __future__ import annotations
import math
import structlog
from admap_m4.models.ttp import TTPProfile, TTPVector
from admap_m4.config import Settings

logger = structlog.get_logger(__name__)

class ManualTFIDFVectorizer:
    """
    TF-IDF implémenté manuellement — ZÉRO scikit-learn, ZÉRO numpy.

    Formules :
      TF(t, d)  = count(t in d) / len(d)
      IDF(t, D) = log((1 + |D|) / (1 + df(t))) + 1    [lissage sklearn-style]
      TF-IDF(t, d, D) = TF(t, d) * IDF(t, D)
      norm(d) = sqrt(sum(v^2 for v in d.values()))

    Le corpus = l'ensemble des TTPProfiles passés à fit().
    Chaque "document" = la liste de techniques d'un TTPProfile.
    """

    @property
    def vectorizer_name(self) -> str:
        return "ManualTFIDFVectorizer"

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._log = structlog.get_logger(self.__class__.__name__)
        self._idf: dict[str, float] = {}
        self._vocabulary: set[str] = set()
        self._fitted: bool = False

    def fit(self, profiles: list[TTPProfile]) -> None:
        """
        Calcule les IDF sur le corpus de profiles.
        Doit être appelé avant transform().
        """
        n_docs = len(profiles)
        if n_docs == 0:
            self._fitted = True
            self._log.warning("fit_called_on_empty_corpus")
            return

        # Comptage des document frequencies
        df: dict[str, int] = {}
        for profile in profiles:
            seen_in_doc: set[str] = set()
            for technique in profile.techniques:
                self._vocabulary.add(technique)
                if technique not in seen_in_doc:
                    df[technique] = df.get(technique, 0) + 1
                    seen_in_doc.add(technique)

        # Calcul IDF avec lissage (évite division par zéro)
        for term in self._vocabulary:
            doc_freq = df.get(term, 0)
            self._idf[term] = math.log((1 + n_docs) / (1 + doc_freq)) + 1.0

        self._fitted = True
        self._log.info(
            "tfidf_fitted",
            n_documents=n_docs,
            vocabulary_size=len(self._vocabulary),
        )

    def transform(self, profiles: list[TTPProfile]) -> list[TTPVector]:
        """
        Transforme une liste de TTPProfiles en TTPVectors.
        fit() doit avoir été appelé au préalable.
        """
        if not self._fitted:
            raise RuntimeError(
                "ManualTFIDFVectorizer.transform() called before fit(). "
                "Call fit(profiles) first."
            )

        vectors: list[TTPVector] = []
        for profile in profiles:
            techniques = profile.techniques
            n_terms = len(techniques)
            if n_terms == 0:
                continue

            # Term Frequency
            tf: dict[str, float] = {}
            for t in techniques:
                tf[t] = tf.get(t, 0.0) + 1.0
            for t in tf:
                tf[t] /= n_terms

            # TF-IDF
            tfidf: dict[str, float] = {}
            for t in techniques:
                idf_val = self._idf.get(t, math.log((1 + 1) / (1 + 0)) + 1.0)
                tfidf[t] = tf[t] * idf_val

            # Norme L2
            norm_val = math.sqrt(sum(v * v for v in tfidf.values()))
            if norm_val == 0.0:
                norm_val = 1.0  # éviter division par zéro

            vectors.append(TTPVector(
                profile_id=profile.alert_id,
                vector=tfidf,
                norm=norm_val,
            ))

        self._log.info("tfidf_transform_complete", n_vectors=len(vectors))
        return vectors

    def fit_transform(self, profiles: list[TTPProfile]) -> list[TTPVector]:
        """Enchaîne fit() puis transform() sur le même corpus."""
        self.fit(profiles)
        return self.transform(profiles)

    @staticmethod
    def cosine_similarity(v1: TTPVector, v2: TTPVector) -> float:
        """
        Calcul manuel de la similarité cosinus entre deux TTPVectors.
        cos(v1, v2) = dot(v1, v2) / (norm(v1) * norm(v2))
        """
        if v1.norm == 0.0 or v2.norm == 0.0:
            return 0.0
        dot_product = sum(
            v1.vector.get(t, 0.0) * v2.vector.get(t, 0.0)
            for t in v1.vector
        )
        return dot_product / (v1.norm * v2.norm)
