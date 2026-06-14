"""
Module   : admap_m3.models.token
Version  : 1.0.0
Dépend   : [pydantic]

Modèles pour les tokens extraits et leurs scores TF-IDF discriminants.
"""
from __future__ import annotations

from pydantic import BaseModel


class TokenFeature(BaseModel, frozen=True):
    """Feature TF-IDF calculée pour un token du corpus.

    Attributes:
        token: La chaîne / hex / opcode extrait.
        token_type: Type de token (``string``, ``hex_pattern``, ``opcode_ngram``,
                    ``m1_ioc``).
        tf_malware: TF moyen du token dans le corpus malware.
        tf_benign_max: TF maximum observé dans le corpus bénin.
        delta_score: Score discriminant Δ = tf_malware − tf_benign_max.
        df_malware: Nombre de fichiers malware contenant ce token.
        df_benign: Nombre de fichiers bénins contenant ce token.
        corpus_id: Identifiant du corpus source.
    """

    token: str
    token_type: str
    tf_malware: float
    tf_benign_max: float
    delta_score: float
    df_malware: int
    df_benign: int
    corpus_id: str


class TokenScore(BaseModel, frozen=True):
    """Score final d'un token après filtrage et scoring.

    Attributes:
        token: La chaîne du token.
        delta_score: Score discriminant Δ.
        confidence: Confiance de 0 à 100, calculée dynamiquement depuis Δ.
        selected: ``True`` si le token passe tous les critères de sélection.
        rejection_reason: Raison du rejet si ``selected`` est ``False``.
    """

    token: str
    delta_score: float
    confidence: int
    selected: bool
    rejection_reason: str | None = None
