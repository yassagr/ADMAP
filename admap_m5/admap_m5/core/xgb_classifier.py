from __future__ import annotations
from pathlib import Path
import structlog
from admap_m5.core.apt_kb import APTGroup

logger = structlog.get_logger(__name__)

# XGBoost est optionnel — le module fonctionne en mode "cosine_only" si absent
try:
    import joblib
    import numpy as np
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    logger.warning("xgb_classifier.xgboost_unavailable", mode="cosine_only_fallback")


class XGBAttributor:
    """Wrapper XGBoost pour l'attribution APT.
    
    Si XGBoost n'est pas disponible ou si le modèle n'existe pas,
    le classifieur retourne des probabilités uniformes et l'attribution
    se fait uniquement par similarité cosinus.
    
    Le modèle est pré-entraîné (fichier .joblib) — jamais de retrain à la volée.
    """

    def __init__(self, model_path: Path) -> None:
        self._model_path: Path = model_path
        self._model: object | None = None
        self._label_encoder: dict[int, str] = {}
        self._available: bool = False
        self._load_model()

    def _load_model(self) -> None:
        """Charge le modèle depuis le fichier .joblib si disponible."""
        if not XGBOOST_AVAILABLE:
            logger.info("xgb_classifier.skip_load", reason="joblib/numpy unavailable")
            return

        if not self._model_path.exists():
            logger.info("xgb_classifier.model_not_found", path=str(self._model_path),
                        mode="cosine_only_fallback")
            return

        try:
            bundle = joblib.load(self._model_path)
            self._model = bundle.get("model")
            self._label_encoder = bundle.get("label_encoder", {})
            self._available = True
            logger.info("xgb_classifier.loaded", path=str(self._model_path),
                        classes=len(self._label_encoder))
        except Exception as exc:
            logger.warning("xgb_classifier.load_failed", error=str(exc),
                           mode="cosine_only_fallback")

    @property
    def is_available(self) -> bool:
        return self._available

    def predict_proba(
        self,
        feature_vector: list[float],
        apt_groups: list[APTGroup],
    ) -> dict[str, float]:
        """Retourne {apt_id: probabilité} pour chaque groupe APT.
        
        Si le modèle n'est pas disponible, retourne une distribution uniforme.
        Les probabilités sont dans [0, 1] et somment à 1.
        """
        n_groups = len(apt_groups)
        if n_groups == 0:
            return {}

        if not self._available or not XGBOOST_AVAILABLE:
            # Distribution uniforme — le cosine similarity dominera le score final
            uniform_prob = 1.0 / n_groups
            return {grp.apt_id: uniform_prob for grp in apt_groups}

        try:
            import numpy as np
            x = np.array(feature_vector, dtype=np.float32).reshape(1, -1)
            probas = self._model.predict_proba(x)[0]  # type: ignore[union-attr]
            result: dict[str, float] = {}
            for idx, prob in enumerate(probas):
                apt_id = self._label_encoder.get(idx, "")
                if apt_id:
                    result[apt_id] = float(prob)
            return result
        except Exception as exc:
            logger.warning("xgb_classifier.predict_failed", error=str(exc),
                           mode="uniform_fallback")
            uniform_prob = 1.0 / n_groups
            return {grp.apt_id: uniform_prob for grp in apt_groups}


def generate_synthetic_xgb_model(
    apt_groups: list[APTGroup],
    model_path: Path,
    feature_dim: int = 50,
) -> None:
    """Génère et sauvegarde un modèle XGBoost synthétique pré-entraîné.
    
    Utilisé lors de la première initialisation pour avoir un modèle fonctionnel
    sans données réelles. Le modèle est entraîné sur des données aléatoires
    avec la bonne structure de labels — il ne fournit pas de prédictions
    significatives mais permet au pipeline de fonctionner end-to-end.
    """
    if not XGBOOST_AVAILABLE:
        logger.warning("xgb_classifier.synthetic_skip", reason="joblib/numpy unavailable")
        return

    try:
        import numpy as np
        import xgboost as xgb
        from sklearn.preprocessing import LabelEncoder

        n_samples = max(len(apt_groups) * 20, 200)
        n_classes = len(apt_groups)

        X = np.random.RandomState(42).rand(n_samples, feature_dim).astype(np.float32)
        y_labels = [grp.apt_id for grp in apt_groups]
        y = np.array([y_labels[i % n_classes] for i in range(n_samples)])

        le = LabelEncoder()
        y_encoded = le.fit_transform(y)
        label_encoder = {int(idx): str(cls) for idx, cls in enumerate(le.classes_)}

        model = xgb.XGBClassifier(
            n_estimators=50,
            max_depth=4,
            learning_rate=0.1,
            eval_metric="mlogloss",
            random_state=42,
        )
        model.fit(X, y_encoded)

        model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": model, "label_encoder": label_encoder}, model_path)
        logger.info("xgb_classifier.synthetic_generated", path=str(model_path),
                    n_classes=n_classes, feature_dim=feature_dim)
    except Exception as exc:
        logger.warning("xgb_classifier.synthetic_failed", error=str(exc))
