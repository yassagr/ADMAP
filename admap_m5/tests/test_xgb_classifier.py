from __future__ import annotations
import pytest
from pathlib import Path
from admap_m5.core.xgb_classifier import XGBAttributor, generate_synthetic_xgb_model, XGBOOST_AVAILABLE
from admap_m5.core.apt_kb import APTGroup


def test_init_model_not_found(tmp_path):
    clf = XGBAttributor(tmp_path / "nonexistent.joblib")
    assert not clf.is_available


def test_predict_proba_fallback_uniform(tmp_path):
    clf = XGBAttributor(tmp_path / "nonexistent.joblib")
    groups = [
        APTGroup("G1", "A1", [], "O1", "U1", [], [], [], [], [], [], [], "D1"),
        APTGroup("G2", "A2", [], "O2", "U2", [], [], [], [], [], [], [], "D2"),
    ]
    probas = clf.predict_proba([0.5, 0.5], groups)
    assert len(probas) == 2
    assert probas["G1"] == 0.5
    assert probas["G2"] == 0.5


def test_predict_proba_sums_to_one(tmp_path):
    clf = XGBAttributor(tmp_path / "nonexistent.joblib")
    groups = [
        APTGroup("G1", "A1", [], "O1", "U1", [], [], [], [], [], [], [], "D1"),
        APTGroup("G2", "A2", [], "O2", "U2", [], [], [], [], [], [], [], "D2"),
    ]
    probas = clf.predict_proba([0.5, 0.5], groups)
    assert sum(probas.values()) == 1.0


def test_predict_proba_empty_groups(tmp_path):
    clf = XGBAttributor(tmp_path / "nonexistent.joblib")
    probas = clf.predict_proba([0.5, 0.5], [])
    assert len(probas) == 0


def test_generate_synthetic_model(tmp_path):
    if not XGBOOST_AVAILABLE:
        pytest.skip("xgboost not available")
    
    model_path = tmp_path / "test_model.joblib"
    groups = [
        APTGroup("G1", "A1", [], "O1", "U1", [], [], [], [], [], [], [], "D1"),
        APTGroup("G2", "A2", [], "O2", "U2", [], [], [], [], [], [], [], "D2"),
    ]
    generate_synthetic_xgb_model(groups, model_path, feature_dim=10)
    assert model_path.exists()
    
    clf = XGBAttributor(model_path)
    assert clf.is_available
