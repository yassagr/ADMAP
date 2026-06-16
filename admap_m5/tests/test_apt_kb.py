from __future__ import annotations
import pytest
from pathlib import Path
from admap_m5.core.apt_kb import APTKnowledgeBase


def test_load_valid_kb(settings):
    kb = APTKnowledgeBase(settings.apt_kb_path)
    assert len(kb.groups) == 2


def test_get_by_id_found(settings):
    kb = APTKnowledgeBase(settings.apt_kb_path)
    grp = kb.get_by_id("G0007")
    assert grp is not None
    assert grp.apt_name == "APT28"


def test_get_by_id_not_found(settings):
    kb = APTKnowledgeBase(settings.apt_kb_path)
    grp = kb.get_by_id("G9999")
    assert grp is None


def test_all_technique_vectors(settings):
    kb = APTKnowledgeBase(settings.apt_kb_path)
    vectors = kb.all_technique_vectors()
    assert "G0007" in vectors
    assert "G0032" in vectors
    assert len(vectors["G0007"]) > 0
    assert len(vectors["G0032"]) > 0


def test_load_missing_file():
    with pytest.raises(FileNotFoundError):
        APTKnowledgeBase(Path("/nonexistent.json"))


def test_load_invalid_json(tmp_path):
    invalid_path = tmp_path / "invalid.json"
    invalid_path.write_text("{invalid json", encoding="utf-8")
    with pytest.raises(ValueError):
        APTKnowledgeBase(invalid_path)
