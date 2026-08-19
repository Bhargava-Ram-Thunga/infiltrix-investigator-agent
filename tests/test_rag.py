"""Unit tests for the RAG engine: handbook ingestion, snippet search, MITRE mapping."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rag_engine import MITRE_MAPPING, RAGEngine


@pytest.fixture(scope="module")
def engine():
    return RAGEngine()


class TestMitreMapping:
    @pytest.mark.parametrize("threat,code", [
        ("credential_stuffing", "T1110.004"),
        ("endpoint_scan", "T1595.002"),
        ("high_rate_api_abuse", "T1499.002"),
        ("status_code_anomaly", "T1083"),
    ])
    def test_known_threats(self, engine, threat, code):
        assert engine.map_to_mitre(threat) == code

    def test_unknown_threat_returns_none(self, engine):
        assert engine.map_to_mitre("unknown_threat") is None

    def test_mapping_covers_all_spec_threats(self):
        assert set(MITRE_MAPPING) == {
            "credential_stuffing", "endpoint_scan",
            "high_rate_api_abuse", "status_code_anomaly",
        }


class TestHandbookIngestion:
    def test_handbook_found_and_ingested(self, engine):
        assert engine.handbook_path is not None, "handbook DOCX should be discoverable"
        assert len(engine.paragraphs) > 0

    def test_missing_handbook_degrades_gracefully(self, tmp_path):
        missing = RAGEngine(handbook_path=str(tmp_path / "nope.docx"))
        assert missing.handbook_path is None
        assert missing.paragraphs == []
        assert missing.search("credential_stuffing") is None
        # MITRE mapping still works without the handbook.
        assert missing.map_to_mitre("endpoint_scan") == "T1595.002"


class TestSnippetSearch:
    @pytest.mark.parametrize("threat", list(MITRE_MAPPING))
    def test_snippet_returned_for_each_threat(self, engine, threat):
        snippet = engine.search(threat)
        assert snippet is not None
        assert len(snippet) <= 500

    def test_unknown_threat_no_snippet(self, engine):
        assert engine.search("unmapped_threat") is None

    def test_enrich_returns_snippet_and_code(self, engine):
        snippet, code = engine.enrich("credential_stuffing")
        assert snippet is not None
        assert code == "T1110.004"
