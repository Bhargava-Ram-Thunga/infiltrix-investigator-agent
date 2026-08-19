"""Unit tests for InvestigatorAgent: time boundaries, dedup, severity matrix."""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent import InvestigatorAgent, compute_severity
from db import EventDatabase
from schemas import DetectionEvent

NOW = datetime(2026, 8, 14, 12, 0, 0, tzinfo=timezone.utc)


class StubRAG:
    def enrich(self, threat):
        return ("stub snippet", "T1110.004")


@pytest.fixture
def db(tmp_path):
    database = EventDatabase(str(tmp_path / "test_events.db"))
    yield database
    database.close()


@pytest.fixture
def agent(db):
    return InvestigatorAgent(db=db, rag_engine=StubRAG(), lookback_minutes=15)


def make_detection(**overrides):
    payload = dict(
        event="credential_stuffing",
        source_ip="10.0.0.1",
        session_id="sess-1",
        confidence=0.9,
        timestamp=NOW,
    )
    payload.update(overrides)
    return DetectionEvent(**payload)


def seed(db, count, source_ip="10.0.0.1", status_code=200, endpoint="/login",
         start=None, spacing_seconds=10, session_id="sess-1"):
    start = start or (NOW - timedelta(minutes=5))
    for i in range(count):
        db.insert_event(
            source_ip=source_ip,
            endpoint=endpoint,
            method="POST",
            status_code=status_code,
            timestamp=start + timedelta(seconds=i * spacing_seconds),
            session_id=session_id,
        )


class TestTimeBoundaries:
    def test_events_before_window_excluded(self, db, agent):
        seed(db, 3, start=NOW - timedelta(minutes=30))  # outside lookback
        result = agent.investigate(make_detection())
        assert result.related_event_count == 0

    def test_events_after_window_excluded(self, db, agent):
        seed(db, 3, start=NOW + timedelta(seconds=1))  # future telemetry
        result = agent.investigate(make_detection())
        assert result.related_event_count == 0

    def test_boundary_events_inclusive(self, db, agent):
        db.insert_event("10.0.0.1", "/a", "GET", 200, NOW - timedelta(minutes=15), "sess-1")
        db.insert_event("10.0.0.1", "/b", "GET", 200, NOW, "sess-1")
        result = agent.investigate(make_detection())
        assert result.related_event_count == 2

    def test_window_matches_lookback(self, agent):
        result = agent.investigate(make_detection())
        assert result.window_end - result.window_start == timedelta(minutes=15)


class TestZeroEvents:
    def test_zero_events_normal_severity(self, agent):
        result = agent.investigate(make_detection())
        assert result.investigation_status == "success"
        assert result.related_event_count == 0
        assert result.failed_event_count == 0
        assert result.failure_rate == 0.0
        assert result.severity_hint == "normal"
        assert result.endpoints_touched == []
        assert result.related_events == []


class TestDeduplication:
    def test_ip_and_session_match_not_duplicated(self, db, agent):
        # Row matches BOTH source_ip and session_id; must appear once.
        db.insert_event("10.0.0.1", "/login", "POST", 401, NOW - timedelta(minutes=1), "sess-1")
        result = agent.investigate(make_detection())
        assert result.related_event_count == 1
        assert len({e.id for e in result.related_events}) == 1

    def test_session_only_match_included(self, db, agent):
        db.insert_event("172.16.0.9", "/login", "POST", 401, NOW - timedelta(minutes=1), "sess-1")
        result = agent.investigate(make_detection())
        assert result.related_event_count == 1


class TestFailureRate:
    def test_failure_rate_computed(self, db, agent):
        seed(db, 3, status_code=401)
        seed(db, 1, status_code=200, endpoint="/home")
        result = agent.investigate(make_detection())
        assert result.failed_event_count == 3
        assert result.failure_rate == pytest.approx(0.75)


class TestSeverityMatrix:
    @pytest.mark.parametrize("events,endpoints,rate,expected", [
        (10, 1, 0.0, "severe"),      # N >= 10
        (1, 5, 0.0, "severe"),       # U >= 5
        (6, 1, 0.80, "severe"),      # N >= 6 and F >= 0.80
        (6, 1, 0.79, "elevated"),    # just below severe failure threshold
        (9, 4, 0.0, "elevated"),     # N >= 4
        (2, 3, 0.0, "elevated"),     # U >= 3
        (3, 1, 0.60, "elevated"),    # N >= 3 and F >= 0.60
        (3, 1, 0.59, "normal"),
        (2, 2, 1.0, "normal"),
        (0, 0, 0.0, "normal"),
    ])
    def test_matrix(self, events, endpoints, rate, expected):
        assert compute_severity(events, endpoints, rate) == expected

    def test_severe_end_to_end(self, db, agent):
        seed(db, 10, status_code=401)
        result = agent.investigate(make_detection())
        assert result.severity_hint == "severe"

    def test_elevated_end_to_end(self, db, agent):
        seed(db, 4, status_code=200)
        result = agent.investigate(make_detection())
        assert result.severity_hint == "elevated"


class TestEnrichmentAndFailure:
    def test_rag_fields_populated(self, db, agent):
        seed(db, 2)
        result = agent.investigate(make_detection())
        assert result.handbook_snippet == "stub snippet"
        assert result.mitre_technique == "T1110.004"

    def test_db_failure_reports_failed_status(self, agent):
        def boom(**kwargs):
            raise RuntimeError("db unavailable")
        agent.db.query_related_events = boom
        result = agent.investigate(make_detection())
        assert result.investigation_status == "failed"
        assert "db unavailable" in result.investigation_error
        assert result.severity_hint == "normal"
