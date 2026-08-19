"""InvestigatorAgent — context enrichment for INFILTRIX detections.

Pipeline for one `investigate(detection)` call:

    1. Window derivation   window_end = detection.timestamp (UTC),
                           window_start = window_end - lookback (default 15 min)
    2. Telemetry query     time-bounded, indexed SQLite lookup (db.py)
    3. Deduplication       by DB primary key `id`
    4. Statistics          endpoints, sessions, failure rate (status >= 400)
    5. RAG enrichment      handbook snippet + MITRE ATT&CK code (rag_engine.py)
    6. Severity matrix     deterministic normal/elevated/severe (spec §5)

Error contract
--------------
`investigate()` NEVER raises. Any exception (DB failure, corrupt row, RAG
error) is converted into an InvestigationResult with
`investigation_status="failed"`, the error message in
`investigation_error`, zeroed statistics, and `severity_hint="normal"`.
Downstream agents must branch on `investigation_status`, never on
exceptions. Rationale: in the SOC pipeline a crashed investigator would
drop the detection entirely; a "failed" result keeps the detection visible
for manual triage.

Concurrency & deployment notes
------------------------------
* The agent itself is stateless between calls — one instance can serve
  concurrent threads as long as its collaborators allow it: EventDatabase
  is thread-safe (per-thread connections) and RAGEngine is immutable after
  construction.
* Construct RAGEngine ONCE at startup (DOCX parse is the expensive step)
  and inject it; the default `RAGEngine()` construction here is a
  convenience for scripts and tests.
* `lookback_minutes` is per-instance configuration. If you need per-threat
  lookbacks (e.g. longer windows for slow scans), extend `investigate` to
  accept an override rather than mutating the instance — mutation would
  race under concurrent use.
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional

from db import EventDatabase
from rag_engine import RAGEngine
from schemas import DetectionEvent, InvestigationResult, RelatedEvent

# Default lookback window. 15 minutes balances catching burst attacks
# (credential stuffing, scans complete in minutes) against query cost and
# false correlation from stale telemetry. Change via the constructor, not
# here, so different deployments can tune it without a code change.
DEFAULT_LOOKBACK_MINUTES = 15


def compute_severity(event_count: int, unique_endpoints: int, failure_rate: float) -> str:
    """Deterministic severity matrix (spec §5).

    Evaluated top-down; first match wins:
        severe:   N >= 10  OR  U >= 5  OR  (N >= 6 AND F >= 0.80)
        elevated: N >= 4   OR  U >= 3  OR  (N >= 3 AND F >= 0.60)
        normal:   otherwise

    Kept as a pure module-level function (not a method) so it is trivially
    unit-testable and reusable by other agents without instantiating the
    investigator. The thresholds are pinned by parametrized tests in
    tests/test_agent.py — update those in the same change if you retune.

    Args:
        event_count: Deduplicated related events in the window (N).
        unique_endpoints: Distinct endpoints touched (U).
        failure_rate: Fraction of events with status_code >= 400 (F).
    """
    if event_count >= 10 or unique_endpoints >= 5 or (event_count >= 6 and failure_rate >= 0.80):
        return "severe"
    if event_count >= 4 or unique_endpoints >= 3 or (event_count >= 3 and failure_rate >= 0.60):
        return "elevated"
    return "normal"


class InvestigatorAgent:
    """Investigates IDS detections against historical telemetry.

    Dependencies are injected to keep the agent testable and to allow
    swapping backends (see db.py / rag_engine.py module docstrings):

        db  = EventDatabase("events.db")
        rag = RAGEngine()               # build once, share
        agent = InvestigatorAgent(db=db, rag_engine=rag)
    """

    def __init__(
        self,
        db: EventDatabase,
        rag_engine: Optional[RAGEngine] = None,
        lookback_minutes: int = DEFAULT_LOOKBACK_MINUTES,
    ):
        """
        Args:
            db: Telemetry store. Must expose `query_related_events`.
            rag_engine: Enrichment engine; built with default handbook
                discovery when omitted. Inject a prebuilt instance in
                services to avoid re-parsing the DOCX, or a stub in tests.
            lookback_minutes: Size of the historical window ending at the
                detection timestamp. Must be positive.
        """
        self.db = db
        self.rag_engine = rag_engine if rag_engine is not None else RAGEngine()
        self.lookback_minutes = lookback_minutes

    def investigate(self, detection: DetectionEvent) -> InvestigationResult:
        """Run the full investigation pipeline for one detection.

        See the module docstring for the pipeline stages and the error
        contract. Returns a fully-populated InvestigationResult; never
        raises.
        """
        # Window is anchored to the DETECTION time, not "now" — this keeps
        # investigations reproducible and correct for replayed/backfilled
        # detections. The upper bound also excludes telemetry written after
        # the detection (future leakage).
        window_end = detection.timestamp.astimezone(timezone.utc)
        window_start = window_end - timedelta(minutes=self.lookback_minutes)

        try:
            rows = self.db.query_related_events(
                source_ip=detection.source_ip,
                window_start=window_start,
                window_end=window_end,
                session_id=detection.session_id,
            )

            # Deduplicate by DB primary key. SQL's OR already returns each
            # row once, but this guards against future backends (e.g. a
            # UNION of per-dimension queries) double-returning rows that
            # match both source_ip and session_id.
            seen_ids = set()
            related_events: List[RelatedEvent] = []
            for row in rows:
                if row["id"] in seen_ids:
                    continue
                seen_ids.add(row["id"])
                related_events.append(
                    RelatedEvent(
                        id=row["id"],
                        timestamp=datetime.fromisoformat(row["timestamp"]),
                        source_ip=row["source_ip"],
                        session_id=row["session_id"],
                        endpoint=row["endpoint"],
                        method=row["method"],
                        status_code=row["status_code"],
                    )
                )

            event_count = len(related_events)
            # Sorted for deterministic output — downstream diffing and test
            # assertions rely on stable ordering.
            endpoints_touched = sorted({e.endpoint for e in related_events})
            session_ids_observed = sorted({e.session_id for e in related_events if e.session_id})
            # "Failed" = HTTP 4xx/5xx. Guard the division: zero events must
            # yield rate 0.0, not a ZeroDivisionError.
            failed_event_count = sum(1 for e in related_events if e.status_code >= 400)
            failure_rate = failed_event_count / event_count if event_count > 0 else 0.0

            handbook_snippet, mitre_technique = self.rag_engine.enrich(detection.event)

            return InvestigationResult(
                source_ip=detection.source_ip,
                session_id=detection.session_id,
                window_start=window_start,
                window_end=window_end,
                related_event_count=event_count,
                endpoints_touched=endpoints_touched,
                session_ids_observed=session_ids_observed,
                failed_event_count=failed_event_count,
                failure_rate=failure_rate,
                related_events=related_events,
                handbook_snippet=handbook_snippet,
                mitre_technique=mitre_technique,
                severity_hint=compute_severity(event_count, len(endpoints_touched), failure_rate),
                investigation_status="success",
            )
        except Exception as exc:
            # Broad catch is intentional — see "Error contract" in the
            # module docstring. Do not narrow this to specific exception
            # types: an unanticipated error must still produce a result.
            return InvestigationResult(
                source_ip=detection.source_ip,
                session_id=detection.session_id,
                window_start=window_start,
                window_end=window_end,
                related_event_count=0,
                endpoints_touched=[],
                session_ids_observed=[],
                failed_event_count=0,
                failure_rate=0.0,
                related_events=[],
                severity_hint="normal",
                investigation_status="failed",
                investigation_error=str(exc),
            )
