"""Pydantic V2 data contracts for the INFILTRIX Investigator Agent.

This module is the single source of truth for every data structure that
crosses the Investigator Agent's boundary:

    Network IDS Agent ──DetectionEvent──▶ InvestigatorAgent
    InvestigatorAgent ──InvestigationResult──▶ Risk Assessment / Correlation Agents

Design decisions
----------------
1. **Pydantic V2 only.** All models use `pydantic.BaseModel` with V2 field
   validators (`field_validator`). Do NOT mix in V1 idioms (`@validator`,
   `class Config`) — they behave subtly differently under V2 and will break
   when V1 compatibility is eventually removed.

2. **All timestamps are UTC-aware.** Naive datetimes are coerced to UTC and
   aware datetimes are converted to UTC by `_ensure_utc`. This guarantees
   that window arithmetic in `agent.py` and lexicographic ISO-8601 string
   comparison in `db.py` are always correct, regardless of what timezone the
   caller supplied. If you add a new datetime field to any model, attach the
   same validator.

3. **Validation happens at the boundary, not inside the agent.** The agent
   assumes every `DetectionEvent` it receives is already valid (confidence
   in [0, 1], UTC timestamp, etc.), which keeps its logic free of defensive
   checks. Upstream producers must construct these models — never pass raw
   dicts between agents.

Extending the contracts
-----------------------
* Adding a field to `InvestigationResult` is backward-compatible for
  consumers that ignore unknown fields; give it a default so old producers
  keep working.
* Renaming/removing a field is a breaking change — coordinate with the Risk
  Assessment and Threat Correlation agent owners and bump the module version
  in README.md.
* New threat types need no schema change: `DetectionEvent.event` is a free
  string by design. Register new types in `rag_engine.MITRE_MAPPING` instead.
"""

from datetime import datetime, timezone
from typing import List, Literal, Optional

from pydantic import BaseModel, Field, field_validator


def _ensure_utc(value: datetime) -> datetime:
    """Coerce naive datetimes to UTC-aware; normalize aware ones to UTC.

    Naive datetimes are *assumed* to already be UTC (we cannot know the
    producer's local zone, and assuming local time would silently corrupt
    window math). Producers should always send timezone-aware values;
    this is a safety net, not a supported input format.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class DetectionEvent(BaseModel):
    """Inbound detection emitted by the Network IDS Agent.

    One `DetectionEvent` triggers exactly one investigation. The `event`
    field carries the IDS attack-pattern identifier and drives both the RAG
    handbook lookup and the MITRE ATT&CK mapping (see `rag_engine.py`).

    Known `event` values (extensible — see rag_engine.MITRE_MAPPING):
        credential_stuffing, endpoint_scan, high_rate_api_abuse,
        status_code_anomaly
    """

    event: str = Field(
        ...,
        description="IDS attack pattern identifier (e.g. credential_stuffing, endpoint_scan)",
    )
    source_ip: str = Field(..., description="Source IPv4 or IPv6 address")
    session_id: Optional[str] = Field(
        default=None,
        description="Session correlation identifier; enables cross-IP session tracking",
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="IDS detection confidence score in [0.0, 1.0]"
    )
    timestamp: datetime = Field(
        ...,
        description="Detection time (UTC-aware). Defines the upper bound of the lookback window.",
    )

    @field_validator("timestamp")
    @classmethod
    def _utc_timestamp(cls, v: datetime) -> datetime:
        return _ensure_utc(v)


class RelatedEvent(BaseModel):
    """One historical telemetry row from the `events` SQLite table.

    Mirrors the DB schema in `db.SCHEMA_SQL` column-for-column. `id` is the
    DB primary key and is the deduplication key used by the agent — a row
    that matches a detection by BOTH source_ip and session_id must still
    appear exactly once in the result.
    """

    id: int
    timestamp: datetime
    source_ip: str
    session_id: Optional[str] = None
    endpoint: str
    method: str
    status_code: int

    @field_validator("timestamp")
    @classmethod
    def _utc_timestamp(cls, v: datetime) -> datetime:
        return _ensure_utc(v)


class InvestigationResult(BaseModel):
    """Complete output of one investigation, consumed downstream.

    Contract guarantees:
    * `window_start` / `window_end` are the exact inclusive bounds used in
      the SQL query — consumers can independently re-verify the telemetry.
    * `failure_rate == failed_event_count / related_event_count`
      (0.0 when there are no events; never a division-by-zero).
    * `related_events` is deduplicated by DB primary key and sorted newest
      first (DB `ORDER BY timestamp DESC`).
    * `endpoints_touched` and `session_ids_observed` are sorted and unique.
    * On any internal failure `investigation_status == "failed"`,
      `investigation_error` holds the message, all counts are zeroed, and
      `severity_hint` falls back to "normal". The agent never raises out of
      `investigate()` — check `investigation_status`, not try/except.
    """

    source_ip: str
    session_id: Optional[str] = None
    window_start: datetime
    window_end: datetime

    related_event_count: int = Field(..., ge=0)
    endpoints_touched: List[str]
    session_ids_observed: List[str]
    failed_event_count: int = Field(..., ge=0)
    failure_rate: float = Field(..., ge=0.0, le=1.0)

    related_events: List[RelatedEvent]

    # RAG Handbook Enrichment & MITRE Mapping.
    # Both are Optional: snippet is None when the handbook is unavailable or
    # the threat has no registered keywords; technique is None for threat
    # types not present in rag_engine.MITRE_MAPPING.
    handbook_snippet: Optional[str] = Field(
        default=None, description="Excerpt from Infiltrix AI Engineering Handbook"
    )
    mitre_technique: Optional[str] = Field(
        default=None, description="Matched MITRE ATT&CK technique code (e.g. T1110.004)"
    )

    severity_hint: Literal["normal", "elevated", "severe"]
    investigation_status: Literal["success", "failed"]
    investigation_error: Optional[str] = None

    @field_validator("window_start", "window_end")
    @classmethod
    def _utc_window(cls, v: datetime) -> datetime:
        return _ensure_utc(v)
