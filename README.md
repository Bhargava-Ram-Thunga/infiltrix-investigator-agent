# INFILTRIX — Investigator Agent

> **Version:** 1.0.0 · **Python:** 3.10+ · **Architecture:** [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

The **Investigator Agent** is the context-enrichment and threat-intelligence component of the INFILTRIX AI SOC framework. It receives a `DetectionEvent` from the Network IDS Agent, retrieves strictly time-bounded historical telemetry from SQLite, performs RAG lookups against the *Infiltrix AI Engineering Handbook* (DOCX), maps threats to MITRE ATT&CK techniques, and evaluates a deterministic severity matrix for the Risk Assessment and Threat Correlation agents. It is fully deterministic — no LLM calls anywhere in the module.

```
Network IDS Agent ──DetectionEvent──▶ InvestigatorAgent ──InvestigationResult──▶ Risk / Correlation Agents
```

For internals, design decisions, and extension recipes, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Repository Layout

```text
infiltrix-investigator-agent/
├── agent.py            # InvestigatorAgent class + compute_severity()
├── db.py               # Thread-safe SQLite layer, indexed time-bounded queries
├── rag_engine.py       # DOCX handbook ingestion + keyword retrieval + MITRE map
├── schemas.py          # Pydantic V2 contracts
├── docs/
│   ├── ARCHITECTURE.md # Design decisions & extension guide
│   └── Artificial_Intelligence_Engineering_Handbook_INFILTRIX.docx  # RAG corpus (if absent, module still works)
├── tests/
│   ├── __init__.py
│   ├── test_agent.py
│   └── test_rag.py
├── README.md
├── pytest.ini
├── requirements.txt    # ONLY: pydantic>=2.0, python-docx, pytest
└── .gitignore
```

## Installation

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

Requirements are strictly minimal: `pydantic>=2.0` (data contracts), `python-docx` (handbook ingestion), and `pytest` (tests). `sqlite3` is built into the Python standard library.

### Handbook Placement

The RAG engine discovers `Artificial_Intelligence_Engineering_Handbook_INFILTRIX.docx` automatically in this order:

1. `./docs/` — **primary; the module ships with its copy here**, making it self-contained
2. `<parent>/docs/` (fallback)
3. `<parent>/` (fallback)

Or pass an explicit path: `RAGEngine(handbook_path="/path/to/handbook.docx")`. **If the handbook is absent the module still boots and runs** — `handbook_snippet` returns `None` and MITRE mapping continues to work.

## Usage

```python
from datetime import datetime, timezone
from agent import InvestigatorAgent
from db import EventDatabase
from rag_engine import RAGEngine
from schemas import DetectionEvent

# Build once at service startup: RAGEngine construction parses the DOCX
# (the expensive step); both collaborators are then safe to share across threads.
db = EventDatabase("events.db")
rag = RAGEngine()
agent = InvestigatorAgent(db=db, rag_engine=rag, lookback_minutes=15)

result = agent.investigate(DetectionEvent(
    event="credential_stuffing",           # see "Supported Threat Types" below
    source_ip="10.0.0.1",
    session_id="sess-1",                   # optional; enables cross-IP session correlation
    confidence=0.92,                       # [0.0, 1.0]
    timestamp=datetime.now(timezone.utc),  # always timezone-aware
))

if result.investigation_status == "failed":
    # investigate() never raises — branch on status, log the error,
    # and route the detection to manual triage.
    print("investigation failed:", result.investigation_error)
else:
    print(f"Severity: {result.severity_hint}")
    print(f"MITRE: {result.mitre_technique}")
    print(f"Related Events: {result.related_event_count}")
    print(f"Handbook Snippet: {result.handbook_snippet}")
```

## Behavior Reference

### Lookback Window
- Defaults to **15 minutes** (`lookback_minutes` constructor arg).
- Anchored to the **detection timestamp**, not wall-clock "now" — investigations are reproducible for replayed detections.
- Bounds are **inclusive on both ends**: `timestamp >= window_start AND timestamp <= window_end`. The upper bound prevents future-telemetry leakage.

### Telemetry Matching & Deduplication
- Rows match on `source_ip` **OR** `session_id` (when provided) — the session branch catches attackers rotating IPs within one session.
- Results are deduplicated by DB primary key `id`; a row matching both dimensions appears exactly once.
- `related_events` is ordered newest-first; `endpoints_touched` / `session_ids_observed` are unique and sorted.

### Failure Rate
```text
failure_rate = failed_event_count / related_event_count
```

where "failed" means `status_code >= 400`. When `related_event_count == 0`, `failure_rate = 0.0` (never division-by-zero).

### Severity Matrix (Deterministic)

Evaluated top-down ($N$ = event count, $U$ = unique endpoints, $F$ = failure rate):

| Severity | Condition |
|:---|:---|
| `severe` | `N >= 10` or `U >= 5` or (`N >= 6` and `F >= 0.80`) |
| `elevated` | otherwise: `N >= 4` or `U >= 3` or (`N >= 3` and `F >= 0.60`) |
| `normal` | otherwise |

Implemented as the pure function `compute_severity(event_count, unique_endpoints, failure_rate)` in `agent.py`. Thresholds are pinned by parametrized tests.

### Supported Threat Types → MITRE ATT&CK

| `DetectionEvent.event` | Technique | Technique Name |
|:---|:---|:---|
| `credential_stuffing` | `T1110.004` | Credential Stuffing |
| `endpoint_scan` | `T1595.002` | Vulnerability Scanning |
| `high_rate_api_abuse` | `T1499.002` | Service Exhaustion Flood |
| `status_code_anomaly` | `T1083` | File and Directory Discovery |

Unknown threat types are not an error: both `mitre_technique` and `handbook_snippet` come back `None`. To register a new type, see "Adding a new threat type" in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

### Error Contract
`investigate()` **never raises.** Any internal failure returns `investigation_status="failed"` with the message in `investigation_error`, zeroed statistics, and `severity_hint="normal"`. Consumers branch on `investigation_status`.

## Running Tests

```bash
pytest tests/
```

Or with verbose per-case output:

```bash
pytest tests/ -v
```

The test suite (36 tests) covers:
- Inclusive window boundaries (events exactly at start/end included)
- Events before window and after detection time (future) excluded
- Zero events handling (success, all zeros, severity normal)
- Deduplication across match dimensions (IP + session)
- Failure-rate math
- Parametrized severity matrix including boundary edge cases
- Database exception degradation without raising
- Handbook ingestion, keyword search, missing handbook degradation, and all 4 MITRE mappings

Tests use an isolated temp-file SQLite DB per test (`tmp_path`) and a stub RAG engine — no network access required.

## Deployment Checklist

- [ ] Python 3.10+ available; `pip install -r requirements.txt` in a clean venv.
- [ ] Handbook DOCX present in `docs/` (shipped with the module) or another discovery path. Missing handbook degrades gracefully.
- [ ] SQLite DB path writable by the service user; schema and indexes are created automatically and idempotently.
- [ ] Build `EventDatabase` / `RAGEngine` / `InvestigatorAgent` **once** at startup, not per request.
- [ ] `pytest tests/` green in the target environment.
- [ ] Confirm nothing from `.gitignore` is staged: `.claude/`, `CLAUDE.md`, `claude.md`, `*.db`, `venv/` must never be committed.

## Operational Notes & Scaling

- **Concurrency:** One agent instance serves concurrent threads — `EventDatabase` uses per-thread connections via `threading.local` and `RAGEngine` is immutable after construction.
- **Volume:** SQLite with composite indexes `(source_ip, timestamp)` and `(session_id, timestamp)` handles moderate telemetry volume. For high-volume environments, swap `EventDatabase` for Postgres or ClickHouse with identical public methods (see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)).
- **Tuning:** Configurable lookback per instance via `lookback_minutes`; deterministic severity thresholds in `compute_severity()`; keyword scoring in `rag_engine._THREAT_KEYWORDS`.
