# Investigator Agent — Architecture & Extension Guide

This document explains *why* the module is built the way it is and *how* to
change it safely. For usage and behavior reference, see
[../README.md](../README.md).

## 1. Position in the INFILTRIX pipeline

```
┌──────────────────┐   DetectionEvent    ┌────────────────────┐   InvestigationResult   ┌─────────────────────────┐
│ Network IDS      │ ──────────────────▶ │ Investigator Agent │ ──────────────────────▶ │ Risk Assessment Agent   │
│ Agent            │                     │ (this module)      │                         │ Threat Correlation Agent│
└──────────────────┘                     └─────────┬──────────┘                         └─────────────────────────┘
                                                   │
                                    ┌──────────────┴───────────────┐
                                    ▼                              ▼
                            SQLite `events`              AI Engineering Handbook
                            (bounded telemetry)          (DOCX RAG + MITRE map)
```

The agent is **stateless between calls** and **deterministic**: the same
detection against the same telemetry and handbook always produces the same
result. There is no LLM call anywhere in this module — enrichment is
retrieval + static mapping, severity is a fixed matrix. That determinism is
what makes the output safe to use as ground truth downstream.

## 2. Investigation pipeline (agent.py)

For one `investigate(detection)` call, in order:

| # | Stage | Detail | Where |
|---|-------|--------|-------|
| 1 | Window derivation | `window_end = detection.timestamp` (UTC), `window_start = end − lookback` (default 15 min). Anchored to detection time, not "now", so replays are reproducible. | `agent.py` |
| 2 | Telemetry query | Single indexed SQL query, `source_ip OR session_id`, both time bounds inclusive. | `db.py` |
| 3 | Deduplication | By DB primary key `id` — defensive against future backends returning a row per matched dimension. | `agent.py` |
| 4 | Statistics | Unique endpoints/sessions (sorted for determinism), failure rate = `status≥400 / N` (0.0 for N=0). | `agent.py` |
| 5 | RAG enrichment | `rag_engine.enrich(event)` → (snippet, MITRE code); each may independently be `None`. | `rag_engine.py` |
| 6 | Severity matrix | Pure function `compute_severity(N, U, F)` per spec §5. | `agent.py` |

### Error contract (load-bearing — do not change casually)

`investigate()` never raises. Every exception becomes
`investigation_status="failed"` with zeroed stats and `severity_hint="normal"`.
Rationale: a raising investigator drops the detection from the SOC pipeline
entirely; a "failed" result keeps it visible for manual triage. The broad
`except Exception` is intentional — narrowing it reintroduces the dropped-
detection failure mode for whatever you didn't anticipate.

## 3. Storage layer (db.py)

**Timestamps are ISO-8601 UTC strings.** Because every write goes through
`to_utc_iso`, lexicographic comparison equals chronological comparison, which
makes the `BETWEEN`-style predicates both correct and index-friendly.
The invariant to protect: *no timestamp string enters the table except via
`to_utc_iso`*. A single local-time row silently corrupts window queries.

**Indexes** `(source_ip, timestamp)` and `(session_id, timestamp)` cover the
two OR branches of the related-events query. Any new lookup dimension needs
its own composite `(dimension, timestamp)` index.

**Thread model:** one `EventDatabase` instance, one SQLite connection per
thread via `threading.local`. Never pass a connection across threads; never
cache rows across requests.

### Swapping the storage backend

The agent depends only on this surface:

```python
db.query_related_events(source_ip, window_start, window_end, session_id) -> rows
# rows are mapping-accessible by column name: row["id"], row["endpoint"], ...
```

A Postgres/ClickHouse implementation that honors the same semantics
(OR-match, inclusive UTC bounds, newest-first) is a drop-in replacement.
Recommended trigger for migrating off SQLite: sustained concurrent writers
(SQLite serializes writes at the file level) or the `events` table outgrowing
a single node's disk.

## 4. RAG engine (rag_engine.py)

Two **independent** capabilities that degrade separately:

1. **MITRE mapping** — static dict `MITRE_MAPPING`; authoritative,
   deterministic, works without the handbook file.
2. **Snippet retrieval** — keyword-count scoring over ~260 ingested handbook
   paragraphs; best-effort context only.

Why keyword scoring instead of embeddings: the handbook is a general
AI-engineering text (not threat intel), the corpus is tiny, and the spec
demands determinism and zero extra dependencies. Search cost is
O(paragraphs × keywords) ≈ microseconds.

Degradation matrix:

| Condition | `search()` | `map_to_mitre()` |
|---|---|---|
| Handbook missing/unreadable | `None` | works |
| Unknown threat identifier | `None` | `None` |
| No paragraph scores > 0 | `None` | works |

`RAGEngine` is immutable after `__init__` (one DOCX parse) → build once at
startup, share across threads.

### Upgrading retrieval

Keep `search(threat, max_chars) -> Optional[str]` and
`enrich(threat) -> (snippet, code)` stable; replace only `_ingest`/`search`
internals (e.g. precompute embeddings in `__init__`). The agent and tests of
the *contract* stay valid; only retrieval-quality tests would change.

## 5. Data contracts (schemas.py)

* Pydantic **V2 only** — no `@validator`, no `class Config`.
* Every datetime field carries a UTC-coercion validator. New datetime
  fields must attach the same validator or window math breaks.
* Validation happens at the boundary; the agent contains no defensive
  re-checks. Never pass raw dicts between agents.
* Compatibility rules: adding a defaulted field to `InvestigationResult` is
  safe; renaming/removing is breaking — coordinate with downstream owners.

## 6. How-to: common changes

### Adding a new threat type
1. `rag_engine.MITRE_MAPPING["new_threat"] = ("TXXXX.XXX", "Name")`
2. `rag_engine._THREAT_KEYWORDS["new_threat"] = ["kw1", "kw2", ...]`
   (lowercase; scored by substring count — prefer distinctive stems)
3. Extend the parametrized cases in `tests/test_rag.py`
   (`test_mapping_covers_all_spec_threats` will fail until you do — that's
   the reminder).

No changes to schemas, agent, or DB: threat identifiers flow through as
plain strings by design.

### Retuning severity thresholds
Edit `compute_severity` in `agent.py` **and** the parametrized threshold
table in `tests/test_agent.py::TestSeverityMatrix` in the same commit. The
tests exist to make silent threshold drift impossible.

### Changing the lookback window
Per-deployment: pass `lookback_minutes` to the constructor. Per-threat
lookbacks: extend `investigate()` with an override parameter — do NOT mutate
`self.lookback_minutes` at runtime (races under concurrency).

### Adding a telemetry column
1. Add the column to `db.SCHEMA_SQL` + a migration for existing DBs
   (SQLite: `ALTER TABLE events ADD COLUMN ...`).
2. Add it to `RELATED_EVENTS_SQL`'s SELECT list.
3. Add the field to `schemas.RelatedEvent` (with a default for backward
   compat) and to the row→model construction in `agent.investigate`.
4. If it becomes a lookup dimension, add a `(column, timestamp)` index.

## 7. Testing strategy

* **Isolation:** every test gets a fresh temp-file SQLite DB (`tmp_path`)
  and agent tests inject a `StubRAG` — agent tests never depend on the
  handbook, RAG tests never depend on the DB.
* **Pinned invariants:** inclusive boundaries, future-telemetry exclusion,
  zero-event behavior, dedup, every severity branch including
  near-threshold values (0.79 vs 0.80, 0.59 vs 0.60), never-raise error
  contract, missing-handbook degradation.
* **CI-safe:** no network, no fixed ports, no shared state, sub-second
  runtime. `pytest tests/` from this directory is the whole invocation.

## 8. Non-goals (deliberate)

* No LLM calls — determinism is the point of this stage.
* No alerting/response actions — that belongs to downstream agents.
* No telemetry ingestion pipeline — this module reads `events`; writing it
  is the IDS/collector's job (`insert_event` exists for tests and tooling).
* No config files/env parsing — configuration is constructor injection;
  wire it up in the service entrypoint that composes the agents.
