# The Nabla Clock Specification

**Status:** Approved and implemented (round 6). The five-pass review arc (C→S→T→U→V) closed with V-1 (re-open close is measured on the WATERMARK's value, not wall time); V-2..V-5 landed as implementation-time items: hour-aligned backfill/file hours close at batch end (V-2 — the watermark never moves during a backfill-only bootstrap), migration initializes per-source watermarks and the per-hour open map (V-3). Round 7 (N-2) made the Rule 6 engine stateful — the stateless reference absorbed per batch would have undercounted 12x on every live batch.
**Date:** 2026-11-20. v1: 7 rules. v2: Rule 0, watermark Rule 6, clamps, naive-stamp tz, host attribution, derived anomalies, allowlists, migration. v3: S-pass (per-source watermarks, semantics, repair, far-future→absent, multi-open-hour). v4: T-pass. v5: U-pass. v6: V-pass (V-1 watermark-domain close wording; V-2 batch-end close for hour-aligned/file hours; V-3 migration initialization).

## Scope

Everything that reads, writes, compares, or derives from event time. One specification, eight rules (0–7), each traceable to the bug it exists to prevent. Code conforms or it fails the conformance suite (`tests/test_clock_conformance.py` — one test class per rule, named after the rule).

---

## Rule 0 — Event identity

An event's identity must distinguish occurrences. The ingestion `event_id` is the source's native ID when one exists (Sysmon `EventRecordID`, Splunk `_cd` + index, SumoLogic message ID); otherwise the current field hash **plus an occurrence counter within the batch** (identical-looking events get distinct IDs).

**Conformance:** N identical-looking events yield N distinct IDs. (Prevents: C1 — ten same-second brute-force logins collapsing to one ID, which would have made Rule 6 drop nine real events as "duplicates.")

## Rule 1 — Event time is parsed once, at ingestion

Every entry from every source passes through ONE normalize-and-validate function:

- parses the raw stamp to a timezone-aware UTC datetime,
- **naive stamps (no offset) are read in the source's configured timezone** (`settings.timezone`, per-source override) — a UTC+5 site's local-time stamps are not "hours in the future," they are 05:00-local = 00:00Z,
- offsets are normalized to UTC (a `+05:00` stamp becomes its UTC instant),
- a source whose events are stripped in bulk (Rule 2) raises ONE configuration warning per batch — likely a timezone misconfiguration — not one degradation per event,
- nothing else is preserved; downstream code never re-parses raw strings.

**Forbidden:** `timestamp[:13]` slicing, per-connector stamp handling, second parse sites. (Prevents: R6-6; C5 — naive-stamp mass-stripping.)

## Rule 2 — Ingestion validates against wall clock; nothing else ever does

At the single entry point:

- a stamp **more than 1 hour in the future** of wall clock becomes **absent** — the original is preserved in the entry's details, counted as a degradation (`future_timestamp_stripped`). Signature detectors still fire on the entry; NO time-based consumer (off-hours, rate buckets, chains, clocks) ever reads an invented time. *(S-5: v2's clock-inert clamping kept an invented time in every time consumer's path — each needed a special case. Absence is the same safety with none of the special cases.)*
- an entry with **no parseable stamp carries no time** — never "now," never a guess; counted as a degradation (`absent_timestamp`).

After ingestion, NO code compares event time to wall clock. (Prevents: R6-1, R6-14.)

**Allowed wall-clock uses (C8, exhaustive):** the SIEM pull cursor (`update_last_ingestion`), `first_ingestion_at`/`transitioned_at` phase anchors, the `_data_clock` fallback when nothing has ever been ingested, `flag_quarantine`'s fallback clock, and Rule 2 itself. Anything new joins this list by spec amendment, not by patch.

## Rule 3 — The data clock is the max VALID event time, ever forward

The run's data clock = max(**valid (present) event time**; stripped events have no time to move a clock with) across the batch; the persisted span never regresses. (Prevents: C4 — one far-future event aging a replayed batch to now; preserves A7.)

**Which sources advance the GLOBAL data clock (C10, exhaustive):** splunk and sumologic batches only — file uploads are ad-hoc analysis; neither moves the global clock. A year-old uploaded file must not distort live scoring.

**Watermark clocks are per-source-kind (S-1) and are PERSISTED, monotone (U-1):** each source-kind's watermark advances from the newest valid event time of whatever batch fed the baseline — synthetic runs, `update_baseline=True` file runs, and SIEM batches each close their own hours against their own watermark (+2h lateness). A watermark never moves backwards: an older backfill chunk cannot pull it back and re-open already-observed hours. The quickstart and gate-7 learn from synthetic batches; under a global-only data clock their hours would never close. **SIEM backfill windows (since/until) are hour-aligned** (U-1: removes the chunk-edge case for SIEM at the source). The global data clock (above) remains SIEM-only and governs phase span and cross-source scoring references.

## Rule 4 — Each entity's decay reference advances from its newest VALID event

Entities are attributed events by **the same function risk attribution uses** (`risk_entities` applied to entries — a user+host event advances both the user's and the host's clock; C6). An entity's clock = max(that entity's persisted clock, its newest valid (present) EVENT time in this batch).

- **Events, not anomalies, advance the clock.** Present-but-anomaly-free entities decay. (Prevents: R6-4.)
- **Filtered entities are still present.** An entity whose anomalies were all removed (machine-behavioral case) decays like anyone else. (Prevents: R6-15.)
- **Absent entities are dormant:** no events in the batch → score and clock unchanged. Absence carries no time information; departed-user hygiene is a roadmap TTL, out of scope.
- **The global floor is retired (C4b).** The R12 cold-start floor (risk.py:641-644) is deleted; an entity's clock comes only from its own events. One entity's stripped future event can never age another entity's score (it carries no time at all).

## Rule 5 — Hour keys come from one function; hour-of-day is a different thing

All absolute-hour keys derive from the parsed UTC event time via `event_hour_key(event)`. **Off-hours detection's hour-of-day reads the SITE timezone** (R17's behavior) — that is a different quantity from the UTC absolute-hour key, and conformance must not "fix" one into the other. (C9.) **Rate scoring composes each batch hour with that hour's open count (S-6):** under a 2h watermark up to three hours may be open simultaneously; the profile's open state is per-hour, and `hourly_rates` adds each batch hour's count to that hour's accumulated open count (the single-`open_hour` accumulator is upgraded to a per-hour map).

## Rule 6 — Late data: watermark, then exclude from baseline

An hour has two distinct states — **open**, **observed (closed and registered)** — and "behind the watermark" alone means nothing:

- **Open hours** accumulate; one observation is made when the hour closes (the relevant per-source watermark clock passes it + **allowed lateness, 2h**). Open-hour events deduplicate by ID (S-3: overlapping SIEM pulls merge once; native IDs preferred — occurrence counters are approximate).
- **Observed hours** (in the registry): later events are **excluded from BASELINE ABSORPTION only** and counted as one degradation (`late_beyond_watermark`) per batch. Every detector, risk, and evidence step still sees them (S-2). Conformance test: an event past the watermark still produces its LOLBin anomaly.
- **Behind the watermark but NEVER observed** (T-2 + U-1): this is what every backfill delivers — newest-first SIEM pulls, out-of-order historical files, laptop reconnects. Such an hour is **RE-OPENED, not recorded** — pieces merge into its open count (with ID dedup) until it closes: when the source's watermark **reaches (its own value at re-open) + 2h** — the close is measured on the watermark's value, never on wall time (V-1: 're-open time' as wall clock was exactly the ambiguity Rule 2 forbids). 'Recorded once from the delivering batch' — v4's wording — re-created the piecewise undercount when a laptop's backlog arrives over several 5-minute batches or a chunk boundary falls mid-hour. **Exception (V-2): hours delivered by hour-aligned backfill chunks and by file uploads close at BATCH END** — SIEM backfill windows are hour-aligned (Rule 3), so every such hour is complete on arrival, and during a backfill-only bootstrap (no live data) the watermark does not move at all; the watermark-based close applies to live late data (the laptop case). Conformance: a three-piece laptop reconnect and a mid-hour chunk edge both produce ONE correct observation; a newest-first backfill with no live data afterwards records every hour.
- **Approved drains (T-1):** a held batch is a pipeline BATCH, not an hour — on the 5-minute schedule that's five minutes of data; recording it as an hourly observation undercounts ~12× (R6-7 at its worst). Draining merges ALL of the entity's approved batches, buckets them by `event_hour_key`, and records ONE observation per hour. Hours the registry already holds are skipped (data absorbed live before the hold is not double-counted). The analyst's verdict justifies including the data — not treating a fragment as a whole hour.

The closed-hours registry is sized **from settings: max(TP-hold ceiling, baseline_min_days)** — 21 days today — so the window can never be shorter than the baseline phase it serves (T-2: a 14-day registry starved days 15–21 of every backfill). It stores per-hour counts plus a compact ID filter (not raw ID sets). Hours older than the window — measured against the SOURCE's watermark — are never re-observed: they are left out of the baseline and counted as a degradation, so a backfill longer than the window loses its oldest hours visibly (U-1 clarification). (Prevents: R6-7; C2's undercount; C3's sizing hole.)

## Rule 7 — Anomaly timestamps come from contributing events

An anomaly's timestamp = the newest valid (present) event time of ITS contributing events. This covers derived anomalies explicitly (C7): a temporal chain's timestamp is its **newest member's newest event** (not the chain's start — a long chain must not decay from its first step); provenance-community, GCN-LOF, and pre-flagged anomalies each have a defined contributing set (their member events' newest). No contributing time → no anomaly timestamp → no risk contribution + degradation. (Subsumes N2.3; extends S3.)

---

## Migration (C11)

Rule 1 changes the timestamp strings that `event_id` and `anomaly_id` hash. After upgrade, re-fired anomalies won't match stored copies (double-counted for ~one half-life) and closed-hour registries stop matching. Migration at upgrade time: **reset the closed-hour registries** (a one-time re-observation of warm hours is acceptable and self-correcting under the watermark) and **dedupe retained anomalies once** by (method, entity, normalized time). **Repair poisoned clocks (S-4):** cap every persisted entity `data_clock` and the global `data_newest_ts` at the upgrade's wall time + 1h — clocks never go backwards, so R6-1/R6-14 victims (a 2099 entity clock, a now-stamped span) stay wrong forever without this; log each change. **Initialize the new state (V-3):** the SIEM watermark starts from the repaired `data_newest_ts`, the other per-source watermarks start empty, and the existing single `open_hour`/`open_count` accumulator carries into the per-hour map as its only entry. Baked into the release upgrade step, not left as operator folklore.

## Conformance, not compliance theater

`tests/test_clock_conformance.py` encodes each rule as executable statements — Rule 0's test feeds N identical-looking events and asserts N IDs; Rule 2's feeds a 2099 stamp and asserts stripped-to-absent + the degradation + the original preserved in details; Rule 4's runs the 7-quiet-days scenario AND a host entity AND a machine-behavioral entity; Rule 6's covers S-1 per-source closure, S-2 late-still-detects, S-3 open-hour dedup, T-1 drain-merge-by-hour, T-2 newest-first + out-of-order backfills, and U-1's three-piece reconnect + mid-hour chunk edge. Tests are named after rules: when rule and code disagree, the RULE is on trial as much as the code.

## What this spec deliberately does not do

- No wall-clock decay for dormant entities (roadmap TTL).
- No module split of detection.py/baselines.py (post-round-6).
- No IP-pinning rewrite of connector sockets (validation moved pre-authenticate instead; pinning is a follow-up).
- No change to the gate-7 demo contract: single-hour UTC batches take `family_z_threshold(1) → base`; stripping never touches valid stamps.
