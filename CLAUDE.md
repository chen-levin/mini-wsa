# Mini WSA – Akamai backend take-home

A small security analytics pipeline: ingest security events (DLRs), enrich them
(attackType + threatScore), store in PostgreSQL, expose stats and samples APIs.

## Working rules
- The author must explain and live-modify every line in the interview.
  **Keep code simple, explicit, and boring.** No clever abstractions, no extra libraries
  (exception: Lombok, for `@Getter`/`@Setter` on entities and `@RequiredArgsConstructor`).
- Work one small part at a time. After each part: explain what/why in plain terms,
  propose a commit message, then STOP. The author reviews and commits themselves.
- Never commit the assignment PDF.
- No bonus challenges.

## Stack
Spring Boot 4, Java 21, Maven, PostgreSQL 16 (docker-compose), Flyway, Spring Data JPA,
Bean Validation, Testcontainers. `ddl-auto: validate` – Flyway owns the schema.

## Milestones (git tags)
- [ ] **v0.1-ingestion** – Flyway V1 migration, enums, request DTOs + validation, entity,
      repository, `POST /v1/events/ingest` (single object or array), 400 errors with details
- [ ] **v0.2-enrichment** – V2 migration (attack_type, threat_score), classifier +
      threat score logic, unit tests
- [ ] **v0.3-stats** – `GET /v1/stats/summary`
- [ ] **v0.4-samples** – `GET /v1/events/samples` with limit/offset pagination
- [ ] **v0.5-generator** – data generator with attack waves
- [ ] **v1.0** – integration test, README, app service in docker-compose

## Key decisions
- **Storage: PostgreSQL**, one flat `security_event` table. Nested `rule` and
  `geoLocation` are flattened into columns (`rule_*`, `geo_*`) so they can be filtered,
  grouped, and indexed directly. (README will discuss a columnar store like ClickHouse
  for real big-data scale.)
- **Surrogate primary key** (`id BIGINT identity`). `event_id` is stored but not unique –
  dedup/idempotency is a "more time" item.
- **Enums stored as VARCHAR** (`@Enumerated(EnumType.STRING)`), validated in the app, not
  with DB CHECK constraints.
- **Timestamps as `TIMESTAMPTZ`**, mapped to `Instant`. The JSON `timestamp` field is stored
  in column `event_time` (avoids the SQL keyword).
- **Required fields** = fields our logic or queries depend on: eventId, timestamp, configId,
  clientIp, hostname, path, method, statusCode, rule.id, rule.severity, rule.category,
  action. Optional: policyId, userAgent, rule.name, rule.message, geoLocation,
  requestSize, responseSize.
- **Indexes** match the query patterns: `(config_id, event_time)` for stats/samples
  filtered by config + time range, `(event_time)` for queries without configId.
