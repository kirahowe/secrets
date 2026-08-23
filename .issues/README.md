# Dogfooding backlog

Status: `open` for every item. These issues came from dogfooding the examples
on 2026-08-23. Priorities are relative ordering for the next pass; each issue
is independently ready to pick up in a clean session.

| Priority | Issue | Outcome |
| --- | --- | --- |
| P0 | [001 — Babashka without Java](001-babashka-without-java.md) | Establish a tested JVM-free consumer path, or document the exact dependency-tooling boundary and supported setup. |
| P1 | [002 — Project initialization](002-project-initialization.md) | Get a new consumer from project wiring to a verified encrypted store in at most three clear commands. |
| P1 | [003 — Doctor command](003-doctor-command.md) | Give operators safe, actionable diagnostics without exposing identities or secret values. |
| P1 | [004 — Team bootstrap workflow](004-team-bootstrap-workflow.md) | Make first-recipient creation, onboarding, offboarding, and deployment-recipient practice unambiguous and tested. |
| P2 | [005 — Reader cache lifecycle](005-reader-cache-lifecycle.md) | Make lazy caching, cached failures, reload, and process-restart semantics easy to understand and use correctly. |
