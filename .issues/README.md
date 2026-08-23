# Dogfooding backlog

These issues came from dogfooding the examples on 2026-08-23. Priorities are
relative ordering for the next pass; each open issue is independently ready to
pick up in a clean session. Completed items remain linked as decision and
verification history.

## Open

| Priority | Issue | Outcome |
| --- | --- | --- |
| P1 | [004 — Team bootstrap workflow](004-team-bootstrap-workflow.md) | Make first-recipient creation, onboarding, offboarding, and deployment-recipient practice unambiguous and tested. |
| P2 | [005 — Reader cache lifecycle](005-reader-cache-lifecycle.md) | Make lazy caching, cached failures, reload, and process-restart semantics easy to understand and use correctly. |

## Completed

| Issue | Resolution |
| --- | --- |
| [001 — Babashka without Java](001-babashka-without-java.md) | Documented and regression-tested the exact Java-free runtime boundary. |
| [003 — Doctor command](003-doctor-command.md) | Added safe structured environment diagnostics, verification capability reporting, and stable 0/1/2 exits. |
| [002 — Project initialization](002-project-initialization.md) | Added a preview-first standalone initializer and verified three-command tracked and disposable consumer flows. |
