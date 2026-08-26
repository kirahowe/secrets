# Dogfooding and alpha security backlog

These issues came from dogfooding the examples and the alpha security review
on 2026-08-23. Priorities are relative ordering for the next pass; each open
issue is independently ready to pick up in a clean session. Completed items
remain linked as decision and verification history.

## Security review classification

Under the review's trusted-repository/private-identity model, no Critical or
High findings were identified. Priorities are execution order only and do not
weaken the release gate:

- **Confirmed Medium / alpha release blockers:** 007–015. Every one of these
  issues must be resolved before alpha, regardless of whether its priority is
  P0 or P1.
- **Conditional Medium:** 016–018.
- **Low:** 019–025, of which 024–025 came from the security review of the 006
  fix rather than the original audit.

## Open

| Priority | Issue | Outcome |
| --- | --- | --- |
| P2 | [025 — Blank editor variable](025-blank-editor-variable.md) | Treat a set-but-blank editor variable as unset instead of letting it shadow the next source. |

## Completed

| Issue | Resolution |
| --- | --- |
| [001 — Babashka without Java](001-babashka-without-java.md) | Documented and regression-tested the exact Java-free runtime boundary. |
| [002 — Project initialization](002-project-initialization.md) | Added a preview-first standalone initializer and verified three-command tracked and disposable consumer flows. |
| [003 — Doctor command](003-doctor-command.md) | Added safe structured environment diagnostics, verification capability reporting, and stable 0/1/2 exits. |
| [004 — Team bootstrap workflow](004-team-bootstrap-workflow.md) | Clarified and tested first-owner bootstrap, teammate re-encryption, offboarding, and deployment-recipient practice (`48f6e55`). |
| [005 — Reader cache lifecycle](005-reader-cache-lifecycle.md) | Documented and tested native reader recreation, Aero reset, cached failures, and restart semantics (`e49294f`). |
| [006 — Age option boundary](006-age-option-boundary.md) | Closed the age argument boundary with an explicit option terminator plus `./` normalization of every path-valued argument, made blank and nil paths fail closed, and folded in the CLI secure-delete operand boundary. |
| [007 — Secure plaintext file output](007-secure-plaintext-file-output.md) | Published decrypted plaintext only through an owner-only staging file with no-follow destination validation and atomic replacement, and made non-POSIX filesystems fail closed. |
| [008 — Manifest v2 canonicalization](008-manifest-v2-canonicalization.md) | Replaced the collision-prone value encoding with typed, length-framed v2 frames hashed as lossless code units, bound the version into the HMAC key, and made verification reject v1. |
| [009 — Snapshot recipients before encryption](009-snapshot-recipients-before-encryption.md) | Read, bound and validate the recipients file once up front and encrypt to those exact values as repeated `-r`, so the pathname never reaches age. |
| [010 — Global artifact collision validation](010-global-artifact-collision-validation.md) | Replaced per-environment path comparison with one global canonical role table covering the resolved identity, and an enumerated allow-list for the three safe kinds of sharing. |
| [015 — Reproducible guarded release publication](015-guard-release-publication.md) | Build once from a clean exact tag through a worktree export, receipt the jar and pom, and let a protected credential-isolated workflow upload those exact bytes without rebuilding. |
| [011 — Race-safe initializer writes](011-race-safe-initializer-writes.md) | Proved the project root's whole ancestry untamperable before mutating anything, since babashka cannot reach anchored directory handles, and re-verified every write at the operation point. |
| [012 — Aero cache lifecycle invalidation](012-aero-cache-lifecycle-invalidation.md) | Merged the registration and its reader cache into one atom so replacing or clearing a registration retires its plaintext and cached failures, even for an equal config. |
| [014 — Pin CI executable dependencies](014-pin-ci-executable-dependencies.md) | Pinned every action to a commit SHA and the container to a digest, confirmed Pages remains the only privileged job, and added a workflow policy test plus Dependabot so pinning cannot decay. |
| [013 — Scope CI identities to consuming steps](013-scope-ci-identities.md) | Moved the documented identity onto the step that consumes it, gated and pinned the keyed jobs, and extended the workflow policy to catch a widely scoped credential in docs and workflows alike. |
| [016 — Bound source and plaintext sizes](016-bound-source-and-plaintext-sizes.md) | Bounded source, plaintext, and EDN depth through a runtime `:limits` map, enforced while bytes stream — decryption moved to `ProcessBuilder` because `sh` cannot bound its own output. |
| [018 — Reduce release dependency exposure](018-reduce-release-dependency-exposure.md) | Replaced deps-deploy with a maven-resolver publisher on its own replaced classpath, taking the credential-bearing graph from 108 jars to 25 with no S3, AWS, or logging branch left. |
| [017 — Sender-authenticity contract](017-sender-authenticity-contract.md) | Accepted the protected channel explicitly rather than adding a second key infrastructure, pinned the single-key/team asymmetry with tests, and closed the wrong-app gap the audit found. |
| [019 — Safe initializer output](019-safe-initializer-output.md) | Made path/action summaries the default and `--apply` shape, put full bodies behind a warned opt-in, and stopped the plan and status map carrying file contents at all. |
| [020 — Shell-safe generated commands](020-shell-safe-generated-commands.md) | Routed every dynamic argument in all seventeen emitted snippets through one POSIX single-quoting helper, and gave the `cat` read an option terminator. |
| [021 — Self-host documentation scripts](021-self-host-documentation-scripts.md) | Removed the unused jQuery includes rather than bundling them, stripped a Google Fonts `@import` hidden in Bootstrap's CSS, and added a hash-based CSP enforced by a build check. |
| [022 — Explicit injected-identity temp cleanup](022-injected-identity-temp-cleanup.md) | Gave materialized identities a generation-scoped lifecycle with reference-counted leases, so retirement deletes promptly but never while a decryption is reading. |
| [023 — Redact sensitive exception context](023-redact-sensitive-exception-context.md) | Replaced rendered sources and whole option maps with an allowlisted type-aware descriptor, and closed three routes by which a materialized identity path reached a diagnostic. |
| [024 — CLI flag extraction boundary](024-cli-flag-extraction-boundary.md) | Scoped `--edn` extraction to the one command that defines it and added a `--` operand terminator, closing the last place a filename influenced argument parsing. |