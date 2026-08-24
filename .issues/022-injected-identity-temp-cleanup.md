# 022 — Explicit injected-identity temp cleanup

Status: `open`
Priority: P2
Review classification: Low

## Problem

Raw/base64 injected private identities are materialized as owner-only temporary
files and registered only with `deleteOnExit`. Long-lived processes retain the
identity until normal JVM exit, while crashes can leave it on disk (CWE-459).
A global digest/path cache also complicates safe retirement.

## Evidence

- [Injected identity materialization](../src/com/kirahowe/secrets.clj) at lines
  55–74 uses `deleteOnExit` as its cleanup lifecycle.
- [Identity cache](../src/com/kirahowe/secrets.clj) at lines 78–139 globally
  associates digests with temporary paths.
- Files are confirmed created with mode `0600`, which limits other-user access
  but does not provide timely deletion. Crash residue depends on the temporary
  filesystem and process termination mode.

## Desired outcome

Provide explicit reset/close lifecycle deletion that is safe with concurrent
callers, while documenting unavoidable crash behavior and preferring
non-materialized or externally mounted identity sources.

## Acceptance criteria

- [ ] The public lifecycle offers explicit reset/close that deletes retired raw
      and base64 identity files promptly and is idempotent.
- [ ] Reference ownership prevents deletion while an active age invocation is
      using the file and prevents new use after retirement.
- [ ] Cache replacement and failed materialization remove orphan files; normal
      JVM shutdown remains a fallback rather than the primary lifecycle.
- [ ] Created files retain the `0600` guarantee and no identity bytes, digest,
      or path content leaks through diagnostics.
- [ ] Documentation states crash residue limitations and recommends mounted
      files or memory-backed temporary storage where available.
- [ ] Lifecycle tests cover reset, close, replacement, failure, concurrent use,
      normal shutdown hooks, and simulated stale-file cleanup policy.

## Non-goals

- Promising secure erasure on journaling/copy-on-write storage.
- Deleting caller-owned identity files.
- Weakening the existing owner-only permission guarantee.

## Verification

Materialize sentinel identities in a controlled temporary directory, exercise
concurrent acquire/close/reset sequences, and assert deletion occurs only after
the last active user. Force setup failures and cache replacement and verify no
orphan remains; separately document crash simulation limits.

## Dependencies / related files

- [runtime identity materialization and cache](../src/com/kirahowe/secrets.clj)
- [runtime tests](../test/com/kirahowe/secrets_test.clj)
- [identity injection documentation](../README.md)
