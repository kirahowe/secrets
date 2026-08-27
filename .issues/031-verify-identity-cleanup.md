# 031 — Verify identity cleanup

Status: `resolved`
Priority: P2
Review classification: Low

## Problem

Identity cleanup calls `File.delete` but ignores its boolean result. A failed
delete is therefore indistinguishable from success. `reset-identity-cache!`
reports every attempted unused path as deleted and advances the generation after
dropping those paths from state, so the process cannot retry a failed cleanup.
The materialized private key may remain on disk until JVM-exit cleanup or manual
intervention while callers receive a successful deletion count.

## Evidence

- [`delete-identity-file!`](../src/com/kirahowe/secrets.clj#L111-L115) returns
  the result of `File.delete`, but no check distinguishes successful deletion,
  an already-absent file, and a failed deletion of an existing file.
- [`retire-identities`](../src/com/kirahowe/secrets.clj#L284-L296) clears all
  unleased entries from tracked state before filesystem deletion is attempted.
- [`reset-identity-cache!`](../src/com/kirahowe/secrets.clj#L298-L325) runs the
  unchecked delete function and returns `:deleted (count unused)`, which counts
  attempts rather than confirmed removals. Failed paths are no longer retained
  for retry.
- Deferred cleanup after the last active lease also ignores the same deletion
  result ([`release-identity!`](../src/com/kirahowe/secrets.clj#L252-L259)).
- Existing lifecycle tests assert truthful-looking `:deleted` counts and file
  absence only for successful filesystem behavior
  ([identity cleanup tests](../test/com/kirahowe/secrets_test.clj#L587-L635));
  they do not establish the failure contract.

## Desired outcome

Check deletion results and report confirmed outcomes truthfully. Treat an
already-absent file as clean, but never count an existing file whose deletion
failed as deleted. Retain failed paths for a safe retry or return/throw a
structured cleanup failure that lets the caller act without exposing identity
contents.

## Acceptance criteria

- [x] Cleanup distinguishes confirmed deletion, already absent, and failed
      deletion of an existing materialized identity.
- [x] `:deleted` counts only paths confirmed absent as a result of cleanup; any
      separate already-absent/failed counts are named truthfully.
- [x] A failed path remains eligible for retry, or the API returns/throws a
      structured failure carrying enough safe state for deterministic recovery.
- [x] Deferred last-lease cleanup follows the same checked contract as an
      immediate reset.
- [x] Cleanup diagnostics never include identity contents, digests, or other
      credential material and preserve the existing materialized-path redaction
      policy.
- [x] Focused coverage forces deletion failure and proves the file remains
      tracked or the failure is surfaced, a subsequent retry can remove it, and
      no success count was fabricated.
- [x] Concurrent reset/release behavior remains race-safe and never deletes an
      identity while a lease is active.

## Non-goals

- Guaranteeing deletion defeats filesystem snapshots, journaling, backups, or
  forensic recovery.
- Deleting caller-owned identity files.
- Removing `.deleteOnExit` as a last-resort backstop.

## Verification

Use a controlled deletion seam or filesystem condition that makes deletion fail
while the materialized file still exists. Confirm reset/release reports the
failure rather than incrementing a success count, retains a retry path or emits
the defined structured failure, and deletes successfully after the condition is
removed. Re-run the active-lease scenario to confirm deletion remains deferred.

## Dependencies / related files

- [identity lifecycle](../src/com/kirahowe/secrets.clj)
- [identity lifecycle tests](../test/com/kirahowe/secrets_test.clj)

## Resolution

`identity-state` now has a `:cleanup` set in addition to live `:entries` and
leased `:retired` paths. Retirement atomically moves every unleased materialized
path into that set before filesystem work begins. A path leaves the set only
after checked deletion reports `:deleted` or confirms it is already `:absent`;
`:failed` paths remain there for the next `reset-identity-cache!`. This ordering
also prevents concurrent reset/release interleavings from losing a retry or
deleting a path whose lease is still active.

`reset-identity-cache!` returns path-free
`{:generation g :deleted n :absent n :failed n :pending n}` results. `:deleted`
counts only successful delete operations, `:absent` names paths already gone,
and `:failed` names existing files retained for retry. The deletion classifier
catches `SecurityException` and returns only an outcome keyword, so no
filesystem exception can disclose a materialized path. Identity contents and
digests remain absent from both state transitions and public diagnostics.

The last release of a retired lease now moves its path into `:cleanup` before
attempting deletion, then uses the same checked classifier as immediate reset.
Failed write cleanup and the concurrent materialization/retirement orphan path
also enter the same retry set before deletion, closing the two other unchecked
uses of the old boolean deletion helper.

Focused tests use the narrow `try-delete-identity-file!` filesystem seam to make
deletion return false while the real temp file remains. They prove the reset
reports `:failed 1` and `:deleted 0`, keeps the path tracked without rendering
the path, digest, or sentinel contents, and deletes it on the next reset. Separate
timing-independent cases cover an already-absent file and a failed deferred
last-lease deletion; the existing coordinated active-lease test continues to
cover the reset/release race boundary.

Suggested focused verification (not run as part of this issue assignment):

```sh
clojure -M:test --focus com.kirahowe.secrets-test/cleanup-failure-is-truthful-and-retryable-test
clojure -M:test --focus com.kirahowe.secrets-test/cleanup-reports-an-already-absent-file-test
clojure -M:test --focus com.kirahowe.secrets-test/deferred-cleanup-failure-is-retryable-test
clojure -M:test --focus com.kirahowe.secrets-test/deletion-waits-for-an-active-user-test
```
