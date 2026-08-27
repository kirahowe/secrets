# 031 — Verify identity cleanup

Status: `open`
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

- [ ] Cleanup distinguishes confirmed deletion, already absent, and failed
      deletion of an existing materialized identity.
- [ ] `:deleted` counts only paths confirmed absent as a result of cleanup; any
      separate already-absent/failed counts are named truthfully.
- [ ] A failed path remains eligible for retry, or the API returns/throws a
      structured failure carrying enough safe state for deterministic recovery.
- [ ] Deferred last-lease cleanup follows the same checked contract as an
      immediate reset.
- [ ] Cleanup diagnostics never include identity contents, digests, or other
      credential material and preserve the existing materialized-path redaction
      policy.
- [ ] Focused coverage forces deletion failure and proves the file remains
      tracked or the failure is surfaced, a subsequent retry can remove it, and
      no success count was fabricated.
- [ ] Concurrent reset/release behavior remains race-safe and never deletes an
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
