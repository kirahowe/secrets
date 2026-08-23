# 005 — Reader cache lifecycle

Status: `closed`
Priority: P2

## Problem

Reader literals are lazy, but their loaded result is cached per reader map. A
long-lived REPL can therefore observe a stale encrypted store after an edit,
while a decryption failure can remain cached for the lifetime of that reader
map. Native EDN users must recreate reader maps; Aero users have a reset API.
These semantics are correct for once-per-readers decryption but easy to miss.

## Evidence

- [reader-literals and merge-readers](../src/com/kirahowe/secrets.clj) use a
  delayed load shared by the returned reader functions.
- [Aero reset-cache!](../src/com/kirahowe/secrets/aero.clj) provides an
  explicit reload path for its memoized reader integration.
- [Aero tests](../test/com/kirahowe/secrets/aero_test.clj) cover cache reset;
  [runtime docs](../README.md#using-secrets-at-runtime) describe REPL use but
  should make the lifecycle contract prominent.

## Desired outcome

Make cache, reload, failure, REPL, and process-restart behavior hard to miss
while preserving once-per-reader-map decryption and avoiding silent polling.
Evaluate documentation and API ergonomics before changing behavior.

## Acceptance criteria

- [x] Native `clojure.edn` examples explicitly say to recreate the reader map
      after an encrypted-store change.
- [x] Aero examples explicitly show when to call `reset-cache!` and what it
      invalidates.
- [x] Documents that successful loads and decryption failures are cached for a
      reader map, including the reason this avoids repeated work and surprises.
- [x] Documents that a process restart creates fresh readers and therefore
      observes the current ciphertext.
- [x] REPL guidance includes a safe reload workflow without printing secret
      values or encouraging filesystem polling.
- [x] Tests cover stale-reader, reset/recreate-reader, and cached-failure
      behavior for native and Aero paths as appropriate.
- [x] Any API ergonomics proposal preserves once-per-reader-map semantics and
      does not silently poll or decrypt on every tagged literal.

## Non-goals

- Background polling, filesystem watchers, or automatic secret refresh.
- Weakening failure caching by retrying decryption on every read.
- Changing the security boundary or exposing decrypted maps in diagnostics.

## Resolution

The existing lifecycle APIs are sufficient: native callers deliberately
recreate `reader-literals` / `merge-readers` maps, while Aero callers use
`reset-cache!`. The reset clears all Aero reader/decrypted-store cache entries,
including failures, without clearing `register!`'s default configuration.
Documentation and behavioral coverage now make those boundaries explicit.
No runtime behavior or API was changed, and no polling, watcher, per-tag retry,
or automatic refresh was introduced.

## Verification

Use a temporary encrypted store: read through one native reader map, update the
ciphertext, prove it remains stable, recreate readers, and prove the new value
is observed. Repeat with an initial decryption failure, then with Aero and
`reset-cache!`. Run the existing reader and Aero tests alongside the new cases.

## Dependencies / related files

- [native reader implementation](../src/com/kirahowe/secrets.clj)
- [Aero integration](../src/com/kirahowe/secrets/aero.clj)
- [native reader tests](../test/com/kirahowe/secrets_test.clj)
- [Aero cache tests](../test/com/kirahowe/secrets/aero_test.clj)
- [runtime documentation](../README.md#using-secrets-at-runtime)
