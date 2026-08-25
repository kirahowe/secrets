# 012 — Aero cache lifecycle invalidation

Status: `resolved`
Priority: P1
Review classification: Confirmed Medium — alpha release blocker

## Problem

Aero registration state and decrypted-reader cache state have different
lifecycles. Clearing or replacing a registration changes the default
configuration but leaves matching cached plaintext available, so an equal
configuration can reuse data from a retired lifecycle or tenant (CWE-672,
CWE-668).

## Evidence

- [`register!` and registration state](../src/com/kirahowe/secrets/aero.clj) at
  lines 52–68 update the default registration.
- [The Aero cache](../src/com/kirahowe/secrets/aero.clj) at lines 72–89 is held
  separately.
- [Reader lookup](../src/com/kirahowe/secrets/aero.clj) at lines 108–120 reuses
  cached values for equal configurations.
- A stale plaintext entry survives a clear or replacement today. Cross-tenant
  exposure requires a long-lived process that retires one registration and
  later installs an equal cache key for a different lifecycle; this is a
  lifecycle isolation flaw, not evidence of remote access by itself.

## Desired outcome

Retire cached plaintext and failures when their registration lifecycle ends,
without introducing races, repeated decryption, or global cross-tenant reuse.

## Acceptance criteria

- [x] Clearing a registration invalidates and releases every cache entry owned
      by that registration, including successful plaintext and cached failures.
- [x] Replacing a registration cannot reuse entries from the retired lifecycle,
      even when the new configuration compares equal.
- [x] Concurrent readers observe either the old live lifecycle or the new one;
      invalidation cannot resurrect retired entries or expose partially updated
      state.
- [x] If the API becomes lifecycle-scoped/closeable, close is idempotent and
      subsequent reads fail clearly rather than falling back to global cache.
- [x] Focused tests cover clear, equal replacement, cached failure, concurrent
      read versus invalidation, and two tenant/lifecycle owners.
- [x] Once-per-live-lifecycle caching and the documented explicit reload path
      remain efficient and deterministic.

## Resolution

The two `defonce` atoms became one: `state` holds
`{:generation 0 :config nil :cache {}}`, so there is no way to change the
registration without the cache changing in the same compare-and-set. `register!`
swaps to a fresh generation with an empty cache and *always* clears — an equal
config is precisely the case that must not share state, and `register!` is a
start-up call, so the cost is one extra decryption at start-up rather than
anything in a hot path. `reset-cache!` bumps the generation and empties the
cache while leaving the registration intact, its documented contract unchanged.

The concurrency argument is one sentence, and it is why `readers-for` had to
change shape: the delay is installed and read back out of the value that a
single `swap!` returns. If a `register!` commits first, that swap retries
against the new state and installs into the *new* cache, so a delay from a
retired generation can never be written into a live one. A reader that had
already taken its delay keeps deref'ing it, which is a reader observing the
lifecycle it was live in — permitted by the third criterion, not a resurrection.

`:generation` exists to give a lifecycle an identity tests and diagnostics can
name. It is deliberately *not* part of the cache key: replacing `:cache`
wholesale is the single retirement mechanism, and putting the generation in the
key would be a second mechanism doing the same job. A comment says so, because
the omission otherwise reads as an oversight.

Criterion 4 is satisfied vacuously and on purpose: the API did not become
lifecycle-scoped or closeable. `register!`/`reset-cache!` are the lifecycle
boundary, and a closeable handle would have been a new public surface for a
problem that a shared atom already solves.

On tenancy, the honest answer is that the cache key is the secrets config map,
so two callers passing equal maps deliberately share one decrypted store within
a lifecycle, and any distinguishing key — a `:tenant`, a different `:file` —
makes a distinct entry. The library cannot see a lifecycle boundary a caller
never expressed; a caller who needs isolation expresses it in the config, and
`register!`/`reset-cache!` retire everything at the boundary. That is documented
rather than papered over with a new tenancy mechanism.

Regression tests: `clearing-a-registration-retires-its-cache-test`,
`equal-replacement-cannot-reuse-the-retired-lifecycle-test` (asserting the two
maps really are `=` and really are not `identical?`, so the test tests what it
claims), `cached-failures-are-retired-too-test`,
`concurrent-reads-never-see-a-retired-entry-test`,
`distinct-tenant-configs-do-not-share-a-cache-entry-test`, and
`one-load-per-live-lifecycle-test`. They instrument
`secrets/reader-literals` with a sentinel loader, because the question is which
lifecycle a cached value belongs to and a decrypted value cannot name that. The
concurrent test asserts an invariant over the results — every value was produced
by the loader, for the config that read asked for, and from a load after the
round's own retirement — rather than a specific interleaving, and bounds every
`deref` so a hang fails instead of blocking the suite.

One test-fixture consequence: `with-clean-registration` previously called both
`reset-cache!` and `(register! nil)`. The second now retires the cache too, so
the first is redundant and was removed.

## Non-goals

- Filesystem polling or automatic reload when ciphertext changes.
- Decrypting on every tagged literal read.
- Treating equal configuration maps from independent lifecycles as the same
  security principal.

## Verification

Instrument the decrypt loader with distinct sentinel results. Populate one
registration, clear or replace it with an equal configuration, and prove the
next read performs a fresh load and cannot return the retired sentinel. Repeat
for cached failure and synchronized concurrent invalidation.

## Dependencies / related files

- [Aero registration and cache implementation](../src/com/kirahowe/secrets/aero.clj)
- [Aero lifecycle tests](../test/com/kirahowe/secrets/aero_test.clj)
- [runtime cache documentation](../README.md#using-secrets-at-runtime)
