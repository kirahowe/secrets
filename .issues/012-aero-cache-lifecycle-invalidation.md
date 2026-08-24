# 012 — Aero cache lifecycle invalidation

Status: `open`
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

- [ ] Clearing a registration invalidates and releases every cache entry owned
      by that registration, including successful plaintext and cached failures.
- [ ] Replacing a registration cannot reuse entries from the retired lifecycle,
      even when the new configuration compares equal.
- [ ] Concurrent readers observe either the old live lifecycle or the new one;
      invalidation cannot resurrect retired entries or expose partially updated
      state.
- [ ] If the API becomes lifecycle-scoped/closeable, close is idempotent and
      subsequent reads fail clearly rather than falling back to global cache.
- [ ] Focused tests cover clear, equal replacement, cached failure, concurrent
      read versus invalidation, and two tenant/lifecycle owners.
- [ ] Once-per-live-lifecycle caching and the documented explicit reload path
      remain efficient and deterministic.

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
