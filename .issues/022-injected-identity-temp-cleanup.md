# 022 — Explicit injected-identity temp cleanup

Status: `resolved`
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

- [x] The public lifecycle offers explicit reset/close that deletes retired raw
      and base64 identity files promptly and is idempotent.
- [x] Reference ownership prevents deletion while an active age invocation is
      using the file and prevents new use after retirement.
- [x] Cache replacement and failed materialization remove orphan files; normal
      JVM shutdown remains a fallback rather than the primary lifecycle.
- [x] Created files retain the `0600` guarantee and no identity bytes, digest,
      or path content leaks through diagnostics.
- [x] Documentation states crash residue limitations and recommends mounted
      files or memory-backed temporary storage where available.
- [x] Lifecycle tests cover reset, close, replacement, failure, concurrent use,
      normal shutdown hooks, and simulated stale-file cleanup policy.

## Resolution

`identity-state` replaces the bare digest→path atom with
`{:generation n :entries {} :retired {}}`, deliberately the same shape issue 012
used for the Aero reader cache: one atom, a generation, retirement by wholesale
replacement, and the in-flight `delay` installed in the same `swap!` that reads
it back, so a retirement committing first sends the installing swap around
against the new generation instead of writing into a retired one. Two retirement
mechanisms in one library would be worse than one applied twice. `:retired` is
not a second mechanism — it is the waiting room for an entry whose lease outlived
its generation, keyed by path rather than digest because a temp path is unique to
one materialization and so names the held file even after a newer generation has
re-materialized the same digest.

Reference ownership is `with-identity`, a public function taking a callback
rather than a macro: the body is already deferred by the `fn`, no macro-only
capability is needed, and the style rule says not to write a macro a function can
do. `acquire-identity!` increments the user count inside the swap and decides
success from the pre-swap value via `swap-vals!`, so a retirement either commits
first — in which case acquire fails and there is nothing to use — or observes the
added user and defers deletion to the last release. Deletion never happens inside
a swap function, only after the CAS that uniquely observed the last user
releasing.

`load-secrets` is the single in-library lease site, and it covers every other
in-library route transitively: `reader-literals`/`merge-readers` →
`reader-loaded-state` → `load-secrets`, and the Aero readers through
`readers-for` to the same place.

The CLI's six decrypt sites are deliberately *not* leased, and the reasoning is
worth recording: they receive an `:identity-file` that can be a materialized temp
path, but nothing in the CLI ever calls the retirement function — a one-shot
command process has no retirement to race — so a lease there would be dead code
guarding an impossible interleaving. If the CLI ever grows a long-running mode,
that changes.

`deleteOnExit` remains registered as a backstop and is documented as such rather
than as the lifecycle. A failed materialization now deletes the partially written
file before throwing, so a `spit` that fails part-way leaves no orphan.

The diagnostics audit found two real leaks and fixed both. `write-identity!`
propagated the raw `FileNotFoundException`, whose *message is the temp path* —
and since Clojure renders `:via`, `pr-str` of any wrapper exposed it too. It now
throws a path-free `ex-info` naming only the exception class, with no cause
attached on purpose. And `validate-load-identity!` interpolated the resolved
identity path: resolution now reports provenance, so a caller-supplied path is
still named — the caller already has it and naming it is most of the message's
value — while a path this library materialized is omitted from both message and
`ex-data`.

Two further leaks were found outside this issue's files and carried forward to
issue 023, which owns exception context: `age.clj`'s `decrypt-bytes` puts
`:identity-file` in the `ex-data` of both the decryption failure and
`:plaintext-too-large`, and `cli.clj`'s `require-identity!` and `verify-keyless`
print it — the last of which contradicts a README claim that the command never
prints a materialized identity path.

Regression tests: `retirement-deletes-materialized-identities-test`,
`retirement-is-idempotent-test`, `deletion-waits-for-an-active-user-test` (a
lease held on one thread while another retires, with every wait bounded so a
regression fails rather than hangs), `new-use-after-retirement-materializes-afresh-test`,
`failed-materialization-leaves-no-orphan-test`,
`identity-diagnostics-carry-no-secret-test`, and
`permissions-survive-the-lifecycle-test`. Verified independently on disk with a
real injected identity and a real `age` decryption: one file materialized at mode
`600`, present after the load completed, gone after
`(reset-identity-cache!)` reported `{:generation 1 :deleted 1 :pending 0}`, and a
second call a no-op at `{:deleted 0 :pending 0}`.

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
