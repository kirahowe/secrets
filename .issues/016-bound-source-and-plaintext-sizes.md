# 016 — Bound source and plaintext sizes

Status: `resolved`
Priority: P1
Review classification: Conditional Medium

## Problem

Runtime loading copies URL/InputStream sources without a byte limit, decrypts
whole inputs into byte arrays and strings, and parses the resulting EDN graph
without a bounded resource policy. An attacker-influenced source can exhaust
disk or heap and deny service (CWE-400).

## Evidence

- [Runtime source loading](../src/com/kirahowe/secrets.clj) at lines 226–244
  performs an unbounded URL/InputStream copy.
- [age byte decryption](../src/com/kirahowe/secrets/age.clj) at lines 151–174
  materializes complete byte arrays and strings.
- [Runtime EDN loading](../src/com/kirahowe/secrets.clj) at lines 278–283 parses
  the complete plaintext graph.
- Impact requires control or influence over the configured source/ciphertext,
  its response body, or decrypted content. Ordinary trusted resources have not
  been shown to exceed practical memory.

## Desired outcome

Apply documented, configurable, sane limits at every source, ciphertext,
plaintext, and parse boundary, abort promptly when exceeded, and remove partial
sensitive data.

## Acceptance criteria

- [x] Public runtime entry points define documented defaults and explicit
      configuration for source/ciphertext bytes and decrypted plaintext bytes.
- [x] URL and InputStream copies count bytes while streaming and abort before
      writing beyond the configured bound, including unknown/chunked lengths.
- [x] Age decryption enforces the plaintext bound during output capture rather
      than only after allocating the complete output.
- [x] EDN loading has a defensible graph/depth/collection policy or a clearly
      documented byte-bound rationale that prevents a small input from causing
      unbounded parser allocation.
- [x] Limit failures are distinguishable, redact sensitive content, terminate
      subprocesses/streams, and immediately remove partial plaintext files.
- [x] Boundary tests cover exactly-at-limit, one-byte-over, misleading content
      length, unbounded stream, oversized decrypted output, and ordinary
      trusted resources.

## Resolution

`secrets/default-limits` is the runtime's own `:limits` map —
`:max-source-bytes` 16 MiB, `:max-plaintext-bytes` 8 MiB, `:max-edn-depth` 100 —
merged over by the opts of `load-secrets`, `reader-literals`, and
`merge-readers`, and validated by a local `resolve-limits` that refuses a
non-map, an unknown key, or a non-positive integer. It is deliberately separate
from the CLI's `:limits` config key (issue 009, recipients): different bounds on
a different surface, and reaching across would couple the runtime to the
management tool. `age.clj` carries `default-max-plaintext-bytes` and
`default-limits` aliases it, so the figure has one definition — `age.clj` cannot
depend on `secrets.clj`.

Each bound is enforced while the bytes move. `copy-source!` counts chunk by
chunk and never writes the chunk that would cross the bound, so nothing past it
reaches the filesystem and an endless stream is abandoned rather than read to an
end it does not have. Counting actual bytes is what makes a declared length
irrelevant by construction: a `Content-Length` that lies in either direction, or
is absent, or is chunked, needs no special case.

The plaintext bound is the part `clojure.java.shell/sh` cannot express — it
materializes the complete output before any caller can see its size. Decryption
moved to `ProcessBuilder`: stderr drains on its own future (a process that fills
the stderr pipe while nobody reads it deadlocks), stdin is closed immediately so
the child cannot block on a pipe nobody will fill, and stdout drains through
`read-bounded!`, which checks the running total before every further read and on
refusal discards the buffer, kills the process (`destroy`, escalating to
`destroyForcibly` after a bounded wait), and throws carrying only the byte count
and the limit. The issue-006 argument boundary is intact: `decrypt-argv` still
applies `path-arg` to both path roles and still places `--` immediately before
the positional input, and `age-argv-shape-test` still pins that exact argv.

The EDN policy is two bounds and one deliberate absence, documented where it is
enforced. EDN has no aliasing or expansion mechanism, so a parsed graph's size is
linear in the plaintext's byte count and `:max-plaintext-bytes` already bounds
it. What a byte bound does *not* bound is parser recursion — a few hundred
kilobytes of `[[[[…` overflows the stack, and `StackOverflowError` is an `Error`
no caller should rely on catching — so `edn-max-depth` scans once, before
`clojure.edn` sees the text, skipping string literals and their `\` escapes,
character literals such as `\[`, and `;` comments, since a delimiter inside any
of those is text rather than depth. And `clojure.edn` with no custom readers
evaluates nothing, so no input of any size buys execution.

Two things the issue did not anticipate, both settled during review.

`decrypt-to-file!` does not stream to its staging file: it decrypts fully and
then writes, deliberately, because issue 007 established that decryption runs
before any staging file exists so a wrong key never creates one. There is no copy
loop to add a counter to, and the bound inherited from capture is strictly
stronger — the refusal happens before a staging file exists at all. The
owner-only staging file, the no-follow destination check, and the atomic publish
are untouched.

The 8 MiB plaintext default initially reached `bb secrets decrypt` as well, which
is the general-purpose counterpart to `bb secrets encrypt` for an arbitrary file
the operator names — so an ordinary 9 MiB file became a `:plaintext-too-large`
refusal from a documented command, which is exactly the non-goal about not
lowering defaults until documented use fails. `decrypt!` now passes its own
`max-arbitrary-plaintext-bytes` of 1 GiB, documented as a heap guard rather than
a policy: `decrypt-bytes` returns the whole plaintext as an array, so an
unbounded read is still an allocation a hostile file could choose. A store past
8 MiB is hostile or broken; an arbitrary file past it is ordinary. Confirmed
empirically that the same 9 MiB ciphertext is refused under the store default and
decrypts under the general bound, and
`decrypt-is-not-bound-by-the-secrets-store-limit-test` pins it.

Regression tests: `source-size-boundary-test`,
`misleading-and-unknown-content-length-test`, `unbounded-stream-is-refused-test`,
`plaintext-size-boundary-test`,
`oversized-plaintext-terminates-the-subprocess-test` (the controlled emitter
publishes its own pid, so process death is observed rather than inferred),
`decrypt-to-file-plaintext-bound-test`, `edn-depth-scan-test`,
`ordinary-trusted-resources-are-unaffected-test`,
`invalid-runtime-limits-fail-closed-test`, and
`decrypt-is-not-bound-by-the-secrets-store-limit-test`.

Two measured details worth keeping. `HttpURLConnection` does not truncate a body
whose `Content-Length` lies low, and raises "Premature EOF" when it lies high —
so the lying-high case is asserted as *not* a size refusal with a limit above the
real body, proving the declared figure is never consulted. And because counting
is chunked, a reported `:bytes` can exceed the limit by up to one 64 KiB chunk;
nothing past the bound is ever written or retained, and the figure means "bytes
read when the copy was abandoned".

## Non-goals

- Supporting arbitrarily large stores through a streaming EDN API.
- Treating network timeouts or cryptographic authentication as size limits.
- Lowering defaults so normal documented examples fail.

## Verification

Feed counted local streams and an HTTP fixture with fixed, absent, and
misleading lengths; assert exact boundary behavior and cleanup. Use a real or
controlled age process that emits oversized plaintext and prove the consumer
stops without retaining the full output. Exercise parser depth/graph bounds.

## Dependencies / related files

- [runtime source and EDN loading](../src/com/kirahowe/secrets.clj)
- [age decryption](../src/com/kirahowe/secrets/age.clj)
- [runtime tests](../test/com/kirahowe/secrets_test.clj)
- [runtime configuration documentation](../README.md#using-secrets-at-runtime)
