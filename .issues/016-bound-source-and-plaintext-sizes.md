# 016 — Bound source and plaintext sizes

Status: `open`
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

- [ ] Public runtime entry points define documented defaults and explicit
      configuration for source/ciphertext bytes and decrypted plaintext bytes.
- [ ] URL and InputStream copies count bytes while streaming and abort before
      writing beyond the configured bound, including unknown/chunked lengths.
- [ ] Age decryption enforces the plaintext bound during output capture rather
      than only after allocating the complete output.
- [ ] EDN loading has a defensible graph/depth/collection policy or a clearly
      documented byte-bound rationale that prevents a small input from causing
      unbounded parser allocation.
- [ ] Limit failures are distinguishable, redact sensitive content, terminate
      subprocesses/streams, and immediately remove partial plaintext files.
- [ ] Boundary tests cover exactly-at-limit, one-byte-over, misleading content
      length, unbounded stream, oversized decrypted output, and ordinary
      trusted resources.

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
