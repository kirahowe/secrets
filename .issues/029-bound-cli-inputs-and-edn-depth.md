# 029 — Bound CLI inputs and EDN depth

Status: `resolved`
Priority: P1
Review classification: Conditional Medium / alpha release blocker

## Problem

Several CLI trust boundaries read an entire file or stdin into memory with
`slurp`, and CLI EDN parsing does not apply the runtime's nesting-depth scan.
An attacker-influenced plaintext, pipe, manifest, or read-only recipients file
can therefore choose heap consumption or drive the recursive EDN parser into a
`StackOverflowError`. The impact is denial of service in the process running the
CLI; it is conditional on an untrusted or accidentally extreme input reaching
one of these operator-facing boundaries.

The arbitrary-file decrypt command is related: it permits age to produce a
1 GiB byte array before writing it to stdout. A numeric cap avoids literal
infinity but still lets one input request a process-sized contiguous allocation.

## Evidence

- [`write-secrets!`](../src/com/kirahowe/secrets/cli.clj#L860-L880) slurps the
  whole editor/plaintext file before validating it. [`set-secret!`](../src/com/kirahowe/secrets/cli.clj#L1050-L1082)
  likewise slurps all of stdin before checking blankness or parsing `--edn`.
- The read-only [`read-recipients`](../src/com/kirahowe/secrets/cli.clj#L574-L588)
  path explicitly documents itself as unbounded and slurps the whole recipients
  file for `recipients` and `doctor`. This is separate from encryption's bounded
  `recipient-snapshot` path.
- [`read-supported-manifest`](../src/com/kirahowe/secrets/cli.clj#L1339-L1359)
  and [`manifest-state`](../src/com/kirahowe/secrets/cli.clj#L1577-L1594) slurp
  complete manifests before parsing them.
- CLI [`parse-edn`](../src/com/kirahowe/secrets/cli.clj#L697-L708) reads EDN
  without a nesting-depth check. By contrast, runtime
  [`read-secrets-edn`](../src/com/kirahowe/secrets.clj#L730-L772) scans nesting
  and rejects input beyond `:max-edn-depth` before invoking the parser.
- Controlled input consisting of 200,000 `[` characters produced this result
  verbatim:

  ```text
  StackOverflowError
  ```

- [`max-arbitrary-plaintext-bytes`](../src/com/kirahowe/secrets/cli.clj#L1194-L1205)
  is `1073741824`, and [`decrypt!`](../src/com/kirahowe/secrets/cli.clj#L1207-L1225)
  calls `age/decrypt-bytes` and only then writes the complete byte array to
  stdout. This is related allocation scope, not evidence that ordinary secrets
  stores are allowed to reach 1 GiB.

## Desired outcome

Apply bounded reads at every CLI file/stdin boundary and share one safe EDN
policy, including depth checking, between runtime and CLI parsing. Preserve
binary-safe arbitrary decryption while streaming bounded plaintext directly to
stdout instead of materializing the entire maximum-sized result on the heap.

## Acceptance criteria

- [x] Plaintext/editor files and stdin are bounded while being read, with limits
      enforced before a full oversized value is retained.
- [x] Manifest reads and read-only recipient listing/doctor reads have explicit
      byte and entry limits consistent with encryption's recipient policy.
- [x] Every CLI EDN path applies the same maximum-depth scanner and safe parse
      diagnostics as the runtime before recursive parsing begins.
- [x] Oversized and over-depth inputs fail with stable content-free reasons and
      configured/observed bounds, without echoing input content.
- [x] A 200,000-opener EDN input fails normally before `clojure.edn` is called
      and never raises `StackOverflowError`.
- [x] Arbitrary-file decryption streams binary plaintext to stdout under a
      deliberate bound and does not allocate a byte array sized to the whole
      output.
- [x] Boundary coverage includes exact-limit and one-byte/one-level-over cases
      for plaintext, stdin, manifests, recipient diagnostics, and streamed
      decrypt output.

## Non-goals

- Applying the secrets-store 8 MiB policy unchanged to every legitimate
  arbitrary file.
- Reading only a prefix and treating truncated EDN as a complete value.
- Catching `StackOverflowError` after recursive parsing instead of preventing
  excessive depth.

## Verification

Exercise each boundary at its exact configured limit and immediately over it.
Use deeply nested but small EDN and the controlled 200,000-opener case to confirm
pre-parse rejection without an `Error`. Decrypt a binary fixture larger than the
stream buffer to stdout, compare its bytes, and observe that output is written
incrementally under the configured cap.

## Dependencies / related files

- [CLI input and decrypt paths](../src/com/kirahowe/secrets/cli.clj)
- [runtime limits and EDN depth policy](../src/com/kirahowe/secrets.clj)
- [age process streaming](../src/com/kirahowe/secrets/age.clj)
- [CLI tests](../test/com/kirahowe/secrets/cli_test.clj)
- [runtime tests](../test/com/kirahowe/secrets_test.clj)

## Resolution

CLI limits now inherit the runtime's plaintext-byte and EDN-depth policy and add
explicit manifest byte/entry limits alongside the existing recipient
byte/entry/line limits. Fixed-size bounded readers cover templates, edited
plaintext, stdin, manifests, and every recipient command. Overflow stops after
a bounded chunk (one byte beyond the remaining allowance for byte streams) and
reports only a stable reason, the configured limit, and the observed byte or
entry count.

Runtime and CLI EDN routes now use the same safe `secrets/parse-edn` boundary.
It scans depth before invoking `clojure.edn`, distinguishes empty, extra-value,
over-depth, and malformed input, and keeps only allowlisted numeric location or
depth metadata. Editor plaintext, stdin `--edn`, key paths, decrypted stores,
verification manifests, and doctor manifests all use that policy.

`age/decrypt-to-stream!` copies binary plaintext from the age process to the
caller's output stream in fixed-size chunks, enforces the plaintext cap while
age is producing output, and kills the subprocess at the first byte beyond the
bound. The arbitrary CLI decrypt command writes through this API directly to
stdout; its 1 GiB command policy no longer implies a 1 GiB contiguous byte
array.

Focused coverage exercises exact and immediately-over plaintext files, stdin,
manifest bytes and entries, read-only recipient bytes and entries (including
doctor's content-free bounded state), EDN depth, the 200,000-opener scan, and
binary streamed decrypt output larger than the copy buffer.

Suggested focused verification (not run as part of this issue assignment):

```sh
clojure -M:test --focus com.kirahowe.secrets-test/edn-depth-scan-test
clojure -M:test --focus com.kirahowe.secrets-cli-test/cli-depth-bomb-is-rejected-before-recursive-parse-test
clojure -M:test --focus com.kirahowe.secrets-cli-test/decrypt-to-stream-boundaries-test
clojure -M:test --focus com.kirahowe.secrets-cli-test/read-only-recipient-boundaries-test
clojure -M:test --focus com.kirahowe.secrets-cli-test/plaintext-file-and-stdin-byte-boundaries-test
clojure -M:test --focus com.kirahowe.secrets-cli-test/manifest-byte-and-entry-boundaries-test
```
