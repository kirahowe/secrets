# 028 — Redact EDN parse failures

Status: `resolved`
Priority: P0
Review classification: Confirmed Medium / alpha release blocker

## Problem

Malformed decrypted EDN can place secret-bearing token text in the parser's
exception message. The runtime returns that parser failure directly. The CLI
copies `ex-message` into its parse result, stores it in later `ex-data`, and
prints it in user-facing errors. A malformed secret value can therefore leave
decrypted content in terminal output, logs, exception reporters, or retained
exception chains even though normal diagnostics are intended to be safe.

## Evidence

- [`read-secrets-edn`](../src/com/kirahowe/secrets.clj#L752-L772) performs the
  depth check and then calls `clojure.edn/read-string` directly, without
  translating parser exceptions to a content-free diagnostic.
- [`decrypt-and-read!`](../src/com/kirahowe/secrets.clj#L774-L793) preserves the
  message and cause of `ExceptionInfo` failures. It does not provide a safe
  parser-error boundary around `read-secrets-edn`.
- CLI [`parse-edn`](../src/com/kirahowe/secrets/cli.clj#L697-L708) places
  `(ex-message e)` in `:error`. [`validate-plaintext!`](../src/com/kirahowe/secrets/cli.clj#L710-L719)
  interpolates that value into output and retains it in `ex-data`; the stdin
  `--edn` path does the same
  ([`set-secret!`](../src/com/kirahowe/secrets/cli.clj#L1050-L1082)).
- Manifest verification prints the same retained parser message
  ([`read-supported-manifest`](../src/com/kirahowe/secrets/cli.clj#L1339-L1359)).
- Controlled malformed input produced this parser diagnostic verbatim:

  ```text
  Invalid number: 123SENTINELSECRET
  ```

  The observation confirms token-bearing content reaches the diagnostic; it
  does not imply every EDN parser error contains plaintext.

## Desired outcome

Use one content-free EDN parse-failure policy at runtime and in the CLI. Retain
only an allowlisted stable reason and, when the parser supplies them as numeric
metadata independent of source text, line and column. Do not retain or print the
parser's token-bearing message or cause.

## Acceptance criteria

- [x] Runtime malformed-EDN failures expose a stable allowlisted reason and
      optional numeric line/column, but no parser-generated source excerpt or
      token-bearing message.
- [x] CLI plaintext, stdin `--edn`, manifest verification, and diagnostic paths
      use the same safe parse policy.
- [x] Parser exceptions are not retained as causes when their messages or data
      may contain source text.
- [x] CLI failure maps and `ex-data` omit raw parser messages and malformed
      plaintext.
- [x] Sentinel regression coverage recursively renders runtime exception
      messages, `ex-data`, causes, CLI stdout, and CLI stderr and finds no
      `123SENTINELSECRET`.
- [x] Diagnostics still distinguish empty input, extra EDN values, excessive
      depth, and malformed syntax, and preserve safe line/column information
      when available.

## Resolution

`com.kirahowe.secrets/parse-edn` is now the sole production EDN parser boundary.
It scans nesting before parsing, requires exactly one value, and returns only
four allowlisted failure reasons: `:edn-empty`, `:edn-extra-values`,
`:edn-too-deep`, and `:edn-malformed`. Depth failures retain numeric
`:depth`/`:limit`; malformed failures extract only numeric `:line`/`:column`
from the parser exception chain. Parser messages, other exception data, source
fragments, and causes are discarded at the boundary.

Runtime loading translates a failed parse result into a new content-free
`ex-info` and deliberately omits an intermediate cause for every EDN failure.
The CLI uses the same result maps for editor plaintext, stdin `--edn`, key-path
arguments, decrypted stores used by `set`/`rm`/`verify`, committed manifests,
and doctor manifest state. CLI rendering is derived solely from the allowlisted
reason and numeric metadata; failure `ex-data` no longer carries an `:error`
copied from `ex-message`. The initializer's existing-template parser also uses
the shared boundary, eliminating the last independent production EDN parser.

Focused coverage is in `edn-parse-failures-are-content-free-test`,
`safe-edn-failure-rendering-test`,
`secret-bearing-edn-failures-are-redacted-across-cli-routes-test`, and the
initializer's invalid-template case. The sentinel tests render exception
messages, `ex-data`, causes, stdout, and stderr and assert that
`123SENTINELSECRET` and its parser diagnostic do not survive.

## Non-goals

- Suppressing parse failures or accepting malformed EDN.
- Removing actionable, content-free location metadata.
- Redacting unrelated caller-authored log messages after the library returns a
  successfully decrypted value.

## Verification

Feed malformed runtime plaintext, editor plaintext, stdin `--edn` input, and
manifest variants containing unique sentinel tokens. Recursively render every
returned/thrown diagnostic and capture CLI output. Confirm no sentinel or
source excerpt survives while stable reason and safe line/column metadata remain
usable.

## Dependencies / related files

- [runtime EDN loading](../src/com/kirahowe/secrets.clj)
- [CLI EDN parsing and validation](../src/com/kirahowe/secrets/cli.clj)
- [runtime tests](../test/com/kirahowe/secrets_test.clj)
- [CLI tests](../test/com/kirahowe/secrets/cli_test.clj)
- [initializer template parsing](../src/com/kirahowe/secrets/init.clj)
- [initializer tests](../test/com/kirahowe/secrets/init_test.clj)
