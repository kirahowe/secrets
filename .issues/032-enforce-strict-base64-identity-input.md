# 032 — Enforce strict base64 identity input

Status: `resolved`
Priority: P2
Review classification: Low

## Problem

`SECRETS_AGE_IDENTITY_B64` is documented to fail when its value is not valid
base64, but decoding uses Java's MIME decoder. That decoder deliberately ignores
characters outside the base64 alphabet. Corrupted, contaminated, or
unexpectedly transformed credential input can therefore be accepted and decoded
instead of failing closed.

## Evidence

- [`decode-b64-identity`](../src/com/kirahowe/secrets.clj#L117-L130) trims the
  ends of the value and passes it to `Base64/getMimeDecoder`, while its docstring
  and exception promise invalid base64 is rejected.
- The current test covers valid input, surrounding whitespace, and an input made
  entirely of punctuation/text, but not valid base64 with ignored punctuation
  inserted or appended
  ([`b64-identity-decode-test`](../test/com/kirahowe/secrets_test.clj#L757-L767)).
- Controlled decoding produced this result verbatim:

  ```text
  QUJD%%% decodes to ABC
  ```

  The observation demonstrates MIME-decoder permissiveness. It does not indicate
  that the decoded `ABC` is a usable age identity.

## Desired outcome

Define the exact ASCII whitespace accepted for environment transport, remove
only those permitted bytes, and decode the remainder with Java's strict Base64
decoder. Every other nonalphabet character, misplaced padding, or malformed
length must fail through the existing content-free invalid-base64 contract.

## Acceptance criteria

- [x] The accepted whitespace set is explicit and limited to documented ASCII
      whitespace needed for single- or multi-line environment values.
- [x] Only that whitespace is removed before decoding; Unicode whitespace and
      all other nonalphabet characters are rejected.
- [x] Decoding uses `Base64/getDecoder` or an equivalently strict decoder after
      normalization, not the MIME decoder.
- [x] `QUJD%%%`, punctuation inserted inside otherwise valid input, malformed
      padding, and invalid lengths all fail closed.
- [x] Valid unwrapped and documented whitespace-wrapped/multiline base64 still
      decode byte-for-byte.
- [x] Failure messages and `ex-data` name the environment variable and remedy
      without echoing any credential input or retaining a token-bearing cause.

## Resolution

`decode-b64-identity` now removes exactly ASCII space, horizontal tab, carriage
return, and line feed, then decodes with `Base64/getDecoder`. It re-encodes the
decoded bytes with the standard encoder and requires exact equality with the
normalized input. That canonicality check closes strict-decoder ambiguities such
as omitted padding and nonzero padding bits in addition to the decoder's
rejection of punctuation, misplaced padding, and malformed lengths.

All invalid-input branches construct the existing content-free remediation
error without attaching the decoder exception as a cause. The error names only
`SECRETS_AGE_IDENTITY_B64` in `ex-data`; `env-identity` still invokes decoding
before `materialize-identity!`, so rejected input cannot reach a credential temp
file.

`b64-identity-decode-test` now covers the standard alphabet's `+` and `/`
boundaries, every accepted whitespace byte at the beginning, middle, and end,
mixed multiline wrapping, punctuation in each position, Unicode whitespace,
padding variants, invalid lengths, omitted padding, and noncanonical padding
bits. `b64-identity-input-boundary-test` exercises the public environment entry
path and proves invalid input is rejected before materialization while rendered
diagnostics retain neither the token nor a cause. The runtime namespace and
production documentation state the exact accepted transport characters and
canonical encoding requirement.

## Non-goals

- Validating that decoded text is a functional age identity at the base64 layer.
- Accepting arbitrary MIME comments, punctuation, or Unicode formatting.
- Falling back to treating invalid base64 as raw identity contents.

## Verification

Exercise strict table-driven cases for alphabet boundaries, each permitted ASCII
whitespace position, `%` and other punctuation at the beginning/middle/end,
Unicode whitespace, padding variants, and invalid lengths. Confirm only the
documented normalized forms decode and render all failures to prove no input
content survives.

## Dependencies / related files

- [identity environment decoding](../src/com/kirahowe/secrets.clj)
- [identity decoding tests](../test/com/kirahowe/secrets_test.clj)
