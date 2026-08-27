# 032 — Enforce strict base64 identity input

Status: `open`
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

- [ ] The accepted whitespace set is explicit and limited to documented ASCII
      whitespace needed for single- or multi-line environment values.
- [ ] Only that whitespace is removed before decoding; Unicode whitespace and
      all other nonalphabet characters are rejected.
- [ ] Decoding uses `Base64/getDecoder` or an equivalently strict decoder after
      normalization, not the MIME decoder.
- [ ] `QUJD%%%`, punctuation inserted inside otherwise valid input, malformed
      padding, and invalid lengths all fail closed.
- [ ] Valid unwrapped and documented whitespace-wrapped/multiline base64 still
      decode byte-for-byte.
- [ ] Failure messages and `ex-data` name the environment variable and remedy
      without echoing any credential input or retaining a token-bearing cause.

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
