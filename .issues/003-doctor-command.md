# 003 — Doctor command

Status: `completed`
Priority: P1

## Problem

When a secrets command fails, users need to know whether the problem is age
availability, an incorrect environment path, a missing identity, invalid
recipients, or a keyless-versus-full verification expectation. Existing
commands report useful failures at the point of action, but there is no safe
single diagnostic for the resolved configuration. Diagnostics must not turn
into a secret or identity disclosure mechanism.

## Evidence

- [CLI normalization](../src/com/kirahowe/secrets/cli.clj) resolves environment
  defaults, canonicalizes collision checks, and selects identity sources.
- [age helpers](../src/com/kirahowe/secrets/age.clj) expose availability,
  version-adjacent operations, public-key parsing, and recipient validation.
- [verify!](../src/com/kirahowe/secrets/cli.clj) already distinguishes keyless
  manifest checks from verification that can decrypt with an identity.

## Desired outcome

Provide a `doctor`-style command or equivalent diagnostic API that explains the
resolved environment safely and tells an operator what kind of verification is
possible next.

## Acceptance criteria

- [x] Reports whether age is available and its version, without dumping command
      environment or arguments.
- [x] Reports selected environment and canonical artifact paths plus existence
      for ciphertext, manifest, template, key, and recipients file.
- [x] Names the identity source (`:identity-file`, environment variable source,
      or configured/default path) and reports usability only; never prints its
      path contents, raw value, or private key text where that would expose
      material.
- [x] Reports single-key versus multi-recipient mode, recipient validity, and
      recipient count without exposing private material.
- [x] States whether `verify` can run keylessly (manifest-only) or requires a
      usable identity for full verification.
- [x] Uses stable, scriptable exit behavior: healthy, warning/action-needed,
      and invalid configuration are distinguishable and documented.
- [x] Output remains safe when environment variables contain raw or base64
      identity contents; values are never echoed.

## Non-goals

- Decrypting, printing, hashing, or sampling secret values as diagnostics.
- Automatically generating keys, changing recipients, re-encrypting, or
  rewriting configuration.
- Replacing `verify` or making a diagnostic success imply that application
  startup will succeed for every secret key.

## Verification

Focused coverage exercises healthy, warning, and invalid exits; missing and
present artifacts; absent age; single-key and multi-recipient configurations;
valid, invalid, empty, and missing recipient files; keyless/full/skipped
capability; every identity source; raw/base64 sentinel non-disclosure; public
REPL-safe return behavior; and pre-normalization CLI dispatch.

## Dependencies / related files

- [CLI command dispatcher](../src/com/kirahowe/secrets/cli.clj)
- [age integration](../src/com/kirahowe/secrets/age.clj)
- [team-CI fixture](../examples/team-ci/README.md)
- [manifest verification docs](../README.md#verifying-in-ci)
