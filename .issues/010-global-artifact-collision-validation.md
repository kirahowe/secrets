# 010 — Global artifact collision validation

Status: `open`
Priority: P0
Review classification: Confirmed Medium — alpha release blocker

## Problem

Configuration validation checks some path collisions within each environment
but does not model each resolved artifact's identity and role globally. The
same canonical path can therefore be assigned incompatible roles within one
environment or across environments (CWE-73), allowing a command to overwrite
keys, identities, manifests, or ciphertext.

## Evidence

- [CLI artifact normalization](../src/com/kirahowe/secrets/cli.clj) at lines
  142–155 and 195–218 omits the resolved identity from its collision model.
- [Environment validation](../src/com/kirahowe/secrets/cli.clj) at lines
  249–258 checks environments independently rather than building a global role
  table.
- Confirmed accepted configurations include an identity path equal to the
  manifest path in one environment and the `dev` ciphertext path equal to the
  `prod` key path across environments.
- A destructive command under such a configuration can overwrite private
  identity material or ciphertext, and encryption can consume private identity
  material as input. Impact requires a malformed or attacker-influenced
  configuration and running an affected command; arbitrary paths are not
  overwritten without that precondition.

## Desired outcome

Validate one global table of canonical artifact paths and semantic roles before
any command performs I/O, allowing only explicitly defined compatible sharing.

## Acceptance criteria

- [ ] Normalization includes every resolved ciphertext, manifest, template,
      key, recipients, identity, and plaintext-temporary role relevant to a
      command.
- [ ] Canonical path comparison handles relative aliases, normalization,
      symlinks where resolvable, and nonexistent leaf paths consistently.
- [ ] Incompatible same-environment and cross-environment role reuse fails
      before creating, reading as the wrong role, or modifying any artifact.
- [ ] Any compatible sharing is enumerated narrowly with rationale; sharing is
      rejected by default rather than inferred from matching path strings.
- [ ] Focused tests cover identity=manifest, ciphertext=key across environments,
      aliases to one canonical path, missing leaves, and legitimate configured
      sharing.
- [ ] Diagnostics name environments and roles without printing private
      identity content or secret values.

## Non-goals

- Preventing filesystem changes after validation; race-safe operation remains a
  separate concern.
- Prohibiting every shared read-only input when an explicit role combination is
  demonstrably safe.
- Recovering artifacts already overwritten by a prior configuration.

## Verification

Run table-driven normalization tests for every incompatible role pair within
and across two environments. For representative destructive commands, assert
rejection occurs before filesystem mutation. Exercise allowed sharing and
canonical aliases on supported platforms.

## Dependencies / related files

- [CLI normalization and collision checks](../src/com/kirahowe/secrets/cli.clj)
- [CLI configuration tests](../test/com/kirahowe/secrets/cli_test.clj)
- [configuration documentation](../README.md)
