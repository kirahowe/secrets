# 010 — Global artifact collision validation

Status: `resolved`
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

- [x] Normalization includes every resolved ciphertext, manifest, template,
      key, recipients, identity, and plaintext-temporary role relevant to a
      command.
- [x] Canonical path comparison handles relative aliases, normalization,
      symlinks where resolvable, and nonexistent leaf paths consistently.
- [x] Incompatible same-environment and cross-environment role reuse fails
      before creating, reading as the wrong role, or modifying any artifact.
- [x] Any compatible sharing is enumerated narrowly with rationale; sharing is
      rejected by default rather than inferred from matching path strings.
- [x] Focused tests cover identity=manifest, ciphertext=key across environments,
      aliases to one canonical path, missing leaves, and legitimate configured
      sharing.
- [x] Diagnostics name environments and roles without printing private
      identity content or secret values.

## Resolution

Collision validation moved out of `normalize-environment` and into
`normalize-config`, which now normalizes every environment first and then
checks one global table. `artifact-entries` emits an
`{:environment :role :path :canonical}` entry per path-valued artifact,
`validate-artifact-roles!` groups by canonical path, and a group of more than
one entry is allowed only when its role set appears in `compatible-role-sets`.

Two things the old model left out, both of which the issue confirmed as
accepted configurations. The first is the *resolved* `:identity-file` — the
value commands actually read, `(or env-identity explicit-identity key-file)` —
which was absent from the role list entirely, so an identity path equal to a
manifest path passed. The second is that environments were checked
independently, so `dev`'s ciphertext path equal to `prod`'s key path passed.
Both are now rejected; verified accepted against the pre-fix tree and rejected
against this one.

Compatible sharing is an enumerated allow-list, not an inference:
`#{:key-file :identity-file}` or either alone (one identity artifact —
`:identity-file` *defaults* to `:key-file`, and `:key-file` defaults to one
app-wide path that several environments legitimately share, which
`sharing-environments` reports), `#{:recipients-file}` alone (a committed
read-only list of public keys), and `#{:template}` alone (a read-only example
file). `#{:secrets-file}` and `#{:manifest}` are deliberately absent: two
environments writing one ciphertext, or one manifest, is a configuration bug
rather than sharing.

Modelling the resolved identity has a deliberate consequence worth recording: a
`SECRETS_AGE_IDENTITY*` variable wins over a configured `:identity-file`, so
with one set, a configured identity path that equals a manifest path is *not*
rejected — nothing reads it. The tests neutralize `identity-from-env` rather
than skipping, so they are deterministic on any machine.

`.getCanonicalPath` stays as the comparison, but an `IOException` from it is now
a configuration error naming the environment and role. Falling through to a
string comparison there would let exactly the paths hardest to reason about
skip the check. The `validate-artifact-roles!` docstring records that
canonicalization resolves the configuration as it reads now and is not a TOCTOU
defence, since race-safe operation is a separate concern.

The acceptance criteria's "plaintext-temporary role" is not in the table because
nothing in a configuration can express it: plaintext temporaries come from
`owner-only-temp-file!` and `sibling-temp-file!` at command time, with names the
OS makes unique, so they cannot alias a configured artifact.

Regression tests: `incompatible-artifact-roles-are-rejected-test` (eight rows,
each asserting the diagnostic names both environment-and-role tokens),
`compatible-artifact-sharing-is-allowed-test` (including that
`sharing-environments` still reports both environments for one app-wide key),
`canonical-aliases-collide-test` (a `./x/..` detour, a trailing slash, and a
real symlink), `missing-leaf-paths-are-compared-consistently-test`,
`role-collision-is-rejected-before-any-filesystem-write-test` (`keygen` and
`set` both throw, no `age`/`age-keygen` argv is recorded, and no target file
exists afterwards), and `unresolvable-artifact-path-fails-closed-test`.

Two notes for whoever reads this next. The `dev`-ciphertext-equals-`prod`-key
configuration only reproduces with a `.age` ciphertext name — a non-`.age`
`:secrets-file` trips the earlier derived-template/manifest check first, which
masked the gap. And `book/chapters/secrets_book/manifest.clj` `assoc-in`s an
`:identity-file` onto an already-normalized config, which bypasses validation
by construction; the value it sets equals that environment's `:key-file`, so it
would be allowed anyway, but post-normalization mutation is unchecked.

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
