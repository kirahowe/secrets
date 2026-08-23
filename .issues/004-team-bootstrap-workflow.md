# 004 — Team bootstrap workflow

Status: `closed`
Priority: P1

## Resolution

`add-recipient!` now checks the configured ciphertext path after appending a
public recipient. Before the first ciphertext it directs the owner to create
the store with stdin-backed `set` or editor-backed `new`; once ciphertext
exists it directs the maintainer to `reencrypt`. Its arguments, return value,
and duplicate-recipient behavior are unchanged.

A focused real-age Alice/Bob test covers the complete transition from an empty
recipient list through initial store creation and teammate re-encryption. The
disposable team demo silently checks the same state boundary, exact recipient
set, and decryptability by both private identities without printing values or
identity contents.

The root and team-CI guides now separate first-owner bootstrap from changes to
existing ciphertext. They define the public/private repository boundary,
future-only onboarding and offboarding effects, immutable old-copy limits,
underlying-value rotation after compromise, and a dedicated deployment
recipient using only supported private-identity injection mechanisms.

## Evidence

- [`add-recipient!`](../src/com/kirahowe/secrets/cli.clj) chooses initial-store
  or re-encryption guidance from the configured ciphertext's existence.
- [CLI tests](../test/com/kirahowe/secrets/cli_test.clj) create real Alice and
  Bob identities, create the first store through stdin-backed `set`, assert
  state-dependent output and the exact public recipient set, and decrypt the
  final ciphertext with both identities while checking captured output.
- The [team demo](../examples/team-ci/scripts/team-demo.sh) asserts the empty
  transition and both-recipient state without emitting values or identities.
- The [root team guide](../README.md#teams-multiple-recipients) and
  [team-CI guide](../examples/team-ci/README.md) document the complete bootstrap,
  membership-change, compromise, deployment, and artifact-handling workflows.

## Desired outcome

Give a first-time maintainer an evidence-backed sequence:

1. `keygen` an identity, add the owner's public recipient, and create/set the
   initial store.
2. Add a teammate's public key and re-encrypt only once ciphertext exists.
3. Explain offboarding, old-copy limitations, underlying-value rotation, and a
   separate deployment recipient.

## Acceptance criteria

- [x] Documents and tests the sequence keygen → add own public recipient →
      set/new → add teammate → reencrypt.
- [x] Explicitly distinguishes an initial empty store from an existing
      ciphertext; adding recipients before the first store does not imply a
      pointless or failing re-encryption.
- [x] Automated Alice/Bob flow proves both recipients can read after
      re-encryption and does not print values or commit identities.
- [x] Onboarding and offboarding guidance covers committed recipient lists,
      future ciphertext access, and the fact that old clones/backups cannot be
      revoked.
- [x] Guidance requires rotating underlying secret values after a compromised
      identity or old ciphertext, not merely changing recipients.
- [x] Deployment guidance uses a separate recipient and injects only its
      private identity through the supported secret mechanism.
- [x] Public recipients, ciphertext, manifest, and safe templates are clearly
      separated from private identities and plaintext.

## Non-goals

- Revoking already downloaded ciphertext or recovering a lost private key.
- Making the CLI manage team membership, secure key backup, or organizational
  approval policy.
- Committing generated identities or real credential values in fixtures.

## Verification

Use these commands to verify the implementation and both example paths:

```sh
bb test
(cd examples/team-ci && bb secrets verify fixture)
(cd examples/team-ci && bb cleanup && bb demo && bb cleanup)
sh -n examples/team-ci/scripts/team-demo.sh
```

## Dependencies / related files

- [team-CI example](../examples/team-ci/README.md)
- [team demo script](../examples/team-ci/scripts/team-demo.sh)
- [recipient CLI implementation](../src/com/kirahowe/secrets/cli.clj)
- [production/team documentation](../README.md#teams-multiple-recipients)
