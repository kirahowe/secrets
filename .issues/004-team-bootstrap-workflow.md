# 004 — Team bootstrap workflow

Status: `open`
Priority: P1

## Problem

The team workflow has several state-dependent steps: creating the first
recipient, creating an initial empty store, onboarding another person, and
re-encrypting an existing ciphertext. Guidance can accidentally suggest a
needless `reencrypt` before ciphertext exists, or leave unclear which public
artifact and private identity each person owns.

## Evidence

- [Team CI starter](../examples/team-ci/README.md) contains a disposable
  Alice/Bob flow and a keyless fixture.
- The root [teams guide](../README.md#teams-multiple-recipients) documents
  `keygen`, `add-recipient`, and `reencrypt` but should be checked against the
  empty-store state machine.
- [CLI recipient commands](../src/com/kirahowe/secrets/cli.clj) distinguish
  adding a recipient from re-encrypting current ciphertext.

## Desired outcome

Give a first-time maintainer an evidence-backed sequence:

1. `keygen` an identity, add the owner's public recipient, and create/set the
   initial store.
2. Add a teammate's public key and re-encrypt only once ciphertext exists.
3. Explain offboarding, old-copy limitations, underlying-value rotation, and a
   separate deployment recipient.

## Acceptance criteria

- [ ] Documents and tests the sequence keygen → add own public recipient →
      set/new → add teammate → reencrypt.
- [ ] Explicitly distinguishes an initial empty store from an existing
      ciphertext; adding recipients before the first store does not imply a
      pointless or failing re-encryption.
- [ ] Automated Alice/Bob flow proves both recipients can read after
      re-encryption and does not print values or commit identities.
- [ ] Onboarding and offboarding guidance covers committed recipient lists,
      future ciphertext access, and the fact that old clones/backups cannot be
      revoked.
- [ ] Guidance requires rotating underlying secret values after a compromised
      identity or old ciphertext, not merely changing recipients.
- [ ] Deployment guidance uses a separate recipient and injects only its
      private identity through the supported secret mechanism.
- [ ] Public recipients, ciphertext, manifest, and safe templates are clearly
      separated from private identities and plaintext.

## Non-goals

- Revoking already downloaded ciphertext or recovering a lost private key.
- Making the CLI manage team membership, secure key backup, or organizational
  approval policy.
- Committing generated identities or real credential values in fixtures.

## Verification

Run the committed keyless fixture, then run the disposable team demo from an
empty directory and inspect its recipients, ciphertext, and manifest. Add a
test for the no-ciphertext initial state and a test that re-encryption changes
the recipient set without exposing plaintext.

## Dependencies / related files

- [team-CI example](../examples/team-ci/README.md)
- [team demo script](../examples/team-ci/scripts/team-demo.sh)
- [recipient CLI implementation](../src/com/kirahowe/secrets/cli.clj)
- [production/team documentation](../README.md#teams-multiple-recipients)
