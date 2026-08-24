# 008 — Manifest v2 unambiguous canonicalization

Status: `open`
Priority: P0
Review classification: Confirmed Medium — alpha release blocker

## Problem

The manifest value-hash encoding does not preserve nested collection types and
frames entries with delimiter characters that can also occur in values. Two
semantically different secret graphs can therefore receive the same value hash
(CWE-354). Full verification also trusts regenerated descriptors plus the
public ciphertext SHA, so a party with only a public recipient can replace
ciphertext and update that SHA while retaining a colliding old value hash.

## Evidence

- [Manifest encoding](../src/com/kirahowe/secrets/manifest.clj) at lines 78–102
  flattens nested collections without recursive type and length framing.
- [`verify!`](../src/com/kirahowe/secrets/cli.clj) at lines 1062–1086 compares
  regenerated descriptors and the publicly editable ciphertext digest.
- Confirmed collision: `{:x [{a=b c}]}` and `{:x [{a b=c}]}` are unequal but
  produce the same current value hash.
- Confirmed collection-type collision: `{:x [[1]]}` and `{:x [(1)]}` are
  unequal but produce the same current value hash.
- Confirmed end to end: ciphertext encrypted only to the public recipient was
  forged, its public SHA updated, the old colliding value hash retained, and
  full verification exited 0.
- Exploitation requires ciphertext/manifest write access and a public
  recipient. It does not reveal the private identity; it defeats the current
  value-integrity signal for colliding payloads.
- These are canonicalization/encoding collisions, not a break of the HMAC
  primitive.

## Desired outcome

Introduce a recursively typed, length-framed manifest value encoding under a
new domain/version, with an explicit and safe policy for legacy v1 manifests.

## Acceptance criteria

- [ ] Manifest v2 canonicalization recursively distinguishes maps, vectors,
      lists, sets, scalar types, keys, and values and length-frames every field.
- [ ] Ordering rules are deterministic without relying on ambiguous rendered
      text; equivalent EDN values hash identically across supported runtimes.
- [ ] The hash domain includes an explicit manifest/encoding version so v1 and
      v2 values cannot be confused.
- [ ] Verification explicitly rejects or deliberately migrates v1; it never
      silently interprets a v1 hash as v2 or reports full success without the
      selected policy being satisfied.
- [ ] Focused collision tests include `=` and `;`, nested mixed collection
      types, empty values, and ordering boundaries.
- [ ] An end-to-end regression recreates the confirmed public-recipient forgery
      and proves full verification fails.
- [ ] Manifest creation, re-encryption, and documented verification workflows
      consistently emit and consume v2.

## Non-goals

- Claiming that public-recipient encryption authenticates a sender.
- Designing a general-purpose EDN serialization format.
- Quietly supporting legacy manifests through a collision-prone fallback.

## Verification

Run focused manifest unit vectors for deterministic, injective framing, then a
real-age CLI flow that creates a valid v2 store, forges ciphertext using only a
public recipient, updates public metadata, and observes nonzero full
verification. Exercise the chosen v1 rejection or migration path explicitly.

## Dependencies / related files

- [manifest encoding and validation](../src/com/kirahowe/secrets/manifest.clj)
- [CLI manifest creation and verification](../src/com/kirahowe/secrets/cli.clj)
- [CLI verification tests](../test/com/kirahowe/secrets/cli_test.clj)
- [verification documentation](../README.md#verifying-in-ci)
