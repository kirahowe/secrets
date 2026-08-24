# 008 — Manifest v2 unambiguous canonicalization

Status: `resolved`
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

- [x] Manifest v2 canonicalization recursively distinguishes maps, vectors,
      lists, sets, scalar types, keys, and values and length-frames every field.
- [x] Ordering rules are deterministic without relying on ambiguous rendered
      text; equivalent EDN values hash identically across supported runtimes.
- [x] The hash domain includes an explicit manifest/encoding version so v1 and
      v2 values cannot be confused.
- [x] Verification explicitly rejects or deliberately migrates v1; it never
      silently interprets a v1 hash as v2 or reports full success without the
      selected policy being satisfied.
- [x] Focused collision tests include `=` and `;`, nested mixed collection
      types, empty values, and ordering boundaries.
- [x] An end-to-end regression recreates the confirmed public-recipient forgery
      and proves full verification fails.
- [x] Manifest creation, re-encryption, and documented verification workflows
      consistently emit and consume v2.

## Resolution

Every value now encodes to exactly one frame, `<tag>:<code-unit-count>:<payload>`,
nested for collections, in `encode` in
[manifest.clj](../src/com/kirahowe/secrets/manifest.clj). The tag comes from a
`tags` map with one entry per `value-type` result, so a vector, a list and a
set holding equal elements encode differently; the length prefix is what
removes the need to escape anything, since a `=` or `;` inside a payload can no
longer be read as structure. Map entries (key frame followed by value frame)
and set elements are sorted by their encoded form, so hash-map and hash-set
iteration order cannot reach the hash; vector and list order is preserved
because it is semantic.

Two things about the encoding are not obvious and are load-bearing.

The framing length counts *code units*, not encoded bytes, and `vhash` feeds
the encoding to HMAC through `utf16-bytes`, which copies each code unit out as
a big-endian byte pair rather than calling `String.getBytes`. The first
implementation used UTF-8 byte lengths and `getBytes` for the hash input, and
that was still not injective: every JDK charset *substitutes* for an unpaired
surrogate — `?` under UTF-8, U+FFFD under UTF-16BE — so `"\ud800"`, `"\ud801"`
and a literal `"?"` all hashed identically (`974196fb0ccc248f`). `clojure.edn`
reads `"\ud800"` back, so such a value reaches the manifest from an ordinary
secrets file. Copying code units directly is lossless for any Java String, and
counting them is also one fewer allocation per frame than measuring bytes was.

Path ordering in `entries` moved off rendered text for the same reason the
value encoding did. The old comparator was `(compare (pr-str a) (pr-str b))`,
and `pr-str` is ambiguous across path *elements*: the paths `[a b]` and
`[(symbol "a b")]` render identically, the comparator called them equal, and
the `sorted-map-by` silently dropped one of the two manifest lines. The
comparator now compares `encode`d paths. Such a key is not EDN-readable, so no
encrypted file can carry one, but `entries` is public and its ordering has to
be total for any Clojure data.

The version lives in the HMAC key: `hmac-key` derives from
`com.kirahowe.secrets/manifest-v2`, so the same value under two encoding
versions cannot produce the same `:vhash` by construction. That is the single
version mechanism — the HMAC *message* is deliberately not additionally
prefixed. v1 is rejected, not migrated: `read-supported-manifest` accepts only
`2` and returns drift for everything else before any diffing, and doctor
reports `:unsupported`. A pre-alpha format with no released consumers does not
earn a migration path, and a fallback would have been exactly the
collision-prone route the issue names as a non-goal.

Note when reviewing the first regeneration: manifest line order changes, since
paths now sort by type tag then payload rather than by rendered text. Cosmetic,
but a v1→v2 diff is not only the version line.

Regression tests: `manifest-encoding-is-injective-test` (the two confirmed v1
collisions, delimiter and digit payloads, frame-lookalike strings, nested mixed
collection types, all six empty values distinct, ordering boundaries including a
>8-entry `PersistentHashMap`, code-unit framing, and unpaired surrogates),
`manifest-entry-paths-do-not-collapse-test`,
`manifest-entry-order-is-total-and-stable-test`, `v1-manifest-is-rejected-test`,
and `public-recipient-forgery-fails-verification-test` — the last builds a valid
v2 store, derives the public recipient, re-encrypts one of the confirmed
v1-colliding values to that recipient alone, refreshes `:ciphertext-sha` while
leaving every committed `:vhash` untouched, and asserts full verification exits
nonzero. Against the pre-fix source that test reported `✓ dev — manifest
matches` and exit 0.

Two adjacent things had to change with it. `verify-version-gate-test` used
`:version 2` as its unsupported-version sentinel, so it would have silently
stopped testing the gate; its sentinel is now `3`. And
`examples/team-ci/fixture/secrets.edn.manifest` is a committed v1 manifest that
this repo's own CI verifies keylessly, so it was regenerated — leaving it would
have turned CI red on a correct change.

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
