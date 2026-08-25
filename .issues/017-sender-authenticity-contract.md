# 017 — Sender-authenticity contract

Status: `resolved`
Priority: P2
Review classification: Conditional Medium

## Problem

Age authenticates ciphertext integrity for its encrypted payload but does not
identify or authorize the sender. Runtime code directly parses successfully
decrypted EDN, so anyone holding a public recipient who can replace deployed
ciphertext can author a chosen configuration (CWE-345). The repository is
currently documented as the integrity boundary, but the operational contract
is not enforced or made explicit at every deployment path.

## Evidence

- [Runtime loading](../src/com/kirahowe/secrets.clj) accepts authenticated age
  plaintext and parses it as configuration without a sender signature.
- [Repository caveats and deployment guidance](../README.md) already describe
  the repository/deployment channel as an integrity boundary.
- A public age recipient is intentionally shareable and permits encryption; it
  is not a signing key. Exploitation requires both that public recipient and
  the ability to replace the ciphertext consumed by the application.
- This does not imply that age encryption is broken or that a ciphertext can be
  modified without detection; the missing property is sender authorization.

## Desired outcome

Choose, document, and enforce one sender-authenticity model: either accept a
protected repository/deployment channel as the explicit integrity boundary, or
verify a detached signature bound to application, environment, and ciphertext
under a separately trusted key.

## Acceptance criteria

- [x] The project records one explicit authenticity contract and threat model,
      including who may hold public recipients and who may replace deployed
      artifacts.
- [x] Under the accepted-channel model, deployment requires reviewed/protected
      refs, immutable artifact transfer, least-privilege writes, and no runtime
      path that overstates age as sender authentication.
- [x] Alternatively, detached signatures bind application, environment,
      ciphertext digest, and format/domain version and are verified before
      decryption under a separately provisioned trusted public key.
      *(Not selected — see the resolution. The criteria are alternatives.)*
- [x] Failure behavior is closed and actionable for missing, invalid, replayed,
      wrong-app, or wrong-environment authorization evidence as applicable.
- [x] Focused regression coverage proves a public-recipient holder with artifact
      replacement access cannot pass the selected authorization boundary.
- [x] Documentation consistently distinguishes ciphertext integrity,
      confidentiality, sender authenticity, and repository trust.

## Resolution

The **accepted protected-channel model** was chosen, not detached signatures.
The library's premise is one age key and no other key infrastructure — "no GPG
keyrings, no KMS, no vault to run". Signatures would require every consumer to
provision, distribute, and rotate a second separately trusted key, add a signing
step to every write path, and ship a sidecar artifact: a categorically larger
operational surface than this problem warrants at this scale. The issue's own
non-goals permit exactly this choice, conditional on the model being
"deliberately accepted and fully enforced", so the work is the enforcement half.

The README gained one explicit contract section that keeps four properties apart
instead of letting them run together: confidentiality and ciphertext integrity
(age gives both), sender authenticity (age gives none — a public recipient is
shareable by design and authorizes *encryption*, not authorship), and repository
trust (a requirement on the operator, not a property of the tool). It then names
who may hold a public recipient (anyone: they are committed), who may replace a
deployed artifact (whoever can write the repository or the deployment channel),
the resulting trusted computing base, and what accepting that channel demands:
reviewed protected refs, immutable artifact transfer, least-privilege writes.
This repository's own controls are cited as the worked example, which is only
possible because 013, 014 and 015 landed first.

The substance is the single-key/team asymmetry, which was previously a footnote.
In single-key mode a public-recipient holder cannot recompute a `:vhash`, because
the HMAC key derives from the private identity — issue 008's
`public-recipient-forgery-fails-verification-test` already proves keyed `verify`
catches that forgery, so it was cross-referenced rather than duplicated. In team
mode there is no shared private key, so the manifest has no `:vhash` at all and a
holder of any listed public key can replace the ciphertext with a chosen payload,
regenerate the structure-only manifest, refresh `:ciphertext-sha`, and pass full
verification. `team-mode-manifest-is-not-a-value-integrity-signal-test` asserts
exactly that — a test that pins a documented boundary rather than reporting a
bug — and asserts *why* it passes (no entry carries a `:vhash`), plus that the
forgery necessarily rewrites two committed files, which is what makes it
reviewable. If it ever starts failing, the contract is what needs updating.

A docstring audit covered the four `src` namespaces and the book chapters for
language that could read as authentication of an author. Nothing overstated age
outright, but several places were silent exactly where a reader supplies
"authenticated", so `com.kirahowe.secrets`, `age.clj` (namespace and
`decrypt-bytes`), `manifest.clj`, and `verify!`/`verify-one` now state
affirmatively that success means readability and agreement, never authorship.
One user-facing string changed: the keyless success line said "freshness
verified", and now says "ciphertext agrees with the manifest".

That audit turned up a real gap, and it is fixed rather than recorded. `:app` was
written into every manifest by `manifest/render` and read back by *nothing* —
`read-supported-manifest` gated only on `:version`. So a manifest belonging to
another project whose key paths happened to agree was diffed as a shape, and in
team mode, with no `:vhash`es to disagree, a foreign structure-only manifest with
a refreshed `:ciphertext-sha` verified clean. `verify` now refuses a manifest
whose `:app` is not the configured one, or that records none, as drift — one
`cond` branch beside the version gate, same status and exit code. That is the
wrong-app half of criterion 4, closed. Covered by
`wrong-app-manifest-is-rejected-test` and confirmed against the real CLI:
`✗ dev — manifest describes app "other-app" but this project is
"kira-secrets-demo".`

The rest of criterion 4 is stated as inapplicable rather than left looking
unaddressed: with no signature there is nothing to be missing, invalid, or
replayed, and a wrong *environment* is a misconfigured path — environments are
separate files at separately configured paths, with no cryptographic binding to
an environment name — which `doctor` reports per environment.

## Non-goals

- Implying that age encryption signs messages or hiding public recipients.
- Solving authorization for an attacker who controls the selected trust root.
- Adding detached signatures if the protected-channel model is deliberately
  accepted and fully enforced.

## Verification

Model two identities: an authorized release path and a party holding only the
public recipient. Replace a deployed ciphertext authored by the latter and
prove the chosen boundary rejects it, or that protected deployment controls
make replacement outside the trusted path impossible and are policy-checked.
Exercise app/environment replay boundaries if signatures are selected.

## Dependencies / related files

- [runtime loading](../src/com/kirahowe/secrets.clj)
- [manifest support](../src/com/kirahowe/secrets/manifest.clj)
- [CLI verification](../src/com/kirahowe/secrets/cli.clj)
- [security and deployment documentation](../README.md)
- [CI workflow](../.github/workflows/ci.yml)
