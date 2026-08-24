# 017 — Sender-authenticity contract

Status: `open`
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

- [ ] The project records one explicit authenticity contract and threat model,
      including who may hold public recipients and who may replace deployed
      artifacts.
- [ ] Under the accepted-channel model, deployment requires reviewed/protected
      refs, immutable artifact transfer, least-privilege writes, and no runtime
      path that overstates age as sender authentication.
- [ ] Alternatively, detached signatures bind application, environment,
      ciphertext digest, and format/domain version and are verified before
      decryption under a separately provisioned trusted public key.
- [ ] Failure behavior is closed and actionable for missing, invalid, replayed,
      wrong-app, or wrong-environment authorization evidence as applicable.
- [ ] Focused regression coverage proves a public-recipient holder with artifact
      replacement access cannot pass the selected authorization boundary.
- [ ] Documentation consistently distinguishes ciphertext integrity,
      confidentiality, sender authenticity, and repository trust.

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
