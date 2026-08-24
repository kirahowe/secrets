# 013 — Scope CI identities to consuming steps

Status: `open`
Priority: P1
Review classification: Confirmed Medium — alpha release blocker

## Problem

The production documentation example places a private age identity in the job
environment. Checkout, installation, and mutable setup actions therefore
inherit it even though only the verification step needs the credential
(CWE-522, CWE-829). This unnecessarily expands the secret's exposure to
third-party and repository-controlled code.

## Evidence

- [Production book source](../book/chapters/secrets_book/production.clj) at
  lines 159–169 declares the private identity at job scope before checkout,
  setup, and verification.
- [The root CI guidance](../README.md) nearby already demonstrates safer
  step-scoped secret injection.
- Exposure requires a compromised/malicious inherited step or untrusted code
  executed in the credential-bearing job. The review did not establish that a
  referenced action is currently compromised.

## Desired outcome

Make the production example grant the identity only to the exact trusted
verification step, exclude keyed execution for untrusted pull requests, and
pin every action used in that path.

## Acceptance criteria

- [ ] The private identity secret is defined only on the command step that
      consumes it; checkout, setup, install, cache, and other steps do not
      inherit it.
- [ ] Untrusted/fork pull-request workflows cannot enter the keyed verification
      path or receive an equivalent private identity through another variable.
- [ ] Every referenced action in the example is pinned to a reviewed full
      commit SHA with a human-readable version comment.
- [ ] Source prose explains step scope, trusted-event gating, least workflow
      permissions, and why public-recipient data is not a private identity.
- [ ] The rendered documentation is regenerated from source and contains no
      stale job-scoped identity example.
- [ ] A focused source/rendered-doc regression detects job-scoped credential
      placement and mutable action references without embedding a real secret.

## Non-goals

- Guaranteeing the security of GitHub-hosted runners or a reviewed action
  commit.
- Passing secrets to untrusted pull-request code for convenience.
- Broadly redesigning every CI example unrelated to private identity use.

## Verification

Render the book from source, inspect the resulting workflow example, and run
the focused documentation check. Confirm the identity variable appears only in
the verify step, fork/untrusted events are excluded, permissions are minimal,
and all action references are immutable.

## Dependencies / related files

- [production book source](../book/chapters/secrets_book/production.clj)
- [rendered book artifacts](../book/rendered)
- [root CI guidance](../README.md#verifying-in-ci)
- [repository CI workflow](../.github/workflows/ci.yml)
