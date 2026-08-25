# 013 — Scope CI identities to consuming steps

Status: `resolved`
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

- [x] The private identity secret is defined only on the command step that
      consumes it; checkout, setup, install, cache, and other steps do not
      inherit it.
- [x] Untrusted/fork pull-request workflows cannot enter the keyed verification
      path or receive an equivalent private identity through another variable.
- [x] Every referenced action in the example is pinned to a reviewed full
      commit SHA with a human-readable version comment.
- [x] Source prose explains step scope, trusted-event gating, least workflow
      permissions, and why public-recipient data is not a private identity.
- [x] The rendered documentation is regenerated from source and contains no
      stale job-scoped identity example.
- [x] A focused source/rendered-doc regression detects job-scoped credential
      placement and mutable action references without embedding a real secret.

## Resolution

All three CI examples in
[production.clj](../book/chapters/secrets_book/production.clj) were rewritten:
`SECRETS_AGE_IDENTITY` now appears only in the `env:` of the step that consumes
it, both keyed jobs carry an explicit fork-excluding `if:` and
`permissions: contents: read`, and every `uses:` is a full commit SHA with the
concrete version beside it. The keyless job gets the permissions block and the
pins but deliberately no gate, and the prose says why rather than copying the
gate everywhere: there is nothing there for an untrusted pull request to take.

The gate is explicit even though it is redundant today. A `pull_request` from a
fork receives no repository secrets, so the pre-fix example could not actually
leak the identity to one — but a job that *looks* like it grants a key to a pull
request invites the next person to "fix" the empty variable by switching to
`pull_request_target`, which runs with secrets available and a contributor's
unreviewed code checked out. The condition documents the boundary instead of
leaving it to a platform default.

Prose covers the four things the criteria ask for — step scope, the trusted-event
gate, least permissions, and why a recipients file needs none of it, since its
lines are age *public* keys that are meant to be committed and read.

The enforcement extends `com.kirahowe.secrets.workflow-policy` (added by issue
014) rather than forking it. A new rule finds an `env:` block declaring
`SECRETS_AGE_IDENTITY`, `_FILE`, or `_B64` at anything wider than step scope, and
a new `documentation-yaml-blocks` extracts fenced YAML from literate-Clojure
comment text so the same pinning and placement rules run over the book. All three
spellings are checked, including `_FILE`: it names a path rather than key
material, but what a declaration outside a step hands the steps beside it is the
ability to decrypt, and exempting one spelling would only teach a reader which
one keeps the check quiet. The namespace docstring now bounds what a text rule
claims — it reads placement and reference shape, not behaviour, and no rule here
makes a reviewed action trustworthy.

Regression tests: `documentation-workflow-examples-are-pinned-test` (globs
`book/chapters/**/*.clj` and asserts at least one YAML block was found, so a
formatting change that breaks extraction fails loudly instead of passing
vacuously), `policy-rejects-job-scoped-identity-test`,
`literate-yaml-extraction-test` (including a fenced `sh` block that must not be
treated as YAML), and `repository-workflows-have-no-job-scoped-identity-test`,
which pins the property for the repository's own workflows too. Verified during
review that the rules report both the job-scoped identity and the tagged action
for the pre-fix example shape and nothing for the step-scoped control, and that
a freshly built book contains no job-scoped identity example and no mutable
action reference.

One finding worth recording. `turtlequeue/setup-babashka@v1` — the reference the
chapter used — derefs to a commit whose message is literally "initial commit",
dated 2020-11-18: that repository never adopted the moving-major-alias
convention, so the book was telling readers to run six-year-old code under a tag
that can still be repointed at anything. It is now pinned to `d78ec657`, the
commit of the v1.8.0 release. That is a concrete argument for SHA pinning rather
than a hypothetical one.

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
