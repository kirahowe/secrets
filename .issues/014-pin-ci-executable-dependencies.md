# 014 — Pin CI executable dependencies

Status: `open`
Priority: P1
Review classification: Confirmed Medium — alpha release blocker

## Problem

The main CI workflow executes GitHub Actions from mutable tags and runs a
Babashka container by mutable image tag. Upstream tag or registry movement can
therefore change privileged build and deployment code without a reviewed
repository change (CWE-829, CWE-494).

## Evidence

- [CI workflow](../.github/workflows/ci.yml) uses mutable action tags and a
  mutable Babashka container tag throughout.
- The Pages deployment job at lines 282–300 has `pages: write` and
  `id-token: write`, increasing the impact of changed executable dependencies
  in that job.
- This is a supply-chain exposure: exploitation requires an upstream tag,
  release, account, or registry reference to be compromised or retargeted. No
  current compromise of an action or image was established.

## Desired outcome

Make every CI executable dependency resolve to reviewed immutable content while
retaining narrowly scoped triggers and permissions and a maintainable reviewed
update path.

## Acceptance criteria

- [ ] Every `uses:` reference is pinned to a full commit SHA with an adjacent
      version comment for auditability.
- [ ] Every container image is pinned by digest, with its expected release tag
      recorded as a non-authoritative comment or metadata.
- [ ] Pages deployment retains main-only/environment protections and grants
      `pages`/`id-token` writes only to the job and steps that require them.
- [ ] Other jobs remain read-only by default and do not gain credentials or
      permissions while references are pinned.
- [ ] Automated dependency updates, if enabled, propose reviewable SHA/digest
      changes rather than silently following tags.
- [ ] A focused workflow policy check rejects mutable action and container
      references, including newly added ones.

## Non-goals

- Claiming immutable references eliminate compromise of reviewed upstream code.
- Vendoring all actions or container files into this repository.
- Unrelated changes to CI matrix coverage or release behavior.

## Verification

Parse the workflow and assert every executable action/image reference is a
full SHA or digest and every immutable reference has readable version context.
Review job-level permissions and triggers, especially Pages, and run the
workflow syntax/policy validation used by the repository.

## Dependencies / related files

- [CI workflow](../.github/workflows/ci.yml)
- [CI and Pages documentation](../README.md)
