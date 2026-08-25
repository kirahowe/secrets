# 014 — Pin CI executable dependencies

Status: `resolved`
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

- [x] Every `uses:` reference is pinned to a full commit SHA with an adjacent
      version comment for auditability.
- [x] Every container image is pinned by digest, with its expected release tag
      recorded as a non-authoritative comment or metadata.
- [x] Pages deployment retains main-only/environment protections and grants
      `pages`/`id-token` writes only to the job and steps that require them.
- [x] Other jobs remain read-only by default and do not gain credentials or
      permissions while references are pinned.
- [x] Automated dependency updates, if enabled, propose reviewable SHA/digest
      changes rather than silently following tags.
- [x] A focused workflow policy check rejects mutable action and container
      references, including newly added ones.

## Resolution

Every `uses:` in `ci.yml` is now a full commit SHA with a version comment, and
the Babashka container is `babashka/babashka@sha256:bac7033b…` with
`babashka/babashka:1.13.219` kept above it as a non-authoritative comment. The
four actions release.yml already pinned reuse those exact SHAs rather than
resolving a second one for the same thing. No version moved as a side effect of
pinning: `DeLaGuardo/setup-clojure` stays 13.6.1, and every floating major was
pinned to the commit it points at today with the *concrete* version in the
comment — `# v6.1.0`, never `# v6`, since a comment reading `# v6` would be as
mutable as the tag it replaced. Newly resolved: `actions/cache` `0057852b`
(v4.3.0), `quarto-dev/quarto-actions/setup` `8a96df13` (v2.2.0, the repository
commit with the `/setup` path kept), `actions/upload-pages-artifact` `7b1f4a76`
(v4.0.0), `actions/configure-pages` `983d7736` (v5.0.0), `actions/deploy-pages`
`d6db9016` (v4.0.5). All verified against `git ls-remote --tags` and
re-verified independently during review.

Permissions were confirmed rather than restructured, which is what the issue
asked for. `ci.yml` has exactly two `permissions:` blocks: top-level
`contents: read`, and `deploy-pages` with `actions: read`, `contents: read`,
`pages: write`, `id-token: write`. No other job declares job-level permissions
at all, so none holds a Pages or id-token write. The main-only condition, the
`github-pages` environment, and the non-cancelling concurrency group are
unchanged. `build-book` keeps only the inherited `contents: read` and needs
nothing more: uploading a Pages *artifact* goes through the Actions artifact
runtime token, not `GITHUB_TOKEN` scopes — only deploying consumes it.

The enforcement is the interesting part, because pinning that nothing checks
decays on the next contribution. `com.kirahowe.secrets.workflow-policy` lives in
`build/`, so it is on the test and build classpaths and ships in no jar, and it
works on workflow *text* rather than parsed YAML — there is no YAML parser
available under babashka here, and `uses:`/`image:` references are line-oriented.
It reports one finding per violation with a distinct `:reason`, separating "not a
40-character SHA" from "pinned but carries no trailing version comment", because
a bare SHA is unreviewable and that is a different mistake from a floating tag.
A `docker://` or `./local` reference is reported as unsupported rather than
exempted; neither appears here, and an exemption invented for something absent is
how exemptions get abused.

`repository-workflows-are-pinned-test` globs `.github/workflows/*.yml` rather
than naming files, so a workflow added later is covered automatically, and it
asserts the file list is non-empty so a broken glob cannot pass vacuously. The
other three tests cover the rejection table (floating major, branch, short SHA,
full SHA with no comment, image by tag, `docker://`, `./local`), the acceptance
cases, and the parsing shapes real workflows use (`- uses:` and `uses:`, quoted
values, inline comments, comment-only lines). Verified during review that the
policy reports all five violation classes against a deliberately mutable
fixture, and that it fails against the pre-fix `ci.yml`.

`.github/dependabot.yml` enables only `github-actions`, weekly. Dependabot
updates a SHA-pinned `uses:` and rewrites the adjacent version comment, so a
bump arrives as a reviewable diff naming the commit it moves to. It is
deliberately left on the default branch: naming a `target-branch` would also
turn off Dependabot's security updates.

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
