# 018 — Reduce release dependency exposure

Status: `open`
Priority: P1
Review classification: Conditional Medium

## Problem

The credential-bearing release classpath includes an old deployment library
whose resolved graph pulls in legacy S3 wagon, logging, Jackson, and Ion code.
This expands the code exposed to the Clojars token during publication.

## Evidence

- [Build dependencies](../deps.edn) use `slipset/deps-deploy` 0.2.2.
- The resolved release graph matched seven packages and 25 unique OSV
  advisories through old S3 wagon, Logback, Jackson, and Ion dependencies.
- Representative matches include
  [GHSA-25qh-j22f-pwp8](https://osv.dev/vulnerability/GHSA-25qh-j22f-pwp8),
  [GHSA-j3rv-43j4-c7qm](https://osv.dev/vulnerability/GHSA-j3rv-43j4-c7qm),
  and [GHSA-264p-99wq-f4j6](https://osv.dev/vulnerability/GHSA-264p-99wq-f4j6).
- Reachability through Clojars HTTP publication was not established, and
  deps-deploy 0.2.5 retained the old S3 branch. This is dependency exposure,
  not a claim of a confirmed reachable CVE.

## Desired outcome

Use a smaller isolated publisher that excludes unused transports and enforce a
reviewed advisory policy on the exact credential-bearing classpath.

## Acceptance criteria

- [ ] The publisher's runtime graph contains only components required for
      Clojars, with unused S3/legacy wagon branches absent.
- [ ] Publication is isolated and receives a least-privilege Clojars token only
      for the upload step.
- [ ] The reproducible release classpath is scanned against a documented policy
      before credentials are exposed.
- [ ] Advisory review records dependency path, applicability, and disposition
      without presenting raw matches as proven vulnerabilities.
- [ ] A focused local/dry-run publication proves the intended artifact uploads
      without loading removed transports or disclosing credentials.
- [ ] Release guidance documents token scope, injection, rotation, and
      non-disclosure.

## Non-goals

- Claiming all advisory matches are reachable or exploitable.
- A cosmetic version bump that retains the same unused transport graph.
- Using real publication credentials in tests.

## Verification

Record the isolated release classpath, run its advisory policy, and publish a
fixture to a local/dry-run repository. Confirm earlier build and inspection
steps cannot access the token.

## Dependencies / related files

- [release dependencies](../deps.edn)
- [release tasks](../build.clj)
- [CI workflow](../.github/workflows/ci.yml)
- [release documentation](../README.md)
