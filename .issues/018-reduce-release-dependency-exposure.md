# 018 — Reduce release dependency exposure

Status: `resolved`
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

- [x] The publisher's runtime graph contains only components required for
      Clojars, with unused S3/legacy wagon branches absent.
- [x] Publication is isolated and receives a least-privilege Clojars token only
      for the upload step.
- [x] The reproducible release classpath is scanned against a documented policy
      before credentials are exposed.
- [x] Advisory review records dependency path, applicability, and disposition
      without presenting raw matches as proven vulnerabilities.
- [x] A focused local/dry-run publication proves the intended artifact uploads
      without loading removed transports or disclosing credentials.
- [x] Release guidance documents token scope, injection, rotation, and
      non-disclosure.

## Resolution

`slipset/deps-deploy` is gone, and with it the whole branch that carried the
exposure: `s3-wagon-private` → `aws-maven` → the AWS Java SDK, Logback 1.0.12,
Jackson, `ion-java`, `joda-time`, and `commons-logging`. The credential-bearing
classpath went from 108 jars to 25, with zero artifacts matching `s3`, `aws`,
`logback`, `ion-java`, `jackson`, `joda-time`, or `commons-logging` — verified
independently during review.

Two cheaper routes were tried first and both fail, which is what justified
replacing the publisher rather than trimming it. Excluding
`s3-wagon-private/s3-wagon-private` makes deps-deploy fail at load with
`ClassNotFoundException: org.springframework.build.aws.maven.PrivateS3Wagon` —
it hard-references the wagon regardless of the repository being deployed to. And
a version bump keeps the branch, which the issue rules out as cosmetic.

So publication now runs through `maven-resolver` directly, from a new
`com.kirahowe.secrets.publish`. That choice matters for a reason beyond
dependency count: `maven-resolver` *is* Maven's deploy code path, so the protocol
is not reimplemented. Verified against a local recorder before the work was
dispatched, the upload is the complete and correct sequence — PUT jar, jar.sha1,
jar.md5, pom, pom.sha1, pom.md5, then GET and PUT `maven-metadata.xml` with its
checksums, every request authenticated. Clojars is a plain Maven repository over
HTTPS, which is exactly why the S3 wagon was unreachable code.

Isolation is the `:deploy` alias, and it uses `:replace-deps`/`:replace-paths`
rather than `:extra-*` deliberately: the JVM that holds the Clojars token loads
the publisher, the release guards beside it, and Maven's deploy code, and
nothing else — no `tools.build`, no library `src`, no test dependencies. Both
absences are asserted by a test rather than claimed. `build.clj`'s `deploy` task
is deleted outright, a clean cutover with no shim: the upload is deliberately
not a task in a namespace that requires `tools.build`, since requiring it would
put it on the credential-bearing classpath.

Credentials fail closed before anything else happens, and blank counts as
failure for the reason the project already applies to identity variables: a CI
runner expands a missing or misnamed secret to the empty string, so blank means
a broken release environment, and the alternative is an upload presenting an
empty token and failing downstream as an authentication error nobody attributes
to a misnamed secret. Verified: unset, blank, and missing-receipt each refuse
with a message naming the cause and never echoing a value.

The policy is enforced, not asserted. `publish_policy_test.clj` runs
`clojure -Spath -A:deploy` in a subprocess and checks the resolved set against a
committed allow-list in *both* directions, so an unreviewed addition fails and a
stale allow-list entry fails too — the list cannot rot into a rubber stamp. It
never requires the publisher, because the `:test` alias deliberately has no
maven-resolver on it. A dry-run test uploads a fixture artifact to a local
`com.sun.net.httpserver` recorder and asserts the exact PUT set, the
`Authorization` header, byte equality with the receipted jar, and that no
credential appears in stdout or stderr.

`doc/release-dependency-review.md` is the advisory record: every dependency, the
path that puts it there, its applicability, and its disposition, plus what was
removed and why. It states plainly what it is not — it does not assert that any
advisory match against the old graph was reachable, and it does not claim the
reviewed set is advisory-free. The entry for `maven-resolver-transport-file` is
the useful one: it is unused for an HTTPS repository but cannot be excluded
(the supplier then fails at construction, exactly as excluding the S3 wagon broke
deps-deploy), and hand-assembling the wiring to drop it would mean *more*
publication-relevant code, not less.

Two smaller notes. `publish-policy-test` is deliberately absent from `bb test`:
babashka cannot resolve `com.sun.net.httpserver.HttpServer`, which the recorder
needs, so `clojure -M:test` runs it and `bb.edn` now says why — an unregistered
namespace otherwise reads as an oversight. And the deploy prints three SLF4J
"no binding" lines to stderr, which is the intended state: adding a binding
would put a logging framework, the role Logback played in the removed branch,
back on the classpath holding the credential.

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
