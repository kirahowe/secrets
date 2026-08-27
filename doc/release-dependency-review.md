# Release dependency review

The publication step is the only one that holds a Clojars credential, so the
code on its classpath is reviewed rather than inherited. This is that review:
every dependency `clojure -M:deploy` resolves, the path that puts it there, and
what was decided about it.

Reviewed: 2026-08-27, for `com.kirahowe/secrets` 0.1.0.
Reproduce the exact graph with `clojure -Spath -M:deploy` and
`clojure -Stree -M:deploy` (Clojure CLI 1.12.5.1664) against
[`deps.edn`](../deps.edn)'s `:deploy` alias. The policy tests in
`test/com/kirahowe/secrets/publish_policy_test.clj` run both commands, and the
advisory gate described below scans the same resolved coordinates.

## What this document is, and is not

It records dependency path, applicability, and disposition. An OSV package
match proves that an affected version is present; it does **not** by itself
prove that the advisory-specific method and attacker-controlled input are
reachable. The review therefore removes every known match while preserving the
distinction between exposure and demonstrated exploitation. The automated scan
has no advisory ignore list: a future match fails and requires another reviewed
upgrade or removal.

## What changed

Publication used to run `slipset/deps-deploy` 0.2.2 from the `:build` alias.
That alias resolved **108 jars**; the `:deploy` alias resolves **25**.

The removed weight was one branch: `slipset/deps-deploy` →
`s3-wagon-private` 1.3.5 → `aws-maven` 4.8.0.RELEASE → the AWS Java SDK 1.12.49
(`-s3`, `-kms`, `-core`, `-sts`, `jmespath-java`), Logback 1.0.12
(`logback-classic`, `logback-core`), Jackson 2.12.x (`-core`, `-databind`,
`-annotations`, `-dataformat-cbor`), `ion-java` 1.0.2, `joda-time` 2.8.1, and
`commons-logging` 1.2. Seven of those packages matched 25 unique OSV advisories
(see [issue 018](../.issues/018-reduce-release-dependency-exposure.md)).

That branch existed to publish to an S3-backed Maven repository. This project
publishes to Clojars, which is a plain Maven repository served over HTTPS, so no
S3 wagon is ever constructed and none of the code beneath it can run. Two ways
to keep the library and drop the branch were tried and rejected:

- Excluding `s3-wagon-private/s3-wagon-private` makes deps-deploy fail at load
  with `ClassNotFoundException: org.springframework.build.aws.maven.PrivateS3Wagon`;
  it hard-references the wagon regardless of the repository being deployed to.
- A version bump keeps the same branch (0.2.5 still resolves it), which the
  issue rules out as cosmetic.

So the upload now runs through `maven-resolver` — Maven's own deploy code path,
not a reimplementation of it — from
[`com.kirahowe.secrets.publish`](../build/com/kirahowe/secrets/publish.clj).
The `:deploy` alias uses `:replace-deps` and `:replace-paths`, so the JVM
holding the token also has no `tools.build`, no library source, and no test
dependency on it.

The production entry point always deploys to the exact
`https://repo.clojars.org` origin. Repository arguments and the retired
`SECRETS_DEPLOY_REPOSITORY_URL` input are rejected before credentials are read,
an authenticated repository is constructed, or network I/O can begin. The local
HTTP recorder is injected only through the lower-level `deploy!` test seam with
fixture credentials; it is not a production repository override.

### Plexus Utils advisory disposition

The previous graph selected `org.codehaus.plexus/plexus-utils` 3.5.1 through
`maven-model`, `maven-artifact`, `maven-repository-metadata`, and
`maven-resolver-provider`. OSV records that version as affected by
[GHSA-6fmv-xxpf-w3cw](https://osv.dev/vulnerability/GHSA-6fmv-xxpf-w3cw) /
CVE-2025-67030 and fixes the 3.x line at 3.6.1. The affected surface is unsafe
path handling in `org.codehaus.plexus.util.Expand.extractFile` during archive
extraction.

Maven Central publishes both fixed 3.6.1 and 3.6.2. The upstream 3.6.2 release
states that it changes build metadata only and contains no library-code change
from 3.6.1; its published pom has no runtime dependencies. The `:deploy` alias
therefore overrides the transitive coordinate with 3.6.2: the latest reviewed
3.x maintenance release, without taking the compatibility risk of a 4.x major
upgrade. Dependency mediation replaces the already-present 3.5.1 coordinate
rather than adding another jar, so the credential-bearing graph remains 25 jars
and gains no transport, logging binding, injection container, build tool,
library source, or test dependency.

Reachability remains **not demonstrated**. The publisher constructs a
`RepositorySystemSupplier` and `DeployRequest`, then asks Maven Resolver to
deploy the receipted jar and pom. Neither the publisher nor its release guards
call `Expand`, `extractFile`, or any archive-extraction API, and the deploy input
is the locally built, digest-verified artifact rather than an attacker-selected
archive to extract. That does not excuse the package match; it explains why the
record is a conditional dependency exposure, not a claim of demonstrated
arbitrary-code execution.

## The reviewed set

Two direct deploy dependencies, plus Clojure. Everything else arrives beneath
them; the Plexus Utils override mediates an existing transitive coordinate, not
another jar.

| Dependency | Dependency path | Applicability | Disposition |
| --- | --- | --- | --- |
| `org.clojure/clojure` 1.12.4 | direct | The language the publisher is written in. | Keep. |
| `org.clojure/spec.alpha` 0.5.238 | clojure | Required by Clojure itself. | Keep. |
| `org.clojure/core.specs.alpha` 0.4.74 | clojure | Required by Clojure itself. | Keep. |
| `org.apache.maven.resolver/maven-resolver-supplier` 1.9.22 | direct | Builds a `RepositorySystem` without an injection container, which is why no Sisu/Guice stack appears below. | Keep. |
| `org.apache.maven.resolver/maven-resolver-api` 1.9.22 | supplier | Artifact, repository, session, and deploy-request types the publisher calls. | Keep. |
| `org.apache.maven.resolver/maven-resolver-spi` 1.9.22 | supplier | Transport and connector interfaces the two transports implement. | Keep. |
| `org.apache.maven.resolver/maven-resolver-util` 1.9.22 | supplier | Utilities the resolver implementation and the transports share. | Keep. |
| `org.apache.maven.resolver/maven-resolver-impl` 1.9.22 | supplier | The deployer, checksum policy, and metadata handling that perform the upload. | Keep. |
| `org.apache.maven.resolver/maven-resolver-named-locks` 1.9.22 | supplier | Locking for the local repository the session writes to. | Keep. |
| `org.apache.maven.resolver/maven-resolver-connector-basic` 1.9.22 | supplier | The connector that drives a transport, uploading artifacts and their checksums. | Keep. |
| `org.apache.maven.resolver/maven-resolver-transport-file` 1.9.22 | supplier | `file:` transport, part of the supplier's default set. Unused for an HTTPS repository; it reads and writes local paths and reaches no network. | Keep: excluding it makes the supplier fail at construction with `ClassNotFoundException: org.eclipse.aether.transport.file.FileTransporterFactory` (checked), exactly as excluding the S3 wagon broke deps-deploy. Replacing it means hand-assembling the supplier's wiring — more publication-relevant code, not less. |
| `org.apache.maven.resolver/maven-resolver-transport-http` 1.9.22 | direct | The HTTPS transport that performs the upload. This is the branch an S3 wagon was standing in for. | Keep. |
| `org.apache.httpcomponents/httpclient` 4.5.14 | transport-http | HTTP client the transport is built on. | Keep. |
| `org.apache.httpcomponents/httpcore` 4.4.16 | transport-http, httpclient | Protocol core of that client. | Keep. |
| `commons-codec/commons-codec` 1.17.1 | transport-http | Hex and base64 encoding for the uploaded checksums and the `Authorization` header. | Keep. |
| `org.apache.maven/maven-resolver-provider` 3.9.8 | supplier | Teaches the resolver Maven's model: reading the deployed pom and generating `maven-metadata.xml`. | Keep. |
| `org.apache.maven/maven-model` 3.9.8 | resolver-provider, model-builder | The pom object model. | Keep. |
| `org.apache.maven/maven-model-builder` 3.9.8 | supplier, resolver-provider | Builds that model from the pom being deployed. | Keep. |
| `org.apache.maven/maven-artifact` 3.9.8 | model-builder | Version and coordinate handling. | Keep. |
| `org.apache.maven/maven-builder-support` 3.9.8 | model-builder | Problem collection for the model builder. | Keep. |
| `org.apache.maven/maven-repository-metadata` 3.9.8 | resolver-provider | The `maven-metadata.xml` model the deploy writes. | Keep. |
| `org.codehaus.plexus/plexus-utils` 3.6.2 | override of 3.5.1 requested by maven-model, maven-artifact, maven-repository-metadata, resolver-provider | XML reading and writing for Maven's models. The archive-extraction helper carrying GHSA-6fmv-xxpf-w3cw is present, but this deploy path has no demonstrated call or attacker-controlled archive input. | Keep the reviewed fixed 3.x version; 3.5.1 is rejected by the exact-version policy. |
| `org.codehaus.plexus/plexus-interpolation` 1.27 | model-builder | Property interpolation in the model builder. | Keep. |
| `org.slf4j/slf4j-api` 1.7.36 | resolver and transport, throughout | Logging facade. No binding is on the classpath, so it is a no-op. | Keep, unbound. |
| `org.slf4j/jcl-over-slf4j` 1.7.36 | transport-http | Routes HttpClient's commons-logging calls into that facade, which is why `commons-logging` itself is absent. | Keep. |

`javax.inject` and `org.eclipse.sisu.inject` appear in `clojure -Stree` output
marked `:excluded`, and `maven-resolver-{api,spi,util,impl}` 1.9.20 appears
marked `:older-version`. Plexus Utils 3.5.1 is rejected by the alias override.
None reaches a classpath, so none is an entry in the reviewed resolved set.

## Expected output, not defects

A deploy prints three lines to stderr:

```
SLF4J: Failed to load class "org.slf4j.impl.StaticLoggerBinder".
SLF4J: Defaulting to no-operation (NOP) logger implementation
SLF4J: See http://www.slf4j.org/codes.html#StaticLoggerBinder for further details.
```

That is SLF4J reporting that no logging binding is present, which is the
intended state: adding one would put a logging framework — the role Logback 1.0.12
played in the removed branch — back onto the classpath that holds the credential,
to no benefit. Publication output goes to stdout through `println`.

## How this stays true

`test/com/kirahowe/secrets/publish_policy_test.clj` runs the two commands above
in a subprocess and fails when the resolved graph drifts from this document:

- `release-classpath-has-no-unused-transports-test` — no artifact matching
  `s3`, `aws`, `logback`, `ion-java`, `jackson`, `joda-time`, or
  `commons-logging` is on the classpath, named individually so a failure says
  which branch returned.
- `release-classpath-matches-the-reviewed-set-test` — each resolved coordinate
  and exact version must equal the reviewed map. The two set differences retain
  bidirectional enforcement: an unreviewed addition fails, and so does an entry
  that is no longer resolved.
- `release-classpath-uses-fixed-plexus-utils-test` — the classpath contains the
  reviewed 3.6.2 jar and not affected 3.5.1.
- `deploy-alias-excludes-the-build-tooling-test` — `tools.build` and the
  library's own `src` are absent, so the credential-bearing step cannot load
  them.
- `lower-level-deploy-uploads-the-receipted-bytes-test` and
  `publish-refuses-before-it-uploads-anything-test` — a real upload of a
  receipted fixture through the lower-level seam, plus the artifact refusals
  that precede one.
- `production-repository-target-is-fixed-test` and
  `production-rejects-disallowed-repository-targets-test` — argument- and
  environment-selected repositories fail before a local recorder sees a
  request, and disallowed URI shapes are rejected without disclosing fixture
  credentials.

The release workflow then runs `clojure -M:audit deploy` as the final hard gate
before the only step receiving Clojars credentials. The isolated audit runner
resolves the same `:deploy` alias, writes its exact coordinates and dependency
tree under `target/dependency-audit/deploy/`, and invokes OSV Scanner 2.5.1.
`.github/dependency-audit.edn` pins the scanner download by platform SHA-256 and
defines no advisory ignores, so any package match exits nonzero before
publication. The coordinate, tree, scanner input, and result files remain
available as the reproducible disposition record.

Changing the `:deploy` alias therefore fails the suite until this document is
updated to match.
