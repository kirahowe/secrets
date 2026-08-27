# 033 — Audit build dependency advisories

Status: `resolved`
Priority: P2
Review classification: Low release hygiene

## Problem

Exact-coordinate OSV scans of the documentation and build aliases report
advisory matches in transitive tooling dependencies. The `:book` graph contains
affected Jackson 2.18.2 components, Commons FileUpload 2.0.0-M2, and Jetty
12.0.18. The `:build` graph contains Plexus Utils 3.4.1 and Jetty 9 components
with advisories.

These are build/book-only dependencies and do not ship in the library. The jobs
also do not receive application or Clojars credentials, which lowers impact.
They nevertheless execute repository-controlled and dependency code in CI; the
book graph renders the artifact later deployed to GitHub Pages. Raw OSV matches
do not establish that vulnerable methods or attacker-controlled inputs are
reachable, so each match needs an upgrade and recorded disposition rather than
an exploitability claim.

## Evidence

- Runtime [`:deps`](../deps.edn#L1-L6) contain only Clojure. Clay is confined to
  the [`:book` alias](../deps.edn#L18-L22), and tools.build is confined to the
  [`:build` alias](../deps.edn#L24-L27); these tooling graphs are not library
  runtime dependencies.
- The book task launches `clojure -M:book` with Clay and then applies the site
  policy ([`bb.edn`](../bb.edn#L86-L108)).
- CI runs `clojure -T:build jar` in the build-and-inspect job
  ([`.github/workflows/ci.yml`](../.github/workflows/ci.yml#L146-L204)) and runs
  `bb book:build` in the book job
  ([`.github/workflows/ci.yml`](../.github/workflows/ci.yml#L206-L285)). Neither
  job is given application identities or Clojars publication credentials.
- The book job uploads `book/rendered` as the Pages artifact on `main`, and the
  separately privileged deploy job publishes that artifact
  ([`.github/workflows/ci.yml`](../.github/workflows/ci.yml#L256-L315)). Thus a
  reachable build-tool compromise could affect published documentation even
  though it cannot add a dependency to the library jar by itself.
- Controlled exact-coordinate OSV scanning produced the following package
  matches:

  - `:book` — `com.fasterxml.jackson.core/jackson-core` 2.18.2:
    [GHSA-72hv-8253-57qq](https://osv.dev/vulnerability/GHSA-72hv-8253-57qq) and
    [GHSA-r7wm-3cxj-wff9](https://osv.dev/vulnerability/GHSA-r7wm-3cxj-wff9).
  - `:book` — `com.fasterxml.jackson.core/jackson-databind` 2.18.2:
    [GHSA-3pjw-73gf-8qr5](https://osv.dev/vulnerability/GHSA-3pjw-73gf-8qr5),
    [GHSA-5gvw-p9qm-jgwh](https://osv.dev/vulnerability/GHSA-5gvw-p9qm-jgwh),
    [GHSA-5jmj-h7xm-6q6v](https://osv.dev/vulnerability/GHSA-5jmj-h7xm-6q6v),
    [GHSA-hgj6-7826-r7m5](https://osv.dev/vulnerability/GHSA-hgj6-7826-r7m5),
    [GHSA-j3rv-43j4-c7qm](https://osv.dev/vulnerability/GHSA-j3rv-43j4-c7qm),
    [GHSA-mhm7-754m-9p8w](https://osv.dev/vulnerability/GHSA-mhm7-754m-9p8w), and
    [GHSA-rmj7-2vxq-3g9f](https://osv.dev/vulnerability/GHSA-rmj7-2vxq-3g9f).
  - `:book` — `org.apache.commons/commons-fileupload2-core` 2.0.0-M2:
    [GHSA-vv7r-c36w-3prj](https://osv.dev/vulnerability/GHSA-vv7r-c36w-3prj).
  - `:book` — `org.eclipse.jetty/jetty-server` 12.0.18:
    [GHSA-7p3p-8qv8-m2vh](https://osv.dev/vulnerability/GHSA-7p3p-8qv8-m2vh),
    [GHSA-f4v5-65jj-pcr2](https://osv.dev/vulnerability/GHSA-f4v5-65jj-pcr2), and
    [GHSA-xxh7-fcf3-rj7f](https://osv.dev/vulnerability/GHSA-xxh7-fcf3-rj7f).
  - `:book` — `org.eclipse.jetty/jetty-http` 12.0.18:
    [GHSA-355h-qmc2-wpwf](https://osv.dev/vulnerability/GHSA-355h-qmc2-wpwf) and
    [GHSA-wjpw-4j6x-6rwh](https://osv.dev/vulnerability/GHSA-wjpw-4j6x-6rwh).
  - `:book` — `org.eclipse.jetty/jetty-util` 12.0.18:
    [GHSA-w7x5-g22v-xqhr](https://osv.dev/vulnerability/GHSA-w7x5-g22v-xqhr).
  - `:book` — `org.eclipse.jetty/jetty-security` 12.0.18:
    [GHSA-2fvj-hgj9-j2gr](https://osv.dev/vulnerability/GHSA-2fvj-hgj9-j2gr).
  - `:build` — `org.codehaus.plexus/plexus-utils` 3.4.1:
    [GHSA-6fmv-xxpf-w3cw](https://osv.dev/vulnerability/GHSA-6fmv-xxpf-w3cw).
  - `:build` — `org.eclipse.jetty/jetty-http` 9.4.58.v20250814:
    [GHSA-355h-qmc2-wpwf](https://osv.dev/vulnerability/GHSA-355h-qmc2-wpwf) and
    [GHSA-qh8g-58pp-2wxh](https://osv.dev/vulnerability/GHSA-qh8g-58pp-2wxh).

  These are exact resolved-coordinate advisory matches only. Reachability of
  the advisory-specific methods in Clay rendering or tools.build jar production
  was not established.

## Desired outcome

Update Clay and build tooling to versions with fixed transitive graphs, or apply
minimal safe overrides where upstream releases cannot yet do so. Reproducibly
scan every dependency alias and record the dependency path, vulnerable surface,
repository input that could reach it, fixed version, and keep/override/upgrade
disposition for every match.

## Acceptance criteria

- [x] The exact `:book` graph no longer resolves affected Jackson 2.18.2,
      Commons FileUpload 2.0.0-M2, or Jetty 12.0.18 coordinates.
- [x] The exact `:build` graph no longer resolves Plexus Utils 3.4.1 or affected
      Jetty 9 coordinates.
- [x] Clay/tools.build upgrades or overrides preserve deterministic jar
      production, book rendering, site-policy enforcement, and the existing
      separation from runtime/library dependencies.
- [x] Reproducible advisory scanning covers the default graph and every alias,
      including `:test`, `:book`, `:build`, `:deploy`, `:format`, and `:lint`.
- [x] Scan records retain exact coordinates and dependency paths and distinguish
      raw package matches from demonstrated reachability/exploitability.
- [x] Each retained match has an owner-visible disposition with advisory,
      affected surface, repository-controlled input analysis, fixed version,
      and review date.
- [x] Policy confirms build/book dependencies remain absent from the published
      library jar and credential-bearing deploy classpath.

## Resolution

The dependency changes are local to the three affected tooling aliases. `:book`
upgrades Clay 2.0.16 to 2.0.21 and, because that release still selects the older
components, overrides only the renderer graph to Ring 1.15.5, the Jackson 2.18.9
line, and Jetty server/security plus EE9 security 12.1.10. The resulting
affected coordinates are Jackson core/databind 2.18.9, Commons FileUpload
2.0.0-M5, and Jetty server/http/util/security and EE9 security 12.1.10.
`:build` upgrades tools.build 0.10.13 to 0.10.14; its newer tools.deps/Maven
graph selects Plexus Utils 3.6.1 and removes the Cognitect HTTP client branch
that supplied Jetty 9. `:lint` keeps the pinned clj-kondo release but overrides
Cheshire's Jackson core, CBOR, and Smile modules together from 2.17.0 to 2.18.9;
current clj-kondo releases still select Cheshire 5.13.0 and that Jackson line.
The JVM `:test` graph explicitly includes data.json 2.5.1 to load the audit
policy implementation. None of these changes touches top-level runtime `:deps`
or `:paths`.

There is one advisory system rather than a deploy-only check beside a second
build check. [`.github/dependency-audit.edn`](../.github/dependency-audit.edn)
pins OSV-Scanner 2.5.1 by release URL and per-platform SHA-256, names the default
graph and every project alias (including the isolated `:audit` runner itself),
and carries the review records for every original advisory plus the follow-up
matches exposed by the first complete all-alias run. In particular, the record
now includes `jetty-ee9-security` 12.1.8 through Clay/Ring and Jackson Core
2.17.0 through clj-kondo/Cheshire, with their exact paths. Each record retains
the matched coordinate and dependency path, affected surface,
repository-controlled input analysis, fixed version, upgrade/override
disposition, `:not-demonstrated` reachability, and review date. These are
historical dispositions, not ignores: the scanner invocation has no allowlist
or ignore configuration and fails for every current OSV package match.

`com.kirahowe.secrets.dependency-audit` resolves each graph independently with
the pinned Clojure CLI's `-X:deps list` and `tree` programs. For every graph it
writes `coordinates.edn` (the selected coordinate and every root-to-package
path), `tree.edn`, the exact OSV custom-lockfile input, and OSV's JSON result
under `target/dependency-audit/<graph>/`. A non-Maven coordinate is a refusal,
not a silent omission; one graph's failure is retained while the remaining
graphs are attempted, and the process fails after all selected graphs finish.
The `:audit` alias uses replaced dependencies and the `build/` path; its JSON
dependency is also explicit in `:test` so policy tests load on the JVM. Neither
the runner nor JSON dependency enters the runtime, book, build, deploy, or
published-library graph.

CI's `dependency-advisory-audit` job runs `clojure -M:audit`, uploads the exact
records even on failure, and is a prerequisite of the main-only Pages deploy.
The release workflow runs the same implementation as
`clojure -M:audit deploy`, selecting only `:deploy`'s
`replace-deps`/`replace-paths`, as the final hard gate immediately before the
only step receiving Clojars credentials. Thus the credential-bearing graph is
scanned before every publication without giving the scanner those credentials.

The existing build and book contracts are unchanged: `clojure -T:build jar`
still builds only `src`, the jar inspection compares every non-metadata entry
with the source tree, and `bb book:build` still renders then invokes the site
policy before its Pages artifact can upload. New policy tests require audit
configuration to equal the live alias set, validate scanner pins and complete
review fields, refuse unscannable coordinate kinds, preserve exact dependency
paths in OSV input, pin the fixed EE9 and coherent lint Jackson overrides, prove
the default library basis remains Clojure-only, prove the deploy replacement
excludes every build/book dependency, and enforce both workflow gates.

## Non-goals

- Describing unproven Clay or tools.build exploit paths as confirmed.
- Adding build/book dependencies to the production library to centralize their
  versions.
- Ignoring tooling advisories solely because the dependencies do not ship.

## Verification

- `clojure -M:audit` — resolve and scan the default graph and every alias,
  retaining exact coordinate/path and JSON result artifacts.
- `clojure -M:audit deploy` — exercise the release workflow's selective,
  pre-credential hard gate.
- `clojure -M:test` — run the dependency audit policy and existing publication,
  workflow, release, site-policy, and library tests.
- `clojure -T:build jar` followed by
  `bash .github/scripts/inspect-jar.sh target/secrets-*.jar` — prove tooling did
  not enter the published artifact.
- `bb book:build` followed by `bb book:policy` — prove the upgraded renderer
  still produces and enforces the Pages artifact.

The integrated alpha gate `clojure -M:audit` completed successfully on
2026-08-27. It scanned all eight configured graphs with no OSV package match:
default 3, `:test` 27, `:book` 106, `:build` 59, `:deploy` 25, `:audit` 4,
`:format` 9, and `:lint` 28 exact Maven coordinates. The retained artifacts
carry the exact coordinate and dependency paths for each set.

## Dependencies / related files

- [dependency aliases](../deps.edn)
- [book task definitions](../bb.edn)
- [CI build and Pages workflow](../.github/workflows/ci.yml)
- [build implementation](../build.clj)
- [site policy](../build/com/kirahowe/secrets/site_policy.clj)
- [audit configuration](../.github/dependency-audit.edn)
- [release pre-publication gate](../.github/workflows/release.yml)
- [dependency audit implementation](../build/com/kirahowe/secrets/dependency_audit.clj)
- [dependency audit policy tests](../test/com/kirahowe/secrets/dependency_audit_test.clj)
