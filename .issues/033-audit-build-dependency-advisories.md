# 033 — Audit build dependency advisories

Status: `open`
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

- [ ] The exact `:book` graph no longer resolves affected Jackson 2.18.2,
      Commons FileUpload 2.0.0-M2, or Jetty 12.0.18 coordinates.
- [ ] The exact `:build` graph no longer resolves Plexus Utils 3.4.1 or affected
      Jetty 9 coordinates.
- [ ] Clay/tools.build upgrades or overrides preserve deterministic jar
      production, book rendering, site-policy enforcement, and the existing
      separation from runtime/library dependencies.
- [ ] Reproducible advisory scanning covers the default graph and every alias,
      including `:test`, `:book`, `:build`, `:deploy`, `:format`, and `:lint`.
- [ ] Scan records retain exact coordinates and dependency paths and distinguish
      raw package matches from demonstrated reachability/exploitability.
- [ ] Each retained match has an owner-visible disposition with advisory,
      affected surface, repository-controlled input analysis, fixed version,
      and review date.
- [ ] Policy confirms build/book dependencies remain absent from the published
      library jar and credential-bearing deploy classpath.

## Non-goals

- Describing unproven Clay or tools.build exploit paths as confirmed.
- Adding build/book dependencies to the production library to centralize their
  versions.
- Ignoring tooling advisories solely because the dependencies do not ship.

## Verification

Resolve every alias to an exact coordinate set and run the same pinned advisory
scanner over each set. Review and record every match, then exercise the existing
jar build/inspection and book render/site policy to prove upgraded graphs retain
their outputs and privilege separation.

## Dependencies / related files

- [dependency aliases](../deps.edn)
- [book task definitions](../bb.edn)
- [CI build and Pages workflow](../.github/workflows/ci.yml)
- [build implementation](../build.clj)
- [site policy](../build/com/kirahowe/secrets/site_policy.clj)
