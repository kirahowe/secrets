# 001 — Babashka without Java

Status: `closed`
Priority: P0 (highest)

## Resolution

Babashka's interpreter and loaded library runtime are JVM-free, but the normal
`bb.edn` dependency-resolution paths tested here are not. On Babashka
`1.13.219`, every tested `bb.edn` dependency mode still requires `java`:
`:local/root`, released Git coordinates, and Maven coordinates. Warm Git/Maven
caches do not remove that requirement. The Java-free path that does work is an
already materialized classpath, with the library source placed directly on
Babashka's `:paths`.

This issue is therefore closed by documenting that exact boundary and adding a
regression job for the supported Java-free runtime path: an isolated copy of
the library `src/` plus the quickstart example, with the example's `bb.edn`
rewritten from `:deps` to direct `:paths`. The run covers `bb bootstrap`,
`bb run`, explicit `decrypt`, and manifest `verify`, and proves that no
dependency caches are created.

## Evidence

- Small matrix, all on Babashka `1.13.219` with no `java` on `PATH`:
  - Cold `:local/root` quickstart consumer: fails in dependency resolution with
    `Couldn't find 'java'`.
  - Cold released Git consumer (`io.github.kirahowe/secrets` `v0.1.0`): fails
    in Babashka dependency resolution with `Couldn't find 'java'`.
  - Warm-cache released Git consumer: still fails without Java.
  - Cold Maven probe (`aero/aero` `1.1.6`): fails the same way.
  - Warm-cache Maven probe: still fails without Java.
  - Direct-classpath quickstart rewrite (`:paths ["src" "../../src"]`, no
    `:deps`): full `bootstrap` / `run` / `decrypt` / `verify` succeeds and
    creates no `~/.deps.clj`, `~/.gitlibs`, or `~/.m2`.
  - Public Maven artifact for `com.kirahowe/secrets`: does not exist yet.
- [quickstart-bb/bb.edn](../examples/quickstart-bb/bb.edn) exercises both the
  CLI and native `clojure.edn` reader integration.
- [CI workflow](../.github/workflows/ci.yml) now includes a dedicated
  Java-free cold-start job that runs inside the official
  `babashka/babashka:1.13.219` container without installing a JDK.
- [smoke-bb-java-free-runtime-quickstart.sh](../.github/scripts/smoke-bb-java-free-runtime-quickstart.sh)
  copies `src/` and the quickstart example into an isolated temp repo, rewrites
  the example from `:deps` to direct `:paths`, fails fast if `java` or
  `JAVA_HOME` is present, and asserts that no dependency caches are created
  while `bb bootstrap`, `bb run`, `bb secrets decrypt`, and `bb verify` all
  succeed.

## Supported boundary

- Supported today: Java-free Babashka runtime operations once the source is
  already materialized onto the classpath directly.
- Not supported today on Babashka `1.13.219` without Java: `bb.edn`
  dependency resolution via `:local/root`, Git coordinates, or Maven
  coordinates, even with warmed dependency/artifact caches.
- Also not available today: a public Maven artifact for this library.
- Still useful but not sufficient on their own: the regular Babashka tests and
  the existing quickstart smoke test on the default Ubuntu runner.

## Acceptance criteria

- [x] CI has a dedicated Java-free regression job that exercises the supported
      Babashka runtime path from a cold `HOME`.
- [x] The regression job records the Babashka, `age`, and OS versions and
      fails fast if `java` or `JAVA_HOME` is present.
- [x] The regression job distinguishes bootstrap/load behavior from the
      representative library operations by running `bb bootstrap`, `bb run`,
      `bb secrets decrypt`, and `bb verify`, while asserting that no dependency
      caches are created.
- [x] The issue text now records the observed Git/Maven dependency-tooling
      boundary for Babashka `1.13.219`, including `:local/root`.

## Non-goals

- Making Babashka `bb.edn` dependency resolution Java-free in this repository.
- Treating a warm local cache as proof that a cold install is supported.
- Requiring users to commit identities, plaintext, or generated private data.

## Verification

Run the dedicated CI job in an isolated container with an explicit `java`
absence check and empty temp `HOME`/XDG directories. If a future Babashka
release removes the Java requirement for `bb.edn` dependency resolution, add
follow-up coverage for `:local/root`, Git, and Maven coordinates and update the
README claims accordingly.

## Dependencies / related files

- [quickstart-bb README](../examples/quickstart-bb/README.md)
- [smoke script](../.github/scripts/smoke-bb-java-free-runtime-quickstart.sh)
- [CI workflow](../.github/workflows/ci.yml)
