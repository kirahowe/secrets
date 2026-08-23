# 001 — Babashka without Java

Status: `open`
Priority: P0 (highest)

## Problem

The examples claim to be Babashka consumers, but a cold run with a checkout
dependency such as `{:local/root "../.."}` can activate JVM-backed dependency
resolution when no Java runtime is installed. This creates uncertainty about
whether the limitation is in library runtime code, Babashka's dependency
tooling, or the particular coordinate. A user needs a precise supported path,
not an assumption based on a warm developer cache.

## Evidence

- [quickstart-bb/bb.edn](../examples/quickstart-bb/bb.edn) uses a local root and
  invokes the CLI plus native `clojure.edn` reader code.
- [aero-profiles/bb.edn](../examples/aero-profiles/bb.edn) uses both Aero and a
  local root; [team-ci/bb.edn](../examples/team-ci/bb.edn) exercises keyless
  verification from Babashka.
- The root [bb.edn](../bb.edn) runs the library's Babashka tests successfully in
  the normal project checkout, which does not establish cold consumer behavior.

## Desired outcome

Either provide a tested JVM-free path for supported Babashka consumer setups,
or document the exact boundary: which phase requires Java, which runtime paths
remain JVM-free, which coordinates are supported, and how users should prepare
or cache dependencies.

Do not decide the implementation before the reproduction matrix distinguishes
the causes.

## Acceptance criteria

- [ ] Reproduction matrix covers local checkout, Git, and released Maven
      coordinates.
- [ ] Each coordinate is tested with cold and warm dependency caches.
- [ ] Matrix includes Babashka + `age` with no Java installed, and records the
      Babashka, age, OS, and dependency-cache versions.
- [ ] Results distinguish library execution (loading, `merge-readers`, CLI,
      encryption/decryption) from dependency resolution/bootstrap tooling.
- [ ] Quickstart, Aero, and team-CI commands are included where applicable;
      keyless verification is tested separately from decryption.
- [ ] A supported JVM-free path is demonstrated, or precise documentation and
      claims are updated based on evidence.
- [ ] CI has a regression job or matrix entry that exercises the chosen
      supported claim without accidentally inheriting a JVM from the runner.

## Non-goals

- Rewriting the secrets library or Babashka's dependency resolver before the
  failure mode is reproduced.
- Treating a warm local cache as proof that a cold install is supported.
- Requiring users to commit identities, plaintext, or generated private data.

## Verification

Run the matrix in isolated containers or machines with an explicit `java`
absence check, then run the same commands with Java present and with caches
pre-populated. Capture exit status and the phase that emits each failure. Add
the smallest reproducible command to CI after the supported boundary is known.

## Dependencies / related files

- [quickstart-bb README](../examples/quickstart-bb/README.md)
- [aero-profiles README](../examples/aero-profiles/README.md)
- [team-ci README](../examples/team-ci/README.md)
- [CI workflow](../.github/workflows/ci.yml)
