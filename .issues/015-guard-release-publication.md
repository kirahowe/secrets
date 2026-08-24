# 015 — Reproducible guarded release publication

Status: `resolved`
Priority: P0
Review classification: Confirmed Medium — alpha release blocker

## Problem

The release build hardcodes a version, copies the live working tree while
claiming tag metadata, and rebuilds during upload without proving that the
inspected artifact, tag, and source commit are identical. A dirty or post-tag
working tree can therefore publish bytes not represented by the advertised
release tag (CWE-345).

## Evidence

- [Release build](../build.clj) at lines 11–15 hardcodes the version, and lines
  20–41 copy live `src` while constructing tag-related metadata.
- [Publish task](../build.clj) at lines 53–59 rebuilds/uploads without a clean
  tree, exact-tag, protected-ref, or artifact-identity gate.
- At review time the working tree contained Unreleased changes after `v0.1.0`,
  demonstrating that live source can differ from the last release tag. No
  claim is made that those changes were actually published.
- Exploitation or accidental mispublication requires release credentials and a
  release invocation from mismatched source/state.

## Desired outcome

Build once from a clean, protected, exact release tag; attest version, tag, and
HEAD agreement; inspect those exact bytes; and upload the same artifact without
rebuilding.

## Acceptance criteria

- [x] Publication refuses dirty/untracked release inputs and requires `HEAD` to
      be exactly the protected release tag selected for the declared version.
- [x] Version metadata has one authoritative source and is checked against the
      tag, artifact coordinates, and embedded metadata before upload.
- [x] Build input comes from the verified commit/tree rather than mutable live
      files that can diverge after validation.
- [x] The release artifact is built once, checksummed, and the exact inspected
      bytes are passed to upload; the upload task cannot rebuild implicitly.
- [x] Publication is restricted to a trusted protected-tag workflow with
      minimally scoped credentials and immutable CI dependencies.
- [x] Focused release checks cover dirty tree, wrong tag, version mismatch,
      changed artifact, and successful exact-tag publication using a local or
      dry-run repository.
- [x] Release instructions document the reproducible inspect-then-publish flow.

## Resolution

The guards live in a new namespace, `com.kirahowe.secrets.release`, under a new
top-level `build/` source directory — deliberately not `src/`, so none of it
ships in the jar. It depends on `clojure.core`, `clojure.java.shell` and the
JDK only, so it is tested under both babashka and JVM Clojure; `tools.build`
stays in `build.clj`. Every git-inspecting function takes the repository
directory as an argument, which is what makes the guards testable against
disposable repositories instead of against this checkout.

`build.clj` now has three distinct paths where it had two. `jar` stays
unguarded and builds from the live tree, because CI builds and inspects a jar
on every push, including dirty trees and non-tag refs — but it no longer stamps
`:scm :tag`, since a development build has no tag provenance to claim. `release`
runs `clean-tree!`, `exact-tag!` and `changelog-entry!`, then materializes the
tag with `git worktree add --detach` and builds from *that* directory:
`create-basis` reads the export's `deps.edn` and `copy-dir` copies its `src`.
That is the point of criterion 3 — passing the guards does not stop a live file
changing a moment later. `deploy` builds nothing at all; it reads
`target/release.edn`, re-verifies it, and hands the publisher the exact files it
names.

Three things came out of review rather than the issue text, and each closes a
real hole.

The uploaded *pom* was outside the verified byte path. `deploy` originally
recomputed `b/pom-path` and uploaded whatever was at that location, while
`verify-artifact-metadata!` inspected the pom *inside* the jar. Since a
repository serves the pom beside the jar and the pom is what defines the
coordinate and the dependency list a consumer resolves, that file has to be the
inspected one. The receipt now carries `:pom`, and `verify-pom!` fails unless
its bytes are identical to the jar's embedded
`META-INF/maven/com.kirahowe/secrets/pom.xml`. Comparing against the jar entry
rather than recording a second digest means the artifact's own SHA-256 already
covers both files.

`verify-artifact-metadata!` now also requires the embedded pom to declare
`<scm><tag>` equal to the release tag. This matters because
`.github/scripts/inspect-jar.sh` had to be relaxed: its unconditional
`<tag>v0.1.0</tag>` assertion contradicted removing the tag claim from the
development build, so it now only requires that a pom declaring *any* tag
declares the right one. The strong check belongs in the guard, which only the
release path runs.

`verified-source!` runs `git worktree prune` before adding. `release` calls
`clean`, which deletes `target/` including a leftover export, but git keeps the
worktree registration, so a crashed earlier run would make the next
`worktree add` refuse for a path that no longer exists. Prune is idempotent and
its failure is not fatal.

`.github/workflows/release.yml` triggers on `v*` tags, is `contents: read`, and
runs one job in the `release` environment. The environment is the enforcement
for "protected": a workflow has no trustworthy view of tag or branch
protection, so the environment's protection rules decide whether the job runs
at all, and it holds the only copy of the Clojars credentials. Those credentials
appear in the `env:` of the final deploy step and nowhere earlier, so checkout,
setup, build, inspect and artifact upload cannot see them. The job is
deliberately uncached, so a release never resolves through bytes an earlier run
could have written. All four actions are pinned to full commit SHAs resolved
with `git ls-remote --tags` and confirmed with `gh api`, each with a version
comment: `actions/checkout` `d23441a4` (v6.1.0), `actions/setup-java`
`b6effb05` (v5.7.0), `DeLaGuardo/setup-clojure` `4c7a6f61` (13.6.1),
`actions/upload-artifact` `ea165f8d` (v4.6.2).

Two implementation notes. `lib` moved from `build.clj` into the release
namespace because the guard needs the group and artifact ids to compute the
`META-INF/maven/…` entry paths, and a second copy in `build.clj` would be
exactly the duplication this issue is about. And `b/write-pom` receives
`:src-dirs ["src"]`, not the export path, because `tools.build` writes that
value verbatim into `<sourceDirectory>` — the artifact is still made from the
export, via `create-basis` and `copy-dir`.

Regression tests in `com.kirahowe.secrets.release-test`, all against disposable
repositories: malformed version strings, guards passing at the exact tag, dirty
and purely-untracked trees, a missing tag versus a `HEAD` one commit past the
tag, a tag naming another version, a missing CHANGELOG heading, an export
holding the tagged bytes rather than the working tree's, artifact metadata with
a mismatched pom version and an absent or wrong SCM tag, a receipt whose
artifact had one byte flipped, and that the publisher is handed exactly the
receipted jar and pom — refusing a missing receipt with the
`clojure -T:build release` hint.

`ci.yml` still uses floating action tags; issue 014 owns the repo-wide pinning
policy, and issue 018 owns shrinking the publisher's dependency graph.

## Non-goals

- Publishing or rotating real repository credentials in tests.
- Promising bit-for-bit reproducibility across unspecified toolchains without
  recording/pinning them.
- Rewriting unrelated build and test aliases.

## Verification

In a disposable tagged repository, build the artifact, record its digest, run
inspection, and prove the publisher consumes that same file/digest. Exercise
each guard by introducing a dirty file, tag/version mismatch, non-exact tag,
and post-build artifact mutation; each must fail before credentialed upload.

## Dependencies / related files

- [release build tasks](../build.clj)
- [build and release dependencies](../deps.edn)
- [CI workflow](../.github/workflows/ci.yml)
- [release documentation](../README.md)
