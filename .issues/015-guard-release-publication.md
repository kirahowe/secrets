# 015 — Reproducible guarded release publication

Status: `open`
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

- [ ] Publication refuses dirty/untracked release inputs and requires `HEAD` to
      be exactly the protected release tag selected for the declared version.
- [ ] Version metadata has one authoritative source and is checked against the
      tag, artifact coordinates, and embedded metadata before upload.
- [ ] Build input comes from the verified commit/tree rather than mutable live
      files that can diverge after validation.
- [ ] The release artifact is built once, checksummed, and the exact inspected
      bytes are passed to upload; the upload task cannot rebuild implicitly.
- [ ] Publication is restricted to a trusted protected-tag workflow with
      minimally scoped credentials and immutable CI dependencies.
- [ ] Focused release checks cover dirty tree, wrong tag, version mismatch,
      changed artifact, and successful exact-tag publication using a local or
      dry-run repository.
- [ ] Release instructions document the reproducible inspect-then-publish flow.

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
