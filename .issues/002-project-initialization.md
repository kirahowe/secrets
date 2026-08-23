# 002 — Project initialization

Status: `closed`
Priority: P1

## Resolution

A standalone Babashka entrypoint now wires the project before `bb secrets`
exists. It requires a deliberate app name, previews the complete public-file
diff, and offers apply, manual configuration, or cancel. The default is one
tracked `dev` store under `secrets/`, with its identity outside the repository.
`--layout disposable` and `--team` make their exceptional paths explicit.

The initializer preserves existing `bb.edn` formatting and comments, refuses
dependency/task conflicts and canonical path collisions, and never commits.
Private-key creation happens only when the user explicitly supplies
`--keygen`, after the scaffold has been accepted and written successfully.

The recommended flow is three commands: standalone init with explicit keygen,
stdin-based `set`, then `verify`. Until a release containing the initializer is
tagged, the first command loads its namespace from a source checkout; the
released documentation can replace that classpath with the pinned Git
coordinate without changing the interface or generated project.

## Evidence

- Quickstart, Aero, and team-CI repeat CLI configuration in `bb.edn`; the
  Integrant consumer instead uses JVM runtime configuration and a shell
  bootstrap. The actual minimum CLI schema is `:app`,
  `:default-environment`, and `{env {:secrets-file ...}}`.
- A tracked template alone documents shape but cannot wire the CLI. An
  already-wired `bb secrets init` is convenient only after solving the
  chicken-and-egg problem. The standalone entrypoint solves first wiring and
  then hands all later operations to the ordinary generated task.
- [Initializer tests](../test/com/kirahowe/secrets/init_test.clj) cover merge
  preservation, conflicts, layouts, preview/manual/cancel behavior, symlink
  safety, and keygen sequencing.
- [Initialization smoke test](../.github/scripts/smoke-project-initialization.sh)
  exercises real `age` keygen, stdin `set`, and `verify` in isolated tracked
  and disposable Git consumers.

## Desired outcome

Evaluate initialization approaches and make the recommended consumer flow reach
a verified store in no more than three clear commands, with explicit safe
commit/ignore guidance and no automatic private-key handling or commits.

## Acceptance criteria

- [x] Inventory repeated `bb.edn` configuration across the four examples and
      identify the minimum common schema.
- [x] Compare a scaffold command, a tracked template, and a standalone CLI
      entrypoint; record trade-offs before choosing one.
- [x] Define how tracked templates differ from encrypted ciphertext and
      value-free manifests, including disposable-layout overrides.
- [x] Document explicit paths for local/demo, single-recipient, and
      multi-recipient layouts, including collision constraints.
- [x] Explain the `bb secrets init` chicken-and-egg and provide a first wiring
      step that does not assume the CLI is already available.
- [x] Demonstrate a consumer flow of at most three commands ending in a
      successful `verify`, with stdin used for values and no shell-history leak.
- [x] State exactly what is safe to commit and ignore; no step auto-commits, and
      an initializer/scaffold never silently creates, exports, or uploads a
      private identity. An explicit user-invoked `keygen` step is allowed and
      expected when creating the first store.

## Non-goals

- Automatically committing ciphertext, manifests, templates, or configuration.
- Copying private identities into project directories by default.
- Hiding the underlying CLI configuration when explicit paths are necessary
  for a disposable or multi-environment layout.

## Verification

`bash .github/scripts/smoke-project-initialization.sh` creates two empty Git
consumers and passes both flows. The tracked case leaves exactly `bb.edn`, the
template, ciphertext, and manifest as public untracked files while its identity
lives under an isolated external home. The disposable case leaves only
`.gitignore`, `bb.edn`, and the tracked template visible to Git; its identity,
ciphertext, and manifest are under the ignored `.local/secrets/` directory.

`bb test` includes 11 focused initializer tests and passes with the existing
library suite.

## Dependencies / related files

- [quickstart-bb](../examples/quickstart-bb/README.md)
- [aero-profiles bb.edn](../examples/aero-profiles/bb.edn)
- [team-ci bb.edn](../examples/team-ci/bb.edn)
- [CLI configuration and commands](../src/com/kirahowe/secrets/cli.clj)
- [Standalone initializer](../src/com/kirahowe/secrets/init.clj)
