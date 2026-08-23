# 002 — Project initialization

Status: `open`
Priority: P1

## Problem

A new consumer must currently discover and repeat the CLI configuration in
`bb.edn`, choose paths for a template, ciphertext, manifest, key, and optional
recipients file, then decide what is safe to commit. The examples expose the
pieces but do not yet minimize the zero-to-first-secret friction. There is also
a chicken-and-egg limitation: `bb secrets init` cannot run before a project has
wired the secrets CLI task that would provide it.

## Evidence

- The CLI contract and required paths are described in the root
  [README API section](../README.md#api).
- [quickstart-bb/bb.edn](../examples/quickstart-bb/bb.edn) repeats app,
  environment, ciphertext, key, template, and manifest configuration.
- [quickstart-bb README](../examples/quickstart-bb/README.md) demonstrates a
  tracked template with disposable `.local/` runtime artifacts.
- [aero-profiles/bb.edn](../examples/aero-profiles/bb.edn) and
  [team-ci/bb.edn](../examples/team-ci/bb.edn) show other repeated wiring and
  path layouts.

## Desired outcome

Evaluate initialization approaches and make the recommended consumer flow reach
a verified store in no more than three clear commands, with explicit safe
commit/ignore guidance and no automatic private-key handling or commits.

## Acceptance criteria

- [ ] Inventory repeated `bb.edn` configuration across the four examples and
      identify the minimum common schema.
- [ ] Compare a scaffold command, a tracked template, and a standalone CLI
      entrypoint; record trade-offs before choosing one.
- [ ] Define how tracked templates differ from encrypted ciphertext and
      value-free manifests, including disposable-layout overrides.
- [ ] Document explicit paths for local/demo, single-recipient, and
      multi-recipient layouts, including collision constraints.
- [ ] Explain the `bb secrets init` chicken-and-egg and provide a first wiring
      step that does not assume the CLI is already available.
- [ ] Demonstrate a consumer flow of at most three commands ending in a
      successful `verify`, with stdin used for values and no shell-history leak.
- [ ] State exactly what is safe to commit and ignore; no step auto-commits, and
      an initializer/scaffold never silently creates, exports, or uploads a
      private identity. An explicit user-invoked `keygen` step is allowed and
      expected when creating the first store.

## Non-goals

- Automatically committing ciphertext, manifests, templates, or configuration.
- Copying private identities into project directories by default.
- Hiding the underlying CLI configuration when explicit paths are necessary
  for a disposable or multi-environment layout.

## Verification

Try the proposed flow from an empty temporary consumer directory, once with a
tracked template and once with an explicit disposable directory. Confirm that
bootstrap, stdin-based set, and verify work after a fresh checkout and that
`git status` shows only intended public artifacts.

## Dependencies / related files

- [quickstart-bb](../examples/quickstart-bb/README.md)
- [aero-profiles bb.edn](../examples/aero-profiles/bb.edn)
- [team-ci bb.edn](../examples/team-ci/bb.edn)
- [CLI configuration and commands](../src/com/kirahowe/secrets/cli.clj)
