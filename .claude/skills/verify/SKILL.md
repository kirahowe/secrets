---
name: verify
description: Exercise the library end to end from a user's perspective before a release — scaffold a fresh consumer project, run the full CLI surface, runtime loading, and identity injection, and compare each step against the README's promises.
---

# Pre-release user-journey verification

Simulate a brand-new user adopting this library, using the README as the
contract: every command output, exit code, and error message is checked
against what the README promises. Run this before tagging a release.

Work in a scratch directory (never inside this repo). Use a throwaway
`--app` name (e.g. `verifydemo`) and **delete `~/.config/<app>/` when
done** — keygen writes there.

## Phase 0 — prerequisites

```sh
which age bb clojure java && age --version && bb --version
```

`age` and Babashka are required; a JDK is needed for `:local/root` /
git/Maven deps in `bb.edn` and for the JVM smoke test.

## Phase 1 — scaffold a consumer (the released-user path)

In a fresh `git init` scratch dir:

```sh
bb -cp <checkout>/src -m com.kirahowe.secrets.init --app verifydemo            # preview: must say "No files changed"
bb -cp <checkout>/src -m com.kirahowe.secrets.init --app verifydemo --keygen --apply
```

Check: `bb.edn` + `secrets/secrets.edn.example` created, key at
`~/.config/verifydemo/key.txt` mode 0600, public key printed with backup
warning.

**Release-critical:** the scaffolded `bb.edn` pins the commit `<checkout>` is
at: `{:git/tag "v<version>" :git/sha <HEAD>}` when HEAD is the release tag and
`{:git/sha <HEAD>}` otherwise. Confirm the sha is `git rev-parse HEAD` and,
for a release, that the tag is present; the preview names the coordinate and
says when the commit is not a tag. A consumer resolves the pin from GitHub, so
an unpushed commit cannot be exercised as written.

Exercise the pin once (`bb secrets set` / `verify`) if the commit is pushed.
Otherwise run those commands with
`-Sdeps '{:deps {io.github.kirahowe/secrets {:local/root "<checkout>"}}}'`,
which overrides the coordinate for that invocation. Either way, every phase
tests the current code.

**JVM project variant:** in a second scratch dir, write a `deps.edn` with any
dependency, then run the same two commands. Check: `deps.edn` gained the
pinned coordinate at the top level with its comments intact; `bb.edn` has
`{verifydemo/verifydemo {:local/root "."}}` and the `secrets` task but no
library coordinate; and `bb secrets --help` runs, which proves Babashka
resolves the coordinate through `deps.edn`.

## Phase 2 — migration from v0.1.0

Put a `v0.1.0` checkout of the library on the consumer's classpath
(`git worktree add <dir> v0.1.0`, then the `-Sdeps` `:local/root` override
above pointing at it) and run `bb secrets set` so the store carries a
`:version 1` manifest. Back on the current code, `verify` must report it as
unsupported with a message naming `bb secrets reencrypt <env>`; running that
must rewrite the manifest to `:version 2`, after which `verify` and `doctor`
both exit 0.

## Phase 3 — CLI surface (current code)

Run every command; check outputs and exit codes (verify/doctor: 0 ok,
1 drift/warning, 2 missing/invalid):

- `bb secrets`, `bb secrets --help`, `bb secrets help set`, `bb secrets set -h`
- `set` from stdin (string), `set --edn` (a set literal), blank stdin → refused
- `set` and `rm` with a vector path key (`'[:r2 :account-id]'`)
- `rm` an existing key; `rm` a missing key → error, nonzero exit
- `edit` and `new` with a scripted editor. **Set `VISUAL= EDITOR=<script>`** —
  a non-blank `VISUAL` (the user's shell exports `emacsclient …`) wins over
  `EDITOR` by design and will hang a non-interactive run. `new` with no
  template must seed the editor buffer from a built-in commented placeholder;
  with a template, from the template.
- `encrypt` / `decrypt` an arbitrary non-EDN file, byte-for-byte (`cmp`)
- `show-key`, `doctor` (healthy → exit 0)
- Drift: tamper `:ciphertext-sha` in the manifest → `verify` exit 1;
  restore; delete the manifest → exit reflects missing artifact
- Team flow: add a `:recipients-file` env, `keygen`, `add-recipient`,
  first `set`, `recipients`, `add-recipient <other-key>`, `reencrypt`;
  manifest in multi-recipient mode is structure-only (no `:vhash`)

## Phase 4 — runtime consumption

Java-free Babashka path (library `src` directly on the classpath):

- `load-secrets` + `get-secret` (keyword and vector path, 3-arity default)
  with `{:app …}`
- `merge-readers` / `reader-literals`: `#secret/req` present, `#secret/opt`
  absent → nil, `#secret/req` absent → throws naming the key, and a merged
  caller-supplied literal still works
- `:resource` classpath resolution (add the secrets dir to `-cp`)
- No identity resolvable → `ex-data` `:reason :no-identity`, not a silent nil
- `:limits` with a typo'd key → `:invalid-limits`
- An `https://` source → `:disallowed-source`

JVM smoke: same `load-secrets` call via `clojure -Sdeps '{:deps {… :local/root …}}'`.

Aero (JVM, aero on classpath): per-read `{:secrets …}` opts and
`register!` + `reset-cache!` round trip.

## Phase 5 — identity injection (the CI/production story)

With `~/.config/<app>/key.txt` temporarily moved away, each must decrypt:

- `SECRETS_AGE_IDENTITY_FILE=<path>`
- `SECRETS_AGE_IDENTITY="$(cat <path>)"`
- `SECRETS_AGE_IDENTITY_B64="$(base64 < <path>)"`

And each must fail loudly, naming itself: a set-but-empty variable; a
`_B64` value that isn't canonical base64.

## Phase 6 — library's own gates

In the checkout: `bb test`, `clojure -M:test`, `bb lint`, `bb format:check`.
Capture test output to a file — never pipe through `tail`/`grep`, which
replaces the suite's exit code with the filter's. On a failure, rerun before
concluding: at least one bb-suite test has shown one-off flakiness.

The policy tests scan `book/chapters` and the real workflows for
action refs pinned to full 40-hex commit SHAs; a truncated SHA in a doc
chapter fails three tests at once.

## Phase 7 — shipped examples

Each example must run with its own README's commands and leave nothing behind:

- `examples/quickstart-bb`: `bb bootstrap && bb run && bb verify && bb cleanup`
- `examples/team-ci`: `bb verify fixture`, then `bb demo && bb cleanup`.
  The demo script asserts on exact CLI hint text — it is the canary for
  CLI output-format changes (that is how the quoted-env-name change was
  caught); a failure here usually means the CLI's messages moved.
- `examples/aero-profiles` and `examples/integrant-service` per their READMEs
  when time allows; their integrations are also covered directly in Phase 4.

## Wrap-up

- Remove `~/.config/<app>/` and the scratch dir.
- Report: each phase pass/fail, README promises that didn't hold, and any
  release-critical items (e.g. a pin whose commit is not yet pushed).
