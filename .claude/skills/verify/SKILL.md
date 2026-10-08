---
name: verify
description: Exercise the library end to end from a user's perspective before a release — scaffold a fresh consumer project, run the full CLI surface, runtime loading, and identity injection, and compare each step against the README's promises.
---

# Pre-release user-journey verification

Simulate a new user adopting this library, using the README as the contract:
check every command's output, exit code, and error message against what the
README says. Run this before tagging a release.

Work in a scratch directory, never inside this repo. Use a throwaway `--app`
name such as `verifydemo` and delete `~/.config/<app>/` when done, because
keygen writes there.

In every command that can open an editor, set both `VISUAL` and `EDITOR` to a
script of your own. The user's shell exports `VISUAL=emacsclient …`, a
non-blank `VISUAL` wins over `EDITOR`, and it will hang a non-interactive run.
Unset `SECRETS_AGE_IDENTITY`, `SECRETS_AGE_IDENTITY_FILE`, and
`SECRETS_AGE_IDENTITY_B64` before you start.

## Phase 0: prerequisites

```sh
which age bb clojure java && age --version && bb --version
```

`age` and Babashka are required. A JDK is needed for any `:deps` entry in
`bb.edn` and for the JVM smoke test.

## Phase 1: scaffold a consumer

In a fresh scratch directory:

```sh
bb -cp <checkout>/src -m com.kirahowe.secrets.init --help
bb -cp <checkout>/src -m com.kirahowe.secrets.init --app verifydemo --keygen
bb -cp <checkout>/src -m com.kirahowe.secrets.init --app verifydemo --keygen --apply
```

The preview must say "Nothing is written without --apply" and leave the
directory empty. After `--apply`, check that `bb.edn` and
`secrets/secrets.edn.example` exist, that `~/.config/verifydemo/key.txt` has
mode 0600, and that the public key is printed with the backup warning. A
third run must report all three under "Already there, left as they are".
`--team`, or any other option than `--app`, `--env`, `--keygen`, `--apply`,
and `--help`, must be refused as unknown.

**Release-critical:** the scaffolded `bb.edn` pins the commit `<checkout>` is
at: `{:git/tag "v<version>" :git/sha <HEAD>}` when HEAD is the release tag and
`{:git/sha <HEAD>}` otherwise. Confirm the sha is `git rev-parse HEAD` and,
for a release, that the tag is present. Off a tag, the output says the commit
is not a release tag and has to be pushed. A consumer resolves the pin from
GitHub, so an unpushed commit cannot be exercised as written.

If the commit is pushed, exercise the pin once with `bb secrets --help`.
Otherwise replace the coordinate in the scratch `bb.edn` with
`{:local/root "<checkout>"}`. Either way, every later phase tests the current
code.

**Existing `bb.edn`:** in a second scratch directory, write a `bb.edn` with a
comment and an unrelated task, then run the preview and `--apply`. The
initializer must create only the template, print the dependency and the task
under "Add these yourself", and leave `bb.edn` byte for byte as it was.

**JVM project:** in a third scratch directory, write a `deps.edn` with any
dependency and run the same two commands. Check that the created `bb.edn` has
`{verifydemo/verifydemo {:local/root "."}}` and the `secrets` task but no
library coordinate, that the library entry for `deps.edn` is printed and not
written, and that `deps.edn` is unchanged. Add the entry by hand, then run
`bb secrets --help`, which proves Babashka resolves the library through
`deps.edn`.

## Phase 2: migration from v0.1.0

Export the `v0.1.0` sources (`git archive v0.1.0 src`, unpacked in scratch)
and create a store with them on the classpath:

```sh
printf %s old-value | bb -cp <v0.1.0>/src -e \
  "(require '[com.kirahowe.secrets.cli :as cli]) (cli/run! <config> [\"set\" \":example/api-key\"])"
```

The store then carries a `:version 1` manifest and no manifest key. Back on
the current code:

- `verify` must exit 1 and report version 1 as unsupported, naming
  `bb secrets reencrypt <env>`.
- `set` must fail and say the store has no manifest key, naming the same
  command.
- `reencrypt` must succeed and write a `:version 3` manifest.
- `verify` must then exit 0.

## Phase 3: CLI surface

Run every command and check output and exit codes.

- `bb secrets`, `bb secrets --help`, `bb secrets help set`, `bb secrets set -h`.
  The command list must be `keygen`, `new`, `edit`, `set`, `rm`, `verify`,
  `doctor`, `show-key`, `add-recipient`, `recipients`, `reencrypt`, `help`.
- `set` from stdin (a string), `set --edn` (a set literal), blank stdin
  (refused), a surplus argument (refused without echoing it), and a key under
  `:com.kirahowe.secrets/manifest-key` (refused as reserved).
- `set` and `rm` with a vector path key (`'[:r2 :account-id]'`).
- `rm` an existing key. `rm` a missing key must fail with exit 1.
- `edit` and `new` with a scripted editor. An unchanged `edit` must leave the
  store untouched. An edit that keeps comments must show them again on the
  next `edit`. The editor must never see the library's reserved metadata. An
  edited plaintext that is a vector, is malformed, or holds reserved metadata
  must be refused and leave the files unchanged. `new` with no template must seed the
  editor from the built-in commented placeholder, and with a template, from
  the template.
- `show-key`, and `doctor`. `doctor` must print the identity's source and
  path and no file contents.
- Manifest: version 3, with a `:vhash` on every entry.
- Drift, each exiting 1: change `:ciphertext-sha` in the manifest, change a
  `:vhash`, change `:version`. Restore between each. Delete the manifest:
  exit 2. `reencrypt` regenerates it.
- A store without a manifest key: encrypt `{:a 1}` over the ciphertext with
  `age -e -i <key>`. `verify` exits 1, `set` and `edit` fail, `reencrypt`
  repairs it.
- Keyless: move `~/.config/<app>/key.txt` away. `verify` must pass as
  "freshness only" with exit 0, a changed `:ciphertext-sha` must exit 1, and
  `set` must fail for lack of an identity. Move the key back.
- Config: an unknown top-level key (`:limits`) and an unknown environment key
  must each be refused by name, and `doctor` must exit 2 for the first.
- Team flow, in a config with a `:recipients-file` and a `:key-file` inside
  scratch: `keygen`, `add-recipient` (must not recommend `reencrypt` yet),
  first `set`, `recipients`, `add-recipient <other-key>` (must recommend
  `reencrypt`). A `set` at that point must say the recipients changed and
  that it is generating a new manifest key. The other key must then pass
  `verify` through `SECRETS_AGE_IDENTITY_FILE`. Remove the other key's line,
  `reencrypt`, and check that every `:vhash` changed and that the removed key
  now fails `verify` with a decryption error. An invalid line in the
  recipients file must be marked by `recipients` and refused by `reencrypt`.
- `SECRETS_AGE_IDENTITY_FILE` naming a file that does not exist:
  `verify <env>` must fail with a message naming the variable and the path,
  and `verify` with no environment must report it for each environment, keep
  going, and exit 2.

## Phase 4: runtime consumption

With the library `src` directly on Babashka's classpath
(`bb -cp <checkout>/src script.clj`):

- `load-secrets` and `get-secret` (keyword, vector path, 3-arity default)
  with `{:app …}`. The loaded map must not contain any key in the
  `com.kirahowe.secrets` namespace, and
  `get-secret` with a path that continues into a string must return the
  default.
- `merge-readers` and `reader-literals`: `#secret/req` present, `#secret/opt`
  absent (nil), `#secret/req` absent (throws naming the key), and a merged
  caller-supplied literal still works.
- `:resource` resolution, with the secrets directory added to `-cp`.
- No identity (`(load-secrets store)` with no variables set): `ex-data`
  `:reason :no-identity`.
- A named identity that does not exist: `:no-identity` from `load-secrets`,
  and from `#secret/opt` too.
- An identity path of `key:txt`, `https://…`, or key contents:
  `:disallowed-identity`, and the message must not repeat the value.
- An `https://` source: `:disallowed-source`, with no userinfo or query in the
  error.

JVM smoke: the same `load-secrets` call via
`clojure -Sdeps '{:deps {io.github.kirahowe/secrets {:local/root "<checkout>"}}}'`.

Aero, on the JVM and under Babashka with Aero on the classpath:
`com.kirahowe.secrets.aero/read-config` with `{:secrets …}`, a `#profile`
whose unselected branch names a key the store lacks, and
`aero.core/read-config` on the same file, which must throw an error naming
`com.kirahowe.secrets.aero/read-config`. The namespace's only public var must
be `read-config`.

## Phase 5: identity injection

Each of these must decrypt with no app name given:

- `SECRETS_AGE_IDENTITY_FILE=<path>`, and the same path written with `~`
- `SECRETS_AGE_IDENTITY="$(cat <path>)"`
- `SECRETS_AGE_IDENTITY_B64="$(base64 < <path>)"`

And each of these must fail, naming the variable: a variable that is set but
empty, a `_B64` value that isn't base64, a `_FILE` that names a missing file,
and a `_FILE` that holds key contents (the message must not repeat them).

Precedence and cleanup, with a second key (`age-keygen -o other.txt`) that is
not a recipient of the store under test:

- An explicit `:identity-file` wins over a set variable. With
  `SECRETS_AGE_IDENTITY="$(cat other.txt)"` exported, `load-secrets` with
  `{:identity-file "<good key>"}` must succeed. The same call with `{:app …}`
  must fail with `age decryption failed`, which shows the variable was the
  identity in use.
- A blank `SECRETS_AGE_IDENTITY=""` must fail with "is set but empty", even
  when `~/.config/<app>/key.txt` would have decrypted the store.
- No `age-identity-*` temp file survives the operation. Save this as `c.clj`
  and run it from the scratch project with `bb -cp <checkout>/src c.clj`,
  once with `SECRETS_AGE_IDENTITY="$(cat <good key>)"` (success) and once
  with `SECRETS_AGE_IDENTITY_B64="$(base64 < other.txt)"` (the load throws):

  ```clojure
  (require '[com.kirahowe.secrets :as s])
  (defn strays []
    (count (filter #(.startsWith ^String % "age-identity-")
                   (.list (java.io.File. (System/getProperty "java.io.tmpdir"))))))
  (let [before (strays)
        inside (s/with-identity {} (fn [_] (- (strays) before)))
        result (try (some? (s/load-secrets "secrets/secrets.edn.age" {}))
                    (catch Exception _ :threw))]
    (println "inside callback:" inside "after load:" (- (strays) before) result))
  ```

  `inside callback` must be 1, which shows the counter can see the file, and
  `after load` must be 0 in both runs.

## Phase 6: the library's own gates

In the checkout: `bb test`, `clojure -M:test`, `bb lint`, `bb format:check`,
and `bb book:build`. Capture test output to a file and read the exit code of
the test command itself: a pipe through `tail` or `grep` replaces it with the
filter's. Rerun a failure before concluding anything from it, since a
generated property can fail on one seed.

The policy tests scan `book/chapters`, the README, and the real workflows for
action references pinned to full 40-hex commit SHAs. A truncated SHA in a doc
chapter fails several tests at once.

## Phase 7: shipped examples

Each example must run with its own README's commands and leave nothing
tracked behind (`git status` stays clean):

- `examples/quickstart-bb`: `bb bootstrap && bb run && bb verify && bb cleanup`
- `examples/team-ci`: `bb secrets verify fixture`, then
  `bb demo && bb cleanup`. The fixture check must pass as "freshness only".
  The demo script asserts on exact CLI hint text, so a failure here usually
  means the CLI's messages moved.
- `examples/aero-profiles`: `bb bootstrap`, then with
  `SECRETS_AGE_IDENTITY_FILE=tmp/key.txt` exported, `bb run`, `bb run evals`,
  `bb test`, and `bb clean`.
- `examples/integrant-service`: `./scripts/bootstrap-demo.sh` and
  `clojure -M:test`. Run the service and the jar per its README when time
  allows.

## Wrap-up

- Remove `~/.config/<app>/` and the scratch directory.
- Report each phase as pass or fail, every README statement that did not
  hold, and any release-critical item, such as a pin whose commit is not yet
  pushed.
