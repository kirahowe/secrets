# com.kirahowe/secrets

Keep an application's secrets in one age-encrypted EDN file per environment,
committed next to the code that uses them. The only secret you manage outside
the repository is an [age](https://age-encryption.org) private key.

- The secrets are EDN: strings, numbers, sets, vectors, and nested maps.
- An application loads the whole map, or references single values from its EDN
  config with `#secret/req` and `#secret/opt`. There is an Aero integration,
  and the plain map suits Integrant or Component.
- A `bb secrets` task creates, edits, and checks the encrypted file.
- Every write also updates a committed manifest that holds no values. A diff
  of it shows which keys were added, removed, retyped, or changed, and CI can
  check it against the ciphertext without holding a key.
- A store is encrypted to your own key, or to a committed list of public keys
  so each teammate decrypts with their own.

The library shells out to the `age` binary and otherwise needs only Clojure or
Babashka. It is alpha software: the API, the commands, and the file formats
can still change between releases. It suits a solo developer or a small team
whose secrets change rarely. [Security](#authenticity-contract-and-threat-model)
says what it does not do.

Longer explanations live in the book under `book/chapters`
([Development](#development) shows how to build it), and
[`doc/threat-model.md`](doc/threat-model.md) is the design's decision rule.

## Install

Install `age` (`brew install age`, `apt install age`) and, for the `bb secrets`
task, [Babashka](https://babashka.org). Babashka resolves `:deps` entries
through Java, so a JDK has to be on the `PATH` too. The library's only
runtime dependency is Clojure.

Nothing is published to Clojars yet. Depend on the library through git:

```clojure
;; a release tag and the commit it names
io.github.kirahowe/secrets {:git/tag "v0.1.0" :git/sha "<commit the tag names>"}

;; Maven, once a release is on Clojars, or after `clojure -T:build install`
;; in a checkout
com.kirahowe/secrets {:mvn/version "0.1.0"}
```

The `v0.1.0` tag is older than this README and lacks several things described
here (the [changelog](CHANGELOG.md) lists them). To use the library as
documented before the next tag, pin a commit of `main` instead: write
`{:git/sha "<commit>"}` as the coordinate, or let the initializer below write
it for you.

## Quick start

Run the initializer from a checkout of this repository, in your project's
directory. It previews by default:

```sh
bb -cp /path/to/secrets/src -m com.kirahowe.secrets.init --app myapp --keygen
```

In an empty project the preview lists three files it would create: a `bb.edn`
that declares the library and a `secrets` task, a template at
`secrets/secrets.edn.example`, and the identity at `~/.config/myapp/key.txt`.
This is the task it writes:

```clojure
{secrets
 {:doc "Manage encrypted secrets"
  :requires ([com.kirahowe.secrets.cli :as cli])
  :task
  (cli/run!
   {:app "myapp"
    :default-environment :dev
    :environments {:dev {:secrets-file "secrets/secrets.edn.age"}}}
   *command-line-args*)}}
```

Run it again with `--apply` to create those files. The initializer only
creates files that do not exist. For a `bb.edn` or `deps.edn` that is already
there, it prints the entries to add and leaves the file alone. In a project
with a `deps.edn`, the library goes into `deps.edn` and `bb.edn` reaches it
through a `:local/root "."` dependency, so the application and the task load
the same version.

The dependency it writes is the commit the checkout is at: `:git/tag` and
`:git/sha` when that commit is the release tag, and `:git/sha` alone otherwise.
A commit that is not a release tag has to be pushed before another machine can
resolve it. `--env NAME` names the environment (default `dev`), and `--keygen`
generates the identity at `~/.config/myapp/key.txt`. Without `--keygen`, run
`bb secrets keygen` later. An option's value is a separate argument:
`--app myapp`, not `--app=myapp`.

Back the identity up, for example in a password manager. It is not in git and
cannot be recovered.

Set a first value. From a terminal, `set` prompts for it with echo turned off:

```sh
bb secrets set :example/api-key
```

The first `set` creates the ciphertext, `secrets/secrets.edn.age`, and its
manifest, `secrets/secrets.edn.manifest`. Check that they agree, then commit
`bb.edn` and everything under `secrets/`:

```sh
bb secrets verify
```

```text
✓ dev: manifest matches (secrets/secrets.edn.manifest)
```

Read the value from the application:

```clojure
(require '[com.kirahowe.secrets :as secrets])

(def secret-values
  (secrets/load-secrets "secrets/secrets.edn.age" {:app "myapp"}))

(secrets/get-secret secret-values :example/api-key)
```

Day to day:

```sh
bb secrets edit            # decrypt, open your editor, re-encrypt
bb secrets set :some/key   # one value, from a hidden prompt or stdin
bb secrets rm :old/key     # remove a value
bb secrets verify          # check the manifest before committing
bb secrets doctor          # report on the setup without printing values
bb secrets --help          # every command; `bb secrets help set` for one
```

## Configuration

The `secrets` task passes one map to `com.kirahowe.secrets.cli/run!`:

```clojure
{:app "myapp"
 :default-environment :dev
 :environments
 {:dev  {:secrets-file "env/dev/resources/secrets.edn.age"}
  :prod {:secrets-file "env/prod/resources/secrets.edn.age"
         :recipients-file "env/prod/recipients.txt"}}}
```

`:app` and `:environments` are required. `:app` names the default identity
path, `~/.config/<app>/key.txt`, and is recorded in each manifest. A command
that omits its environment argument uses `:default-environment`.

| Environment key | Meaning |
| --- | --- |
| `:secrets-file` | Required. Path to the ciphertext. It must end in `.age` unless `:template` and `:manifest` are both set. |
| `:template` | What `new` opens in the editor. Default: the secrets file with `.example` in place of `.age`. |
| `:manifest` | Path to the manifest, or `false` to keep none. Default: the secrets file with `.manifest` in place of `.age`. |
| `:key-file` | Where `keygen` writes and `show-key` reads. Default: `~/.config/<app>/key.txt`. |
| `:identity-file` | An explicit identity for commands that decrypt. It wins over the environment variables. |
| `:recipients-file` | A committed file of age public keys, one per line. When set, the store is encrypted to all of them. |

The config is validated before a command runs:

- A key the library does not know, at the top level or in an environment, is
  an error that names it, so a misspelling cannot be ignored silently.
- `:environments` is a map from a keyword to a map, and `:default-environment`
  has to name one of them.
- Every environment setting is a string holding a local filesystem path, and
  `:manifest` may also be `false`. A leading `~` is expanded in `:key-file`,
  `:identity-file`, and `:recipients-file`.
- No file may serve two purposes. Environments may share a template, a key or
  identity file, or a recipients file. Two environments may name the same
  secrets file or manifest only when they name both the same, which makes
  them one store under two names.

Each environment is a separate encrypted file. Environments share the app's
default key unless one sets its own `:key-file`.

## Using secrets in an application

### Load the map

```clojure
(require '[clojure.java.io :as io]
         '[com.kirahowe.secrets :as secrets])

(def m (secrets/load-secrets (io/resource "secrets.edn.age") {:app "myapp"}))

(secrets/get-secret m :database/url)
(secrets/get-secret m [:r2 :account-id])     ; a path into nested maps
(secrets/get-secret m :missing/key "default")
```

The source is a filesystem path, given as a string, a `File`, or a `Path`, or
a classpath resource, given as the `URL` that `io/resource` returns. That URL
is a `file:` or a `jar:file:` one, so a resource inside an uberjar works.
Anything else, such as an HTTP URL or a `file:` string, is refused with
`:reason :disallowed-source` before it is opened.

The second argument chooses the identity. It is a path, or a map with
`:identity-file` or `:app`. [Identity resolution](#identity-resolution) gives
the full order.

A vector path walks maps by key and vectors by integer index. It does not
index into a string, set, or list, so a path that continues past such a value
is not found.

Every failure is an `ex-info` whose data has a `:reason` keyword.
[Failure reasons](#failure-reasons) lists the ones worth branching on. A
failure about the source carries `:source`, which describes it by path, or by
scheme alone for a refused URL, and never repeats a refused value. An EDN
parse failure carries at most a line and column, never the text.

### Reader literals

`reader-literals` returns the `#secret/req` and `#secret/opt` tag functions,
and `merge-readers` adds them to a readers map you already have:

```clojure
(def readers
  (secrets/merge-readers
   {'env (fn [k] (System/getenv k))}
   {:app "myapp" :resource "secrets.edn.age"}))

(clojure.edn/read-string {:readers readers} (slurp "config.edn"))
```

```clojure
;; config.edn
{:db   {:jdbc-url #secret/req :database/url}
 :llm  {:api-key  #secret/opt :llm/api-key}
 :auth {:admins   #secret/req :auth/admins}}
```

The options are `:resource` (a classpath resource name) or `:file` (a path),
plus `:app` or `:identity-file`. Both tags take a keyword or a vector path.

| Situation | `#secret/req` | `#secret/opt` |
| --- | --- | --- |
| The key is in the store | the value | the value |
| The key is not in the store | throws | `nil` |
| The secrets file is not found | throws | `nil` |
| No identity was named and the app's default key file is absent | throws | `nil` |
| A named identity file does not exist | throws | throws |
| Decryption fails | throws | throws |

A readers map decrypts its store at most once, when the first tag is read, and
keeps that result, or that decryption failure, for as long as the map lives. A
config with no secret tags never touches the store or the key. After editing
the store, build a new readers map.

### Aero

[Aero](https://github.com/juxt/aero) is not a dependency of this library. Add
it to your project, then read the config with this namespace's `read-config`
in place of `aero.core/read-config`:

```clojure
(require '[com.kirahowe.secrets.aero :as secrets-aero])

(secrets-aero/read-config
 "config.edn"
 {:profile :dev
  :secrets {:app "myapp" :resource "secrets.edn.age"}})
```

`:secrets` takes the options `reader-literals` takes, and the tags behave the
same way. Every other key goes to Aero. Each call decrypts the store at most
once and keeps nothing afterwards, so the next call reads the store as it then
is. A config with secret tags read through `aero.core/read-config` directly
throws an error that names this function. `read-config` takes both arguments.
Without a `:secrets` option there is no store: `#secret/req` throws
`:invalid-config`, naming the option, and `#secret/opt` reads `nil`.

Aero evaluates only the branch a `#profile` selects, so a key one profile
needs can be absent from the store another profile reads:

```clojure
:api-key #profile {:default #secret/req :openrouter/api-key
                   :evals   #secret/req :openrouter/evals-api-key}
```

### Integrant

The loaded map is an ordinary value, so a component that provides it is one
method:

```clojure
{::secrets {:resource "secrets.edn.age" :app "myapp"}}

(defmethod ig/init-key ::secrets [_ {:keys [resource app]}]
  (secrets/load-secrets (io/resource resource) {:app app}))
```

Or pass `merge-readers` output as the `:readers` of
`integrant.core/read-string` and reference secrets from the system config.

### Identity resolution

Every operation that decrypts resolves its identity when it runs, from the
first of these that applies:

1. An explicit path: the second argument of `load-secrets`, or `:identity-file`
   in the options or in the environment's config.
2. `SECRETS_AGE_IDENTITY_FILE`, a path to the key file.
3. `SECRETS_AGE_IDENTITY`, the key file's contents.
4. `SECRETS_AGE_IDENTITY_B64`, the key file's contents in base64.
5. The environment's configured `:key-file` (CLI only).
6. `~/.config/<app>/key.txt`, when an app name is known.

A path from 1 or 2 names a specific file, and it is an error (`:no-identity`)
if that file does not exist. 5 and 6 say where the key normally lives. When
no file is there, no identity is available: `#secret/opt` reads `nil`,
`verify` checks without a key, and a command that needs the key says where it
looked. An identity variable that is set
but empty is an error that names the variable: a CI runner expands a missing
secret to the empty string, and falling through to another key would hide
that. Unset the variable to fall back.

Identity paths are local paths with a leading `~` expanded. A value that
starts with a URI scheme is refused with `:disallowed-identity`. A bare
relative name with a colon in it, such as `key:txt`, reads as a scheme, so
write `./key:txt`. Key contents placed in a path setting are refused the same
way and are not echoed.

`age` reads identities from files, so the contents from 3 and 4 are written to
an owner-only temporary file for the one operation and deleted when it ends.
If the delete fails, the error names the file that remains. A process that
crashes mid-operation can leave that file behind, and deleting a file does not
erase it from the disk. Use `SECRETS_AGE_IDENTITY_FILE` with a mounted secret
when the platform offers one.

### Size bounds

Fixed bounds catch an accidental huge or deeply nested input, such as a path
that names the wrong file. Loading refuses a ciphertext past 16 MiB and EDN
nested more than 100 collections deep. The CLI refuses to write a plaintext
past 8 MiB, and to read a recipients file past 256 KiB or a manifest past
1 MiB. They are not configurable.

## CI and production

A deployment needs the `age` binary, the ciphertext, and one identity. The
ciphertext ships with the code, on disk or inside the jar. Give the process
the identity through one of the three variables above. `bb secrets keygen`
prints the command for Fly:

```sh
flyctl secrets set SECRETS_AGE_IDENTITY="$(cat -- '/Users/you/.config/myapp/key.txt')"
```

A runtime that cannot start a subprocess cannot decrypt. There, use the
platform's own secret store in production and this library in development and
CI.

### Verifying in CI

`bb secrets verify` exits 0 when every manifest agrees with its ciphertext
and 1 when the only problem is drift. It exits 2 when anything else stopped
it: a missing file, an identity or decryption failure, an unknown environment,
or an invalid configuration. A CI job can therefore tell a stale manifest from
a missing key. It runs in one of two modes per environment.

Without an identity, it checks that the manifest is complete and that the
SHA-256 it records is the digest of the ciphertext. This needs no key and no
`age`, so any CI job can run it. It applies when no identity was named and no
key file is present, which is the usual state of a CI runner. An identity
named by `:identity-file` or an identity variable has to exist: a missing one
is an error, not a reason to skip the comparison.

With an identity, it also decrypts the store and compares every key path,
type, and value hash with the manifest. It reports drift as well when the
recipients file no longer matches the set the store was last encrypted to.

With no environment argument, `verify` checks every environment and keeps
going past one that fails.

A job that holds the identity should give it to the one step that needs it,
keep unreviewed code out, and pin its actions:

```yaml
verify-secrets:
  runs-on: ubuntu-latest
  if: >-
    github.event_name != 'pull_request' ||
    github.event.pull_request.head.repo.full_name == github.repository
  permissions:
    contents: read
  steps:
    - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6.1.0
    - uses: actions/setup-java@b6effb05e454b25005698d916606bdc6ffcbf961 # v5.7.0
      with: {distribution: temurin, java-version: '21'}
    - uses: DeLaGuardo/setup-clojure@4c7a6f613e5089821bb3bb2a33a3ee115578580d # v13.6.1
      with: {bb: 1.13.219}
    - run: sudo apt-get update && sudo apt-get install -y age
    - run: bb secrets verify
      env:
        SECRETS_AGE_IDENTITY: ${{ secrets.SECRETS_AGE_IDENTITY }}
```

The repository secret holds the contents of the key file, not a path:

```sh
gh secret set SECRETS_AGE_IDENTITY < ~/.config/myapp/key.txt
```

For the keyless job, drop the `env:`, the `age` install, and the `if:`. The
book's production chapter walks through both jobs.

## Teams

Point an environment at a recipients file and every write encrypts to all the
public keys in it. Each person keeps their own private identity.

The first owner creates a key, adds its public half, and creates the store:

```sh
bb secrets keygen prod
bb secrets add-recipient prod
bb secrets set prod :service/token     # or: bb secrets new prod
```

To add someone, a current recipient adds the newcomer's public key (the
newcomer gets it from `bb secrets show-key`) and re-encrypts:

```sh
bb secrets add-recipient prod age1...
bb secrets reencrypt prod
```

To remove someone, delete their line from the recipients file and run
`bb secrets reencrypt prod`. Commit the recipients file, the ciphertext, and
the manifest together. Editing the recipients file changes nothing by itself:
the store stays encrypted to the earlier set until it is re-encrypted, and a
`verify` that has an identity reports that as drift.

Removal stops that identity from decrypting ciphertext written afterwards. It
does not take back anything already read, and the old ciphertext stays in git
history, where the removed identity still decrypts it. Rotate the affected
credentials at their providers.

`reencrypt` also gives the store a new manifest key, so every value hash in
the manifest changes once. `edit`, `set`, and `rm` do the same when they find
that the recipients file no longer matches the set the store was last
encrypted to. That catches a forgotten `reencrypt`. It is not the removal
step: `reencrypt` is, because it always renews the key.
[The manifest](#the-manifest) explains why.

Each command reads the recipients file once, before it decrypts or opens an
editor, and refuses a line that is not an age or SSH public key.
`bb secrets recipients` lists the file and marks such lines.

Give deployments and CI their own recipient instead of a person's key.

## The manifest

A diff of `secrets.edn.age` says nothing, because age re-encrypts the whole
file. Every write therefore also writes `secrets.edn.manifest`:

```clojure
{:version 3
 :app "myapp"
 :ciphertext-sha "0e6487cf6f4562d51ef450dbe7ce54d76e91b350425d65ea1ab94288fe3acd6e"
 :keys
 {[:auth/admins] {:type :set, :count 2, :vhash "ce4caccbfee081c6"}
  [:example/api-key] {:type :string, :vhash "89ae7df577fa8bb8"}
  [:r2 :account-id] {:type :string, :vhash "d32adde248640142"}}}
```

Commit it. Its diff shows keys added, removed, or retyped, and a changed
`:vhash` shows that a value changed. `:ciphertext-sha` is the SHA-256 of the
ciphertext the manifest was written for, which is what the keyless `verify`
compares.

A `:vhash` is the first 64 bits of an HMAC-SHA-256 of the value. Its key is
256 random bits that the store holds inside its own encrypted EDN, so solo and
team stores work the same way and every recipient computes the same hashes.
At 64 bits a hash can collide: an unchanged hash is strong evidence that a
value did not change, not proof.

The store keeps that key, and a record of the recipient set it was encrypted
to, under one reserved top-level key, `:com.kirahowe.secrets/store`, that the
library owns. `load-secrets`, the reader literals, and the editor never show
it, and `set`, `rm`, and an edited plaintext cannot name it. A store's
plaintext has to be one EDN map.

`new`, or `set` when no store exists, generates the key. `edit`, `set`, and
`rm` keep it. `reencrypt` always replaces it, and so does any write that finds
the recipient set changed.

A store whose metadata is missing, malformed, or of another version fails
`edit`, `set`, and `rm` and is drift for a `verify` that has an identity. The
message says which it is and names `bb secrets reencrypt`, which writes
current metadata without reading the old. That is the state of a store
written by another tool or by an earlier version of this library. A store
that is not a map at all is told to start over with `bb secrets new`.

### What the manifest discloses

Anyone who can read the repository sees:

- every key path, through nested maps at every depth;
- each value's type, and the size of each collection;
- whether two values in one store are equal, and when a value changes or
  returns to an earlier one, for as long as the store keeps one manifest key;
- the size of the ciphertext and the commit history of both files.

Key paths are public, so never use a secret value as a map key.

Everyone who can decrypt the store holds its manifest key and can test guesses
of a value against any manifest published while that key was in use. Someone
without the key cannot. A removed recipient keeps the key they had, which is
why the next write replaces it.

If a key name is itself sensitive, set `:manifest false` for that environment.
Its changes are then not reviewable at all.

### Writes

A write validates the plaintext, encrypts it, and renders the manifest before
it replaces anything, so a rejected edit leaves both files alone. It then
replaces the ciphertext with an atomic rename, and then the manifest the same
way. The two renames are not one transaction and nothing is rolled back. If
the manifest cannot be replaced after the ciphertext was, the command says the
manifest is stale, `verify` reports the drift, and `bb secrets reencrypt`
regenerates it.

Each file is staged beside its target under a name of the form
`.<target>.<uuid>.tmp`. That holds for the ciphertext, the manifest, the
recipients file, and a generated key. A command deletes its staging file when
it ends, but one that is killed can leave it behind. Such a file is safe to
delete, and a `.*.tmp` line in `.gitignore` keeps it from being committed.

The ciphertext, manifest, and recipients file are written with ordinary file
permissions. Key files and the temporary plaintext that `new`, `edit`, `set`,
`rm`, and `reencrypt` use are readable only by their owner from the moment
they are created, and the temporary files are deleted when the command ends.

## Authenticity contract and threat model

[`doc/threat-model.md`](doc/threat-model.md) states what the library protects
and what it leaves to the deployment. In short:

- age keeps the values confidential and detects a corrupted or truncated
  ciphertext. Only a holder of a matching private identity can decrypt.
- Nothing identifies who wrote a ciphertext. A public recipient is meant to be
  shared, and anyone who has one can encrypt a file that decrypts cleanly. An
  older valid file can also be put back in place of a newer one.
- `verify` shows that a ciphertext and its manifest agree. Someone who can
  replace both can make them agree, so a pass is not evidence of authorship or
  approval, with or without an identity.
- The values a process loads are as trustworthy as the commit that carried
  them and the channel that delivered them. Protect the branches and tags a
  deploy builds from, and limit who can write to whatever serves the
  ciphertext.
- A leaked identity decrypts every ciphertext in git history that was
  encrypted to it. Rotate the secret values, not only the key.
- One identity decrypts a whole environment. There is no access control per
  secret.
- The decrypted map sits in process memory like any other config. The library
  does not defend a compromised host or application process.
- `edit` and `new` put plaintext in an owner-only temporary file while the
  editor is open. Your editor's swap and backup files are outside the
  library's control, and deleting a file does not erase it from the disk.
- [The manifest discloses](#what-the-manifest-discloses) key paths, types,
  sizes, and value equality and change.

If you need dynamic credentials, access rules per secret, automatic rotation,
or a central audit log, use a secrets manager.

Report a suspected vulnerability privately, as [SECURITY.md](SECURITY.md)
describes.

## Reference

### Commands

Every command takes the environment first and uses the default when it is
omitted. Before a `--`, an argument that starts with a dash is an option, and
one the command does not define is an error. Everything after `--` is an
argument, so a key may begin with a dash. A usage error prints the command's
usage and never the argument that caused it, which may be a value typed in the
wrong place. That includes an unknown command and an unknown environment.

| Command | What it does |
| --- | --- |
| `keygen [env]` | Generate an identity at the environment's `:key-file` and print its public key. Asks before replacing one. |
| `new [env]` | Create the store from its template in `$VISUAL`, `$EDITOR`, or `vim`. |
| `edit [env]` | Decrypt, open the editor, and re-encrypt if the text changed. Comments are kept. |
| `set [env] <key> [--edn]` | Set one value from a hidden prompt, or from stdin when it is not a terminal. Creates the store if there is none. |
| `rm [env] <key>` | Remove one key. Fails if the key or the store is absent. |
| `verify [env]` | Check manifests against ciphertexts. With no `env`, checks every environment. |
| `doctor [env]` | Report on the setup: `age`, the files, the identity, and the recipients. |
| `show-key [env]` | Print the public key of the configured `:key-file`. |
| `add-recipient [env] [public-key]` | Append a public key to the recipients file. With no key, the environment's own. |
| `recipients [env]` | List the recipients file. |
| `reencrypt [env]` | Re-encrypt to the current recipients with a new manifest key. |
| `help [command]` | Show help. `<command> --help` does the same for one command. |

`<key>` is a keyword (`:some/key`) or a vector path (`'[:a :b]'`). `set` never
takes the value as an argument. Piped input loses one trailing newline, is
stored as a string unless `--edn` parses it, and is refused when blank (use
`--edn` with `""` for an empty string). `set` and `rm` refuse a path that
passes through a value that is not a map. Both rewrite the plaintext, so
comments in it do not survive them.

`doctor` is for finding out why a command will not run. It does not open the
store or the manifest, and it prints paths and counts, never file contents,
recipient lines, or variable values. This is a team environment on a machine
that has no key:

```text
Environment: prod
age: v1.3.2
Secrets file: env/prod/secrets.edn.age (present)
Manifest: env/prod/secrets.edn.manifest (present)
Recipients file: env/prod/recipients.txt (present)
Recipients: 1
Identity: key file keys/alice.txt (missing)
Warning: No identity, so only keyless verification works here. Create a key with:  bb secrets keygen 'prod'
Status: warning
```

Exit codes:

| Command | 0 | 1 | 2 |
| --- | --- | --- | --- |
| `verify` | every manifest agrees | the only problem is drift | anything else stopped it: a missing file, an identity or decryption failure, an unknown environment, an invalid configuration |
| `doctor` | healthy | a warning: `age`, the secrets file, the manifest, the recipients file, or the key is not there | an invalid configuration, identity, or recipients file, or it could not run |
| every other command | success | any failure | |

### API

`com.kirahowe.secrets` is the runtime API:

- `(load-secrets source)`, `(load-secrets source identity-or-opts)`
- `(get-secret secrets key-path)`, `(get-secret secrets key-path default)`
- `(reader-literals opts)`, `(merge-readers readers opts)`
- `(with-identity identity-or-opts f)` calls `f` with
  `{:identity-file path :identity-source source}` for one operation
- `(expand-home path)`, `(default-key-file app)`

`com.kirahowe.secrets.aero` has `(read-config source opts)`.

`com.kirahowe.secrets.cli` has `(run! config args)`, `(normalize-config
config)`, and one function per command: `keygen!`, `new!`, `edit!`,
`set-secret!`, `remove-secret!`, `verify!`, `doctor!`, `show-key!`,
`add-recipient!`, `recipients!`, and `reencrypt!`. The command functions
return data, throw `ex-info`, and never exit. `verify!` and `doctor!` report
most failures in their result, with the exit code under `:exit`. `run!` is the
entry point of a process, on Babashka or the JVM, and the one place that
exits.

`com.kirahowe.secrets.init` has `-main` and `(init! opts)`.

Those four namespaces are the public API. `com.kirahowe.secrets.age`,
`.manifest`, `.store`, `.fs`, `.safe-edn`, and `.source` are implementation
namespaces and can change without notice. The book's reference chapter lists
every public API var with its docstring.

### Failure reasons

Every `ex-info` the library throws has a `:reason` keyword in its data. These
are the ones a caller can usefully branch on:

| Reasons | Meaning |
| --- | --- |
| `:no-identity`, `:invalid-identity`, `:disallowed-identity` | No identity is available, or a named identity file is missing. An identity variable is blank or not base64. An identity path is URI-shaped or holds key contents. |
| `:no-file`, `:disallowed-source`, `:source-too-large` | The source is nil, absent, or unreadable. It is not a local path or a classpath resource. It is past 16 MiB. |
| `:decrypt-failed`, `:age-not-installed` | `age` could not decrypt with this identity. The `age` binary is not on the `PATH`. |
| `:edn-empty`, `:edn-extra-values`, `:edn-malformed`, `:edn-too-deep` | The plaintext is not exactly one well-formed EDN value. |
| `:missing-key` | `#secret/req` named a key the store does not have. The tag also throws `:no-file` and `:no-identity`. |
| `:invalid-config`, `:unknown-config-key` | The CLI config, or the options of the Aero `read-config`, cannot be used. |
| `:usage` | A command line the CLI cannot place: an unknown command, option, or environment, or a missing or surplus argument. |
| `:invalid-store`, `:secrets-not-a-map`, `:reserved-key`, `:path-not-a-map`, `:no-such-key`, `:blank-value` | A write the CLI refused, and why. |
| `:input-too-large`, `:invalid-recipient`, `:no-recipients`, `:unreadable-file` | A file the CLI was given is too large, holds an invalid recipient or none, or cannot be read. |
| `:manifest-stale` | The ciphertext was replaced and the manifest was not. Run `reencrypt`. |
| `:private-file-remains` | A private temporary file could not be deleted. `:remaining-file` holds its path. |

## Examples

The [examples](examples/README.md) are runnable starter projects:
[quickstart-bb](examples/quickstart-bb/README.md),
[integrant-service](examples/integrant-service/README.md),
[aero-profiles](examples/aero-profiles/README.md), and
[team-ci](examples/team-ci/README.md).

## Development

The tests need `age` and a JDK. The book also needs
[Quarto](https://quarto.org).

```sh
bb test            # the suite under Babashka
clojure -M:test    # the suite under JVM Clojure
bb lint            # clj-kondo
bb format:check    # cljfmt, without changing files (`bb format` fixes)
bb book:build      # render the book into book/rendered
bb book:watch      # re-render chapters as you save them
bb secrets help    # the CLI against a throwaway store under tmp/
```

Source lines stay within 100 columns. The chapters under `book/chapters` are
literate Clojure namespaces rendered with
[Clay](https://scicloj.github.io/clay/), so their examples run against the
library at build time.

The version and coordinates live in `src/com/kirahowe/secrets/coordinate.edn`.
A release is built from a `v<version>` tag by the `release` workflow, or by
hand with `clojure -T:build release` and `clojure -M:deploy`.
[`doc/release-dependency-review.md`](doc/release-dependency-review.md) records
the dependencies of the deploy step.

## License

MIT © 2026 Kira Howe. See [LICENSE](LICENSE).
