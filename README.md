# com.kirahowe/secrets

Manage application secrets as a single **version-controlled, age-encrypted EDN
file** instead of a pile of environment variables. One private key decrypts it;
everything else — structure, defaults, and the encrypted ciphertext itself —
lives in git, with a committed value-free manifest that makes each change
reviewable.

- **No additional Clojure libraries.** It uses core Clojure APIs plus the
  `age` CLI, and once on the classpath it runs the same under JVM Clojure and
  [babashka](https://babashka.org).
- **A safe project initializer and `bb secrets` task.** Bootstrap with a
  previewed `bb.edn` merge, then use `keygen` · `new` · `edit` · `set` · `rm` ·
  `verify` · `doctor` · `show-key` · `add-recipient` · `recipients` ·
  `reencrypt` · `encrypt` · `decrypt`, wired into any project with one task
  definition.
- **Two ways to consume secrets:** `#secret/req` / `#secret/opt` EDN reader
  literals, or a plain `load-secrets` map for Integrant/component setups.
- **Solo or team.** Encrypt to your own key, or to a committed list of
  recipients so each teammate decrypts with their own key.
- **A committed manifest.** Every save writes a value-free `*.manifest` beside
  the ciphertext, so `git diff` shows *which keys changed* without leaking any
  secret.

It wraps [`age`](https://age-encryption.org) — a small, audited, modern
file-encryption tool — so there are no GPG keyrings, no KMS, no vault to run.

## Why not environment variables?

Env vars for secrets are easy to start with and painful to live with: they
sprawl (every integration adds another), they're untyped strings (a
comma-separated allowlist becomes parsing code), and they aren't
version-controlled (no history, no review, just mutable state in a deploy
platform). Encrypting a plain EDN map fixes all three — the map is real data
(sets, nested maps, numbers), the encrypted form is committed, and the only
out-of-band secret is one `age` key.

The ciphertext itself diffs opaquely (age re-encrypts the whole file), so the
committed [manifest](#manifest-seeing-what-changed) is what makes changes
*reviewable* — it records the shape of the secrets, so a PR shows which keys
were added, removed, or changed without revealing any value.

## Install

`age` must be on the PATH (`brew install age`, `apt install age`).

Add the library as a dependency. For a sibling checkout (local development):

```clojure
;; deps.edn
com.kirahowe/secrets {:local/root "../secrets"}
```

For sharing across repos and remote/CI builds, prefer a git or Maven coordinate
when running on JVM Clojure. In Babashka `1.13.219`, every normal `bb.edn`
dependency mode tested here requires Java: `:local/root`, Git coordinates, and
Maven coordinates. Warming the Git or Maven dependency caches does not remove
that requirement. The Java-free Babashka path is an already materialized
classpath, with the library source placed directly on `:paths` or supplied as
an explicit classpath. (A `:local/root` does not resolve inside a remote Docker
build, where the sibling isn't in the build context):

```clojure
;; git
io.github.kirahowe/secrets {:git/tag "v0.1.0" :git/sha "89ded34ce8bd146754cc3ec9971d1ea1fd25da28"}
;; or Maven, after `clojure -T:build install` locally or a future Clojars deploy
com.kirahowe/secrets {:mvn/version "0.1.0"}
```

As of 2026-08-23 there is no public Maven artifact for `com.kirahowe/secrets`.
The Maven example above is for local JVM installs and future publication, not a
currently fetchable coordinate. With Babashka `1.13.219`, the CLI,
`merge-readers`, `load-secrets`, `decrypt`, and `verify` run without Java only
after the library is already on the classpath directly.

## Quick start

**1. Initialize the project.** Until a release containing the initializer is
tagged, invoke it from this source checkout (replace the path with the checkout's
absolute `src` path):

```sh
bb -cp /path/to/secrets/src -m com.kirahowe.secrets.init --app myapp --keygen
```

The initializer proposes a minimal `dev` store, shows the complete `bb.edn` and
template diff, and then offers to apply it, print the configuration for manual
integration, or cancel. `--keygen` is an explicit request to generate the
identity at `~/.config/myapp/key.txt`; it runs only after you accept and the
public scaffold succeeds. Omit it to leave all private-key handling for a later
`bb secrets keygen` command. Nothing is committed automatically.

The default tracked layout is:

```text
bb.edn
secrets/secrets.edn.example
secrets/secrets.edn.age       # created by the first set/new; safe to commit
secrets/secrets.edn.manifest  # created with the ciphertext; value-free
~/.config/myapp/key.txt       # private identity; outside the repository
```

Existing `bb.edn` comments and unrelated forms are preserved. A conflicting
dependency or `secrets` task is refused rather than overwritten. Existing valid
templates and hand-maintained recipients files are also preserved.

For a non-interactive scaffold, `--apply` is the explicit confirmation after
the preview. Other layout options are described under [Initialization
layouts](#initialization-layouts).

**2. Set the first value through stdin.** This interactive shell form disables
echo while reading and never places the value in shell history or a process
argument:

```sh
IFS= read -rs SECRET; printf '%s' "$SECRET" | bb secrets set :example/api-key; unset SECRET
```

**3. Verify the resulting store:**

```sh
bb secrets verify
```

For comparison, the minimum configuration the initializer adds is the same
manual wiring shown below. Use this directly when you choose the initializer's
"manual" option or need a layout it should not infer:

```clojure
{:deps  {io.github.kirahowe/secrets
         {:git/tag "v0.1.0"
          :git/sha "89ded34ce8bd146754cc3ec9971d1ea1fd25da28"}}
 :tasks {secrets
         {:doc      "Manage encrypted secrets (age)"
          :requires ([com.kirahowe.secrets.cli :as secrets-cli])
          :task     (secrets-cli/run!
                     {:app "myapp"
                      :default-environment :dev
                      :environments
                      {:dev {:secrets-file "secrets/secrets.edn.age"
                             :template "secrets/secrets.edn.example"
                             :manifest "secrets/secrets.edn.manifest"}}}
                     *command-line-args*)}}}
```

Per-environment defaults fill in automatically: `:key-file` →
`~/.config/<app>/key.txt`, `:template` → `<secrets-file>.example`, `:manifest` →
`<secrets-file>.manifest`. The config is validated up front: `:app` and each
`:secrets-file` are required (`:app` names the default key path, so there is no
default — unrelated projects must not share a key by accident), and the secrets
file must end in `.age` — otherwise the derived template/manifest names would
collide with (and overwrite) the ciphertext itself — unless you set both
`:template` and `:manifest` explicitly. Ciphertext, manifest, template, key,
and recipients paths must resolve to distinct canonical paths.

To create a store through an editor instead of the stdin-based three-command
flow:

```sh
bb secrets keygen dev    # → ~/.config/myapp/key.txt  (BACK THIS UP — not in git)
bb secrets new dev       # opens $EDITOR with the template; fill in, save, encrypt
```

`new` seeds your editor from `secrets.edn.example` (if present) so the shape is
self-documenting. Saving writes `secrets.edn.age` (ciphertext) and
`secrets.edn.manifest` (its value-free shape) — commit both.

Day to day:

```sh
bb secrets edit dev      # decrypt → $EDITOR → re-encrypt (no plaintext left on disk)
bb secrets show-key       # print public key(s) to share with teammates
bb secrets decrypt dev secrets/secrets.edn.age  # plaintext to stdout
```

Every command takes the environment first (`bb secrets decrypt [env] <file>`);
omit it to use the default environment. `decrypt` writes to stdout byte-for-byte,
so it works for any `.age` file, not just EDN.

Non-interactively (scripts, bootstrap, CI):

```sh
printf %s "sk-live-…" | bb secrets set dev :openrouter/api-key
echo '#{"a@b.com" "b@b.com"}' | bb secrets set dev :auth/admins --edn
bb secrets rm dev :openrouter/old-key
```

`set` reads the value from **stdin**, never a command-line argument, so it
never lands in shell history or `ps`. The value is stored as a string unless
`--edn` parses stdin as EDN — sets, numbers, nested maps. `set` creates the
environment's secrets file when it doesn't exist yet, so bootstrapping a new
environment end to end is scriptable; a blank value on stdin is refused (an
unset CI variable expands to nothing, and storing that silently is worse than
failing loudly) — pass `--edn` with `""` if you genuinely want an empty
string. `rm` fails, rather than quietly doing nothing, when the key or the
file doesn't exist. `<key>` is a keyword (`:some/key`) or a vector path
(`[:a :b]`) for both commands, and both refresh the manifest like every other
write.

## Using secrets at runtime

### Reader literals (recommended for EDN-configured systems)

`reader-literals` returns `#secret/req` / `#secret/opt` tag functions to merge
into the `:readers` you pass to `clojure.edn/read-string` or
`integrant.core/read-string`. (The tags are namespaced because the EDN spec
reserves bare tags like `#secret` for EDN itself.)

```clojure
(require '[com.kirahowe.secrets :as secrets])

(def readers
  (secrets/merge-readers
   {'env (fn [k] (System/getenv k))}          ; your existing literals, if any
   {:app "myapp" :resource "secrets.edn.age"})) ; resolved on the classpath

(integrant.core/read-string {:readers readers} (slurp config))
```

Then config files reference secrets inline:

```clojure
{:db   {:jdbc-url #secret/req :database/url}    ; required — throws if absent
 :llm  {:api-key  #secret/opt :llm/api-key}     ; optional — nil if absent
 :auth {:admins   #secret/req :auth/admins}}    ; values are real EDN: #{"a@b.com"}
```

The file is resolved and decrypted **once, lazily**, on the first secret tag
encountered — so dev/test configs with no secret tags never touch `age` or the
key, even if a secrets file happens to be on the classpath. Each readers map
caches that first successful load **or genuine decryption failure** for its
lifetime. This avoids repeated decryption across tags and prevents one config
read from mixing values from ciphertext changed midway through the read. After
editing the encrypted store, explicitly construct a new `reader-literals` or
`merge-readers` map before re-reading the config; the old map deliberately
continues serving its first successful load or rethrowing its first decryption
failure. A process restart naturally constructs fresh readers and therefore
observes the current ciphertext. There is no filesystem polling or automatic
retry per tag.

The two tags mirror required/optional env reads: `#secret/opt` returns `nil`
when the secrets file is absent, when no identity (key) is available, or when
the key is missing from the decrypted map; `#secret/req` throws in all three
cases, saying which. A genuine decryption failure — the identity exists but
`age` fails — always throws, for both tags.

For a safe REPL reload, edit secrets out of process (for example, run
`bb secrets edit dev` in another terminal), deliberately recreate the readers,
then re-read the whole config. Inspect only non-secret status or structure:

```clojure
(require '[clojure.edn :as edn]
         '[com.kirahowe.secrets :as secrets])

(defn read-app-config []
  (let [readers (secrets/merge-readers
                 {'env (fn [k] (System/getenv k))}
                 {:app "myapp" :resource "secrets.edn.age"})] ; new map every call
    (edn/read-string {:readers readers} (slurp "config.edn"))))

;; After the out-of-process edit:
(def app-config (read-app-config))
{:config-loaded? (map? app-config)
 :section-count  (count app-config)}
```

Do not print the config or secret values while checking a reload. Make each
reload an explicit action like this rather than polling or watching the
ciphertext.

### Aero

[aero](https://github.com/juxt/aero) resolves tags through its own
`aero.core/reader` multimethod rather than a `:readers` map, so the
integration ships as a namespace instead of a snippet to paste into your own
code:

```clojure
(require '[com.kirahowe.secrets.aero])
```

That's the whole thing — requiring the namespace registers the `#secret/req` /
`#secret/opt` methods on `aero.core/reader`; there's nothing else to call.
`aero` is **not** a dependency of this library (`deps.edn`'s `:deps` stays
clean); the namespace only compiles and loads for consumers who already have
`aero` on their own classpath.

There are two ways to supply the secrets config — the same opts map
`reader-literals` takes (`:app`/`:resource`, `:file`, `:identity-file`):

- **Per read (preferred)**, through aero's own opts. `aero.core/read-config`
  passes its entire opts map to readers, so the config comes from a `:secrets`
  key and can vary per call (see the profile recipe below):

  ```clojure
  (aero.core/read-config "config.edn"
    {:secrets {:app "myapp" :resource "secrets.edn.age"}})
  ```

- **Process-wide**, as an explicit convenience for an application with one
  secrets configuration and a deliberate process lifecycle:

  ```clojure
  (com.kirahowe.secrets.aero/register! {:app "myapp" :resource "secrets.edn.age"})
  ```

`register!` stores mutable process state: a later call replaces the default,
and `(register! nil)` clears it when that lifecycle ends. A per-read `:secrets`
opt always wins over the registered default. With neither supplied, reading a
`#secret/…` tag throws rather than resolving to nil.

Each distinct Aero secrets configuration is likewise decrypted once and
cached, including a genuine decryption failure. In a long-running REPL, edit
the ciphertext out of process, call `reset-cache!`, and only then re-read the
whole config:

```clojure
(require '[aero.core :as aero]
         '[com.kirahowe.secrets.aero :as secrets-aero])

(secrets-aero/register!
 {:app "myapp" :resource "secrets.edn.age"})

;; In another terminal: bb secrets edit dev
(secrets-aero/reset-cache!)
(def app-config (aero/read-config "config.edn"))
{:config-loaded? (map? app-config)
 :section-count  (count app-config)}
```

`reset-cache!` invalidates **all** cached Aero reader maps and their decrypted
stores, both successful and failed, so the next `#secret/…` read decrypts the
current ciphertext. It leaves the process-wide default supplied by `register!`
intact; the example therefore does not register again after reset. Without a
reset, a successful load remains stale and a decryption failure keeps
rethrowing. As with native readers, a process restart begins with an empty Aero
cache and sees current ciphertext. Do not print the config or secret values,
poll the file, or reset/re-read once per tag.

#### A different key per profile

A real case: eval runs need to authenticate with a different OpenRouter key
than production, so benchmark spend stays off the key serving real traffic.
Both keys live in the same store — the whole solution is one config line,
combining aero's `#profile` with `#secret/req`:

```clojure
:api-key #profile {:default #secret/req :openrouter/api-key
                   :evals   #secret/req :openrouter/evals-api-key}
```

with the caller passing `{:profile :evals}` to `read-config`. This is safe
because aero evaluates **only the selected branch** — reading with `:default`
decrypts and looks up `:openrouter/api-key` alone, and `:openrouter/evals-api-key`
doesn't need to exist in the store at all; reading with `:evals` is the
mirror image. That's a genuine advantage of building on aero rather than a
bespoke reader: you can add a profile for a key some consumers don't have —
a benchmark-only key, say — without breaking every `read-config` call that
never selects it.

### As a map (Integrant component / direct use)

```clojure
(require '[com.kirahowe.secrets :as secrets])

(def m (secrets/load-secrets (clojure.java.io/resource "secrets.edn.age")
                             {:app "myapp"}))
(secrets/get-secret m :database/url)        ; → "jdbc:…"
(secrets/get-secret m [:r2 :account-id])    ; nested path
```

The second argument selects the identity (private key): a path string/File, or
an opts map with `:identity-file` (an explicit path) or `:app` (→
`~/.config/<app>/key.txt`). Without it, only the `SECRETS_AGE_IDENTITY*` environment
variables are consulted — there is deliberately no default key path, so loading
with no resolvable identity throws (listing your options) rather than silently
reading some other app's key. Passing `{:app "myapp"}` gives you the local
default *and* still lets the env vars win in production.

An Integrant `init-key` is two lines:

```clojure
(defmethod ig/init-key ::secrets [_ {:keys [resource]}]
  (secrets/load-secrets (io/resource resource) {:app "myapp"}))
```

## Production & CI: injecting the key

Locally the key lives at `~/.config/<app>/key.txt`. Anywhere else, provide it
through one of three environment variables, checked in this order (and before
the local default path):

| Var                 | Value                                                                 |
| ------------------- | --------------------------------------------------------------------- |
| `SECRETS_AGE_IDENTITY_FILE` | a path to the key file                                                |
| `SECRETS_AGE_IDENTITY`      | the key file *contents*, used verbatim (never decoded) — materialized to an owner-only (0600) temp file |
| `SECRETS_AGE_IDENTITY_B64`  | base64 of the key file contents (newline-tolerant), for secret stores that mangle multi-line values; invalid base64 throws — no silent fallback |

A variable that is **set but empty** throws, naming itself, rather than being
treated as absent. CI runners expand a missing or misnamed secret to the empty
string (`SECRETS_AGE_IDENTITY: ${{ secrets.AGE_KEY }}` with no such secret), and
falling through to the local `~/.config/<app>/key.txt` would let that broken
deployment config quietly succeed on a developer machine. Unset the variable to
fall back deliberately.

So a Fly / Docker / CI deployment sets exactly one secret:

```sh
flyctl secrets set SECRETS_AGE_IDENTITY="$(cat ~/.config/myapp/key.txt)"
```

The container image needs the `age` binary (e.g. `apt-get install -y age`). The
encrypted `secrets.edn.age` ships in the image — in the jar or on the classpath.
`load-secrets` and the reader literals handle `jar:` resource URLs from inside
an uberjar (the ciphertext is copied to an owner-only temp file so `age` can
read it), so the file works the same whether it sits on disk or inside the jar.
`SECRETS_AGE_IDENTITY` decrypts it at startup.

### GitHub Actions

GitHub's runner images don't ship `age`, so decryption fails until you install
it. Next to the Fly command above, a job that actually reads secrets (as
opposed to the manifest-only [verify job](#verifying-in-ci) below) needs an
install step and the identity in its environment:

```yaml
- name: Install age
  run: sudo apt-get update && sudo apt-get install -y age

- name: Run the thing
  run: bb evals
  env:
    SECRETS_AGE_IDENTITY: ${{ secrets.SECRETS_AGE_IDENTITY }}
```

The repository secret's value is the **contents** of `~/.config/<app>/key.txt`,
not a path — and the ciphertext it decrypts is the one already committed to
the repo. That's the whole point of the design (the secret Actions holds is
small and rotatable; the thing it unlocks travels with the code), but it's
still the part that feels backwards the first time. Set it with:

```sh
gh secret set SECRETS_AGE_IDENTITY < ~/.config/myapp/key.txt
```

### When the runtime can't exec `age`

Decryption shells out to the `age` binary (see [Trade-offs and
limitations](#trade-offs-and-limitations)), so every runtime that decrypts
needs it on `PATH`. Some platforms can't offer that at all — Cloudflare
Workers, Deno Deploy, and edge runtimes generally run your code somewhere that
can't exec a subprocess, `age` or otherwise.

That's a boundary of the design, not a gap: this library wraps a CLI tool, so
anywhere a CLI tool can't run, neither can it. The fix isn't to work around
that — it's to use this library for development and CI, where the ciphertext
and manifest still do their job, and let the edge platform's own secret store
hold the value for production.

| Where | How the identity gets there |
|---|---|
| Laptop | `~/.config/<app>/key.txt` |
| GitHub Actions | `SECRETS_AGE_IDENTITY` repository secret |
| Container / VM | env var, `age` installed in the image |
| Edge runtime (Workers, Deno Deploy) | **it doesn't** — use the platform's own secret store; this library covers dev and CI |

## Initialization layouts

The initializer requires `--app`, defaults to `--env dev`, and supports these
explicit layouts:

| Invocation | Template | Ciphertext + manifest | Identity | Recipients |
| --- | --- | --- | --- | --- |
| default tracked | `secrets/secrets.edn.example` | `secrets/secrets.edn.{age,manifest}` | `~/.config/<app>/key.txt` | none |
| `--team` | same tracked template | same tracked store | external app key | tracked `secrets/recipients.txt` |
| `--layout disposable` | tracked `secrets/secrets.edn.example` | ignored `.local/secrets/secrets.edn.{age,manifest}` | ignored `.local/secrets/key.txt` | ignored `.local/secrets/recipients.txt` with `--team` |

The tracked template is safe documentation and contains placeholders, never
real values. The ciphertext is safe encrypted data. The manifest is plaintext
but value-free; it exposes key names and shapes as described below. A recipients
file contains public keys only. These four public artifacts and `bb.edn` may be
committed. Private identities, decrypted plaintext, and the explicit
`.local/secrets/` disposable layout must not be committed.

Team initialization creates or preserves the public recipients file, but does
not silently add a key to it. After explicitly generating a personal identity,
run `bb secrets add-recipient dev` before creating the first team ciphertext.
All configured artifact paths must remain canonically distinct; aliases such as
`secret.age` and `./secret.age` count as the same path and are rejected.

The four included consumers illustrate different needs rather than four copies
of one schema: quickstart, Aero, and team-CI carry CLI configuration in
`bb.edn`; the Integrant service uses JVM runtime wiring and a shell bootstrap.
The common CLI schema is only `:app`, `:default-environment`, and an environment
with `:secrets-file`. Template, manifest, and key paths derive from that minimum;
disposable and multi-recipient layouts make their exceptional paths explicit.

## Environments

Each environment is an independent encrypted file. By default they share one key
(`~/.config/<app>/key.txt`) — simplest for a solo project. Give an environment
its own `:key-file` to isolate it (e.g. so a dev key can't read prod). The same
resource name (`secrets.edn.age`) can live on each environment's own classpath,
so one set of reader literals serves every environment.

## Teams: multiple recipients

The default single-key model means everyone shares one private key. For a team,
point an environment at a **recipients file** — a committed list of age public
keys — and it encrypts to all of them (`age -R`). Each person decrypts with
their own private identity; private identities are never shared.

```clojure
;; bb.edn — add :recipients-file to an environment
{:prod {:secrets-file    "env/prod/resources/secrets.edn.age"
        :recipients-file "env/prod/recipients.txt"}}
```

### First owner: no ciphertext yet

Team initialization creates or preserves an empty public recipients file. The
first owner creates a personal identity, adds its public recipient, then creates
the initial store:

```sh
bb secrets keygen prod
bb secrets add-recipient prod
printf %s "$INITIAL_SECRET_VALUE" | bb secrets set prod :service/token
# Or create the initial store in an editor instead:
# bb secrets new prod
```

Run either `set` or `new` for the last step. There is nothing to `reencrypt`
after `add-recipient` while the ciphertext is absent: the first `set` or `new`
already encrypts to every public recipient currently in `recipients.txt`.

### Existing ciphertext: add, then re-encrypt

After ciphertext exists, a teammate generates and keeps their own private
identity and sends only its `age1…` public recipient to a maintainer. A current
recipient who can decrypt the store adds that public key and re-encrypts:

```sh
bb secrets add-recipient prod age1...teammate-public-key...
bb secrets reencrypt prod
bb secrets recipients prod
```

`add-recipient` changes only the public list. `reencrypt` is what writes a new
ciphertext and value-free manifest for the current recipient set. Onboarding
therefore grants access to ciphertext produced after that re-encryption.

For offboarding, remove the person's public-key line from `recipients.txt` and
run `bb secrets reencrypt prod`. This prevents that identity from decrypting
future ciphertext only. It cannot revoke ciphertext, plaintext, clones, or
backups the person already obtained. If a private identity or an old ciphertext
is compromised, changing the recipient list is not enough: rotate every
underlying secret value or credential that copy exposed, then write ciphertext
for the remaining recipients.

Deployments and CI use a separate, non-human recipient — never a developer's
identity. Commit its public recipient, re-encrypt, and give the runtime only
that deployment recipient's private identity through exactly one supported
mechanism: `SECRETS_AGE_IDENTITY_FILE` (a secret-provided file path),
`SECRETS_AGE_IDENTITY` (raw identity contents), or
`SECRETS_AGE_IDENTITY_B64` (base64 identity contents).

The repository boundary is explicit:

- Commit public-only `recipients.txt`, encrypted `*.age` ciphertext, its
  value-free `*.manifest`, and templates containing only safe fake placeholders.
- Never commit private identities, decrypted plaintext, or real secret values.

Runtime decryption is otherwise unchanged: any currently listed identity can
decrypt the file, so `load-secrets` / `#secret/req` need no team-specific
configuration.

## Manifest: seeing what changed

Because age re-encrypts the whole file, a `git diff` of `secrets.edn.age` is an
opaque blob — you can't tell *what* changed. So every `new` / `edit` / `reencrypt`
also writes a plaintext **manifest** next to it (`secrets.edn.manifest`) that
records only the *shape* of the secrets — never a value:

```clojure
{:version 1
 :app "myapp"
 :ciphertext-sha "0b7d9f31…"   ; SHA-256 of secrets.edn.age when it was written
 :keys
 {[:auth :admins]  {:type :set, :count 3, :vhash "9ad1126f40c10b21"}
  [:database/url]  {:type :string, :vhash "32450c7262fdd852"}}}
```

Commit it. A diff of the manifest shows keys added, removed, retyped, or (via
`:vhash`) a value changed — enough to review a change meaningfully without ever
exposing a secret. `:vhash` is an HMAC keyed by a secret derived from the
private key *material* — only the `AGE-SECRET-KEY` lines, so the identity
file's comment lines and whitespace don't affect it and two copies of the same
key always agree — and someone with only the repo can't brute-force a value
from it. (In multi-recipient mode there's no single shared key, so the manifest
is structure-only — no `:vhash`.)

`:ciphertext-sha` is the SHA-256 of the encrypted `.age` file at the moment the
manifest was written. It ties the manifest to the exact ciphertext, which lets
CI check the manifest is fresh without holding any key, and lets a keyed
`verify` catch an out-of-band re-encryption even when the shape still matches.

```sh
bb secrets verify         # regenerate from the ciphertext and check every env
bb secrets verify prod    # …or just one
```

### Verifying in CI

`verify` exits 0 when everything matches, 1 on drift, and 2 when an artifact or
key is missing — so `bb secrets verify` gates a pipeline directly. It runs in
two modes:

- **Keyless freshness check.** With no identity available, `verify` compares
  the manifest's recorded `:ciphertext-sha` against the actual file. A CI job
  holding **no secret material at all** can still catch a manifest that drifted
  from its ciphertext (exit 0 on a pass, same as a keyed run).
- **Full verification.** With a key (e.g. `SECRETS_AGE_IDENTITY` on the runner),
  `verify` decrypts and checks the full shape and `:vhash`es, and also flags an
  out-of-band re-encryption via the sha even when the shape matches.

`verify` also reads the manifest's `:version` and treats an unsupported one as
drift. Disable the manifest for an environment with `:manifest false`.

## Diagnosing configuration

Run `bb secrets doctor [env]` before an operation to inspect one explicitly
selected environment, or the configured default when `[env]` is omitted. It
reports the installed `age` version, selected environment, single-key or
multi-recipient mode, and canonical paths plus existence for the ciphertext,
manifest, template, key, and recipients file. Disabled manifests and
unconfigured recipients files are labeled explicitly.

Recipient diagnostics contain only count and validity. Identity diagnostics
contain only the source label (`SECRETS_AGE_IDENTITY_FILE`,
`SECRETS_AGE_IDENTITY`, `SECRETS_AGE_IDENTITY_B64`, `:identity-file`,
`configured key path`, or `default key path`) and whether it is usable. The
command never returns or prints identity environment values, materialized
raw/base64 identity paths, recipient lines, private-key text, or secret values.

The verification fields distinguish a keyless freshness check from full
verification. Keyless verification is available only when ciphertext exists
and a readable version-1 manifest contains `:ciphertext-sha`; full verification
requires `age`, a usable identity, ciphertext, and a manifest. A disabled
manifest is reported as `skipped`.

`doctor` has exact, scriptable exit meanings:

- **0 — healthy:** the selected configuration is complete.
- **1 — warning/action needed:** a required tool, file, or identity is missing,
  recipients are unreadable, the manifest needs attention, or verification
  cannot run.
- **2 — invalid configuration:** normalization fails, the environment cannot be
  selected, or a configured recipients file is empty or contains invalid
  recipients.

## API

`com.kirahowe.secrets`
- `(load-secrets source)` / `(load-secrets source identity-or-opts)` — decrypt + read an EDN map. `source` is a path, File, or URL/resource (including a `jar:` URL inside an uberjar); the second arg is an identity path String/File or an opts map `{:identity-file … :app …}`. Every failure throws `ex-info` with a `:reason` — `:no-identity` (no identity resolves, or the resolved file doesn't exist) or `:no-file` (the source is nil, names a path that doesn't exist, or wraps another IOException) — the same vocabulary `#secret/req` uses, so a consumer can branch on it whichever way it reached the store.
- `(get-secret m key-path)` / `(get-secret m key-path default)` — keyword or vector path.
- `(reader-literals opts)` → `{'secret/req … 'secret/opt …}`; `(merge-readers readers opts)`.
- `(identity-from-env)` — identity path from `SECRETS_AGE_IDENTITY_FILE` / `SECRETS_AGE_IDENTITY` / `SECRETS_AGE_IDENTITY_B64`, or nil when none is set. A variable that is set but empty throws.
- `(resolve-identity-file)` / `(resolve-identity-file app-or-opts)` — the env vars first, then `~/.config/<app>/key.txt` when an app name is known; nil otherwise. The path is *conventional* — it's never checked for existence, so a non-nil result doesn't mean a usable key is actually there.
- `(identity-available?)` / `(identity-available? app-or-opts)` — true when an identity actually resolves **and** its file exists on disk. The "do I have a key, or should I tell the user to run `keygen`?" check; `app-or-opts` also accepts an opts map's `:identity-file`.
- `(owner-only-temp-file! prefix suffix)` — a delete-on-exit temp file that is 0600 from the moment it exists.
- `(expand-home path)`.

`com.kirahowe.secrets.age` — `version`, `installed?`, `public-key`, `valid-recipient?`, `keygen!`, `encrypt-file!` (to an identity file, a `:recipients-file`, or a `:recipients` list — a bare String/File always means an identity-file *path*; bare `age1…` public-key strings throw, pass them as `{:recipients […]}`), `decrypt` (UTF-8 string), `decrypt-bytes` (byte array, binary-safe), `decrypt-to-file!` (byte-for-byte). The positional input is passed behind an option terminator (`--`), and every path-valued argument — that input, the `-o` output, the `-i` identity, the `-R` recipients file — is normalized so a dash-leading path becomes `./-name`, so filenames beginning with `-` (including names identical to age options) work like any other file; a blank or nil path throws `ex-info` instead of falling back to stdin. `:recipients` strings are recipient *values*, not paths, and are passed through as given.

`com.kirahowe.secrets.manifest` — pure manifest helpers: `entries`, `(render {:app … :ciphertext-sha …} entries)`, `diff`, `value-type`, `hmac-key`.

`com.kirahowe.secrets.cli` — `(run! config args)` and the individual command fns. The command fns are a REPL-safe API: they return data (paths, result maps, `:aborted` from a declined overwrite prompt) and throw `ex-info` on failure — only `run!` prints error data and exits. `(verify! config env)` returns `{:results {env status} :exit code}`; `(doctor! config env)` safely normalizes one raw selected/default environment and returns its structured age, artifact, identity-source, recipient, and verification-capability fields plus `:status` and `:exit`. Config keys: `:app`, `:default-environment`, `:environments {env {:secrets-file … :key-file … :identity-file … :template … :manifest … :recipients-file …}}` — validated on load (`:app` and `:secrets-file` required, no blank path strings, `.age` extension unless both `:template` and `:manifest` are explicit), and each environment's decrypt-side identity resolves from the `SECRETS_AGE_IDENTITY*` env vars before an explicit `:identity-file`, then falls back to its configured/default `:key-file`.

`com.kirahowe.secrets.init` — Babashka-only project bootstrap entrypoint.
`(-main & args)` parses `--app`, optional `--env`, `--layout`, `--team`,
`--keygen`, and `--apply`; `(init! opts)` exposes the preview/apply operation for
programmatic use. It preserves `bb.edn` formatting with Babashka's bundled
`rewrite-clj`, refuses conflicts and unsafe paths, and returns a status map.

## Examples

See the [examples guide](examples/README.md) for a choice matrix and runnable
starters: [quickstart-bb](examples/quickstart-bb/README.md),
[integrant-service](examples/integrant-service/README.md),
[aero-profiles](examples/aero-profiles/README.md), and
[team-ci](examples/team-ci/README.md).

## Development

Project Clojure code follows a 100-column policy. Tests require `age` and a
JDK.

```sh
bb format          # format Clojure source with cljfmt
bb format:check    # check formatting without changing files
bb lint            # lint Clojure source with clj-kondo
bb test            # run the suite under Babashka
clojure -M:test    # run the suite under JVM Clojure
```

Other development tasks:

```sh
bb secrets help            # demo the CLI against a throwaway tmp/ file
clojure -T:build install   # build + install the jar to ~/.m2 (needs a JDK)
```

### The documentation book

Full documentation lives in a [Quarto](https://quarto.org) book under
`book/chapters` — quick start, design rationale, runtime/CLI/teams/manifest
guides, production & CI, caveats, and a generated API reference. Chapters are
literate Clojure namespaces rendered with [Clay](https://scicloj.github.io/clay/),
so every example is evaluated against the real library at build time.

```sh
bb book:build     # render the book into book/rendered (needs JDK + quarto + age)
bb book:preview   # serve the rendered book locally
bb book:watch     # re-render chapters on save (Clay live reload)
```

## Trade-offs and limitations

This is the "encrypted secrets in git" model (like SOPS, git-crypt, sealed-
secrets), done with EDN and age. It's a deliberately small tool; know what
you're trading for that simplicity.

- **Ciphertext diffs are opaque.** age re-encrypts the whole file, so a `git
  diff` of `secrets.edn.age` reveals nothing. The [manifest](#manifest-seeing-what-changed)
  makes *which* keys changed reviewable, but you never see the changed *value*
  in a PR. If reviewing plaintext values is a hard requirement, you want per-
  value encryption (SOPS) instead.
- **Access is coarse and shared.** One key decrypts an entire environment;
  there's no per-secret access control within a file. Multi-recipient gives each
  person their own key, but every recipient can still read the whole file.
- **Key rotation is all-or-nothing, and history is immutable.** A leaked key can
  decrypt every past commit it encrypted; true revocation means rotating the
  secret *values*, not just the key (see [Security notes](#security-notes)).
- **No authenticity / signing.** age encrypts *to* a recipient but doesn't sign,
  so anyone holding the public key(s) can craft a file that decrypts cleanly.
  Integrity rests on git review + branch protection; `verify` and `:vhash`
  detect manifest/ciphertext *drift*, not a forged commit. (A keyless `verify`
  run checks freshness only, via `:ciphertext-sha`; the full value-level check
  still needs a key.)
- **`age` is a runtime dependency.** Decryption shells out, so every environment
  that decrypts — dev, CI, the production container — needs the `age` binary on
  PATH, not just the build. (The one exception: a keyless `bb secrets verify`
  compares hashes only, so a freshness-gating CI job needs neither a key nor
  the binary.)
- **Plaintext briefly touches disk on `edit`/`new`.** It's an owner-only temp
  file, securely deleted after — but the window is unavoidable, editor swap/undo
  files are outside this tool's control, and secure-delete is best-effort (and
  largely symbolic on SSD / copy-on-write filesystems like APFS).
- **The manifest leaks structure.** Key names and value types/shape are
  committed in the clear (values are not). Opt out per environment with
  `:manifest false`.
- **`:vhash` only in single-key mode.** Detecting a same-type value edit needs a
  shared secret to key the HMAC; multi-recipient setups have no single shared
  key, so their manifests are structure-only (add / remove / retype still show;
  a rotated string does not).
- **Where it fits.** A solo developer or small team shipping a handful of apps
  with no secrets infrastructure. If you need dynamic secrets, centralized
  audit, fine-grained IAM, or automatic rotation, a dedicated secrets manager
  (Vault, a cloud KMS / secret manager) earns its extra complexity.

## Security notes

- Never commit decrypted plaintext — only `*.edn.age` (encrypted),
  `*.edn.manifest` (value-free shape), `*.edn.example` (templates), and
  `recipients.txt` (public keys). `edit`/`new` keep plaintext in an owner-only
  temp file and securely delete it.
- Back up the private key (a password manager). It is not in git and cannot be
  recovered; losing it means re-keying every secret.
- **A leaked key exposes history, not just the present.** Git history is
  immutable, so a key that leaks can decrypt every past version of every file it
  encrypted. Rotating the key is not enough — you must rotate the underlying
  secret *values*. Likewise, removing a recipient stops *future* access but not
  their ability to decrypt old commits.
- The decrypted map lives in process memory like any config; an RCE in the host
  app can read it. Encryption protects secrets at rest and in git, not from a
  compromised running process.
- The manifest is intentionally plaintext: it leaks key *names* and value
  *types/shape* (not values). If a key's mere existence is sensitive, set
  `:manifest false` for that environment.
- Sensitive temp files (injected identities, plaintext during `edit`) are
  created owner-only (0600) atomically on POSIX filesystems. On non-POSIX
  filesystems (e.g. Windows) the permissions are applied best-effort after
  creation — the library targets POSIX systems.
- **Pathnames reaching `age` are data, never options.** Encryption and
  decryption shell out to the `age` binary, so a path that arrived on its
  command line as an option would let a filename choose the operation instead of
  naming the file it operates on. Every invocation that takes an input pathname
  therefore terminates its options with `--` before it, and every path argument
  that starts with a dash is passed as `./-name` — age reads a bare `-` from
  standard input even behind a terminator, so the prefix is the part that keeps
  a filename a filename.

## License

MIT © 2026 Kira Howe. See [LICENSE](LICENSE).
