# com.kirahowe/secrets

Manage application secrets as a single **version-controlled, age-encrypted EDN
file** instead of a pile of environment variables. One private key decrypts it;
everything else — structure, defaults, and the encrypted ciphertext itself —
lives in git, with a committed value-free manifest that makes each change
reviewable.

- **No dependencies.** Nothing beyond Clojure itself, and it loads and runs
  the same under JVM Clojure and [babashka](https://babashka.org).
- **A `bb secrets` task.** `keygen` · `new` · `edit` · `verify` · `show-key` ·
  `add-recipient` · `recipients` · `reencrypt` · `encrypt` · `decrypt`, wired
  into any project with one task definition.
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
(a `:local/root` does not resolve inside a remote Docker build, where the sibling
isn't in the build context):

```clojure
;; git
io.github.kirahowe/secrets {:git/tag "v0.1.0" :git/sha "…"}
;; or Maven, after `clojure -T:build install` / a Clojars deploy
com.kirahowe/secrets {:mvn/version "0.1.0"}
```

## Quick start

**1. Wire the task** into your `bb.edn`:

```clojure
{:deps  {com.kirahowe/secrets {:local/root "../secrets"}}
 :tasks {secrets
         {:doc      "Manage encrypted secrets (age)"
          :requires ([com.kirahowe.secrets.cli :as secrets-cli])
          :task     (secrets-cli/run!
                     {:app "myapp"
                      :default-environment :prod
                      :environments
                      {:prod {:secrets-file "env/prod/resources/secrets.edn.age"}
                       :dev  {:secrets-file "env/dev/resources/secrets.edn.age"}}}
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

**2. Create secrets:**

```sh
bb secrets keygen prod    # → ~/.config/myapp/key.txt  (BACK THIS UP — not in git)
bb secrets new prod       # opens $EDITOR with the template; fill in, save, encrypt
```

`new` seeds your editor from `secrets.edn.example` (if present) so the shape is
self-documenting. Saving writes `secrets.edn.age` (ciphertext) and
`secrets.edn.manifest` (its value-free shape) — commit both.

**3. Day to day:**

```sh
bb secrets edit prod      # decrypt → $EDITOR → re-encrypt (no plaintext left on disk)
bb secrets show-key       # print public key(s) to share with teammates
bb secrets decrypt prod env/prod/resources/secrets.edn.age  # plaintext to stdout
```

Every command takes the environment first (`bb secrets decrypt [env] <file>`);
omit it to use the default environment. `decrypt` writes to stdout byte-for-byte,
so it works for any `.age` file, not just EDN.

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
key, even if a secrets file happens to be on the classpath. The two tags mirror
required/optional env reads: `#secret/opt` returns `nil` when the secrets file
is absent, when no identity (key) is available, or when the key is missing from
the decrypted map; `#secret/req` throws in all three cases, saying which. A
genuine decryption failure — the identity exists but `age` fails — always
throws, for both tags.

### Aero

[aero](https://github.com/juxt/aero) resolves tags through its own
`aero.core/reader` multimethod rather than a `:readers` map, so delegate the
two tags to the same functions:

```clojure
(def secret-readers
  (secrets/reader-literals {:app "myapp" :resource "secrets.edn.age"}))

(defmethod aero.core/reader 'secret/req [_opts _tag value]
  ((secret-readers 'secret/req) value))
(defmethod aero.core/reader 'secret/opt [_opts _tag value]
  ((secret-readers 'secret/opt) value))
```

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

## Environments

Each environment is an independent encrypted file. By default they share one key
(`~/.config/<app>/key.txt`) — simplest for a solo project. Give an environment
its own `:key-file` to isolate it (e.g. so a dev key can't read prod). The same
resource name (`secrets.edn.age`) can live on each environment's own classpath,
so one set of reader literals serves every environment.

## Teams: multiple recipients

The default single-key model means everyone shares one private key. For a team,
point an environment at a **recipients file** — a committed list of age public
keys — and it encrypts to all of them (`age -R`). Each person then decrypts with
their *own* key; nobody shares a private key.

```clojure
;; bb.edn — add :recipients-file to an environment
{:prod {:secrets-file    "env/prod/resources/secrets.edn.age"
        :recipients-file "env/prod/recipients.txt"}}
```

Public keys are safe to commit, so `recipients.txt` lives in git. The workflow:

```sh
bb secrets keygen prod                 # each dev makes their own key
bb secrets add-recipient prod          # …and adds their public key to the list
#   (a maintainer can also add someone else's: bb secrets add-recipient prod age1…)
bb secrets reencrypt prod              # re-encrypt so new recipients can decrypt
bb secrets recipients prod             # list who can currently decrypt
```

- **Onboard** = add a key + `reencrypt`. **Offboard** = remove the line +
  `reencrypt` (stops *future* access; see the key-rotation note below).
- **Deploy/CI** gets its own recipient — include a dedicated deploy key so no
  human needs to hold it. It's still injected as `SECRETS_AGE_IDENTITY` at runtime.
- Runtime decryption is unchanged: any listed identity decrypts the file, so
  `load-secrets` / `#secret/req` need no configuration for this.

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

## API

`com.kirahowe.secrets`
- `(load-secrets source)` / `(load-secrets source identity-or-opts)` — decrypt + read an EDN map. `source` is a path, File, or URL/resource (including a `jar:` URL inside an uberjar); the second arg is an identity path String/File or an opts map `{:identity-file … :app …}`.
- `(get-secret m key-path)` / `(get-secret m key-path default)` — keyword or vector path.
- `(reader-literals opts)` → `{'secret/req … 'secret/opt …}`; `(merge-readers readers opts)`.
- `(identity-from-env)` — identity path from `SECRETS_AGE_IDENTITY_FILE` / `SECRETS_AGE_IDENTITY` / `SECRETS_AGE_IDENTITY_B64`, or nil when none is set. A variable that is set but empty throws.
- `(resolve-identity-file)` / `(resolve-identity-file app-or-opts)` — the env vars first, then `~/.config/<app>/key.txt` when an app name is known; nil otherwise.
- `(owner-only-temp-file! prefix suffix)` — a delete-on-exit temp file that is 0600 from the moment it exists.
- `(expand-home path)`.

`com.kirahowe.secrets.age` — `installed?`, `public-key`, `valid-recipient?`, `keygen!`, `encrypt-file!` (to an identity file, a `:recipients-file`, or a `:recipients` list — a bare String/File always means an identity-file *path*; bare `age1…` public-key strings throw, pass them as `{:recipients […]}`), `decrypt` (UTF-8 string), `decrypt-bytes` (byte array, binary-safe), `decrypt-to-file!` (byte-for-byte).

`com.kirahowe.secrets.manifest` — pure manifest helpers: `entries`, `(render {:app … :ciphertext-sha …} entries)`, `diff`, `value-type`, `hmac-key`.

`com.kirahowe.secrets.cli` — `(run! config args)` and the individual command fns. The command fns are a REPL-safe API: they return data (paths, result maps, `:aborted` from a declined overwrite prompt) and throw `ex-info` on failure — only `run!` prints error data and exits; `(verify! config env)` returns `{:results {env status} :exit code}`. Config keys: `:app`, `:default-environment`, `:environments {env {:secrets-file … :key-file … :template … :manifest … :recipients-file …}}` — validated on load (`:app` and `:secrets-file` required, no blank path strings, `.age` extension unless both `:template` and `:manifest` are explicit), and each environment's decrypt-side `:identity-file` resolves from the `SECRETS_AGE_IDENTITY*` env vars before falling back to its `:key-file`, so CI holding only `SECRETS_AGE_IDENTITY` can encrypt, decrypt, and verify.

## Development

```sh
bb test                    # run the suite under babashka (needs age installed)
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

## License

MIT © 2026 Kira Howe. See [LICENSE](LICENSE).
