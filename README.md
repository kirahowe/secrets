# com.kirahowe/secrets

Manage application secrets as a single **version-controlled, age-encrypted EDN
file** instead of a sprawl of environment variables. One private key decrypts it;
everything else — structure, defaults, and the encrypted ciphertext itself —
lives in git, with a committed value-free manifest that makes each change
reviewable.

- **Pluggable.** Zero runtime dependencies beyond Clojure. Loads and runs
  identically under JVM Clojure and [babashka](https://babashka.org).
- **A `bb secrets` task.** `keygen` · `new` · `edit` · `verify` · `show-key` ·
  `add-recipient` · `recipients` · `reencrypt` · `encrypt` · `decrypt`, wired
  into any project with one task definition.
- **Two ways to consume secrets:** `#secret` / `#secret/opt` EDN reader literals,
  or a plain `load-secrets` map for Integrant/component setups.
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
io.github.you/secrets {:git/tag "v0.1.0" :git/sha "…"}
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
`~/.config/<app>/key.txt`, `:template` → `<secrets-file>.example`.

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
bb secrets decrypt env/prod/resources/secrets.edn.age   # print plaintext to stdout
```

## Using secrets at runtime

### Reader literals (recommended for EDN-configured systems)

`reader-literals` returns `#secret` / `#secret/opt` tag functions to merge into
the `:readers` you pass to `clojure.edn/read-string` or
`integrant.core/read-string`:

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
{:db   {:jdbc-url #secret :database/url}        ; required — throws if absent
 :llm  {:api-key  #secret/opt :llm/api-key}     ; optional — nil if absent
 :auth {:admins   #secret :auth/admins}}        ; values are real EDN: #{"a@b.com"}
```

The file is resolved and decrypted **once, lazily**, on the first `#secret`
encountered — so dev/test configs with no secret tags never touch `age` or the
key, even if a secrets file happens to be on the classpath. `#secret/opt` returns
`nil` when the file or key is absent; `#secret` throws.

### As a map (Integrant component / direct use)

```clojure
(require '[com.kirahowe.secrets :as secrets])

(def m (secrets/load-secrets (clojure.java.io/resource "secrets.edn.age")))
(secrets/get-secret m :database/url)        ; → "jdbc:…"
(secrets/get-secret m [:r2 :account-id])    ; nested path
```

A six-line Integrant `init-key`:

```clojure
(defmethod ig/init-key ::secrets [_ {:keys [resource]}]
  (secrets/load-secrets (io/resource resource)))
```

## Production & CI: injecting the key

Locally the key lives at `~/.config/<app>/key.txt`. Anywhere else, provide it
through one of two environment variables (checked before the default path):

| Var                | Value                                                              |
| ------------------ | ----------------------------------------------------------------- |
| `AGE_IDENTITY_FILE`| a path to the key file                                            |
| `AGE_IDENTITY`     | the key *contents* (raw or base64) — materialized to a 0600 temp file |

So a Fly / Docker / CI deployment sets exactly one secret:

```sh
flyctl secrets set AGE_IDENTITY="$(cat ~/.config/myapp/key.txt)"
```

The container image needs the `age` binary (e.g. `apt-get install -y age`). The
encrypted `secrets.edn.age` ships in the image (in the jar or on the classpath);
`AGE_IDENTITY` decrypts it at startup.

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
  human needs to hold it. It's still injected as `AGE_IDENTITY` at runtime.
- Runtime decryption is unchanged: any listed identity decrypts the file, so
  `load-secrets` / `#secret` need no configuration for this.

## Manifest: seeing what changed

Because age re-encrypts the whole file, a `git diff` of `secrets.edn.age` is an
opaque blob — you can't tell *what* changed. So every `new` / `edit` / `reencrypt`
also writes a plaintext **manifest** next to it (`secrets.edn.manifest`) that
records only the *shape* of the secrets — never a value:

```clojure
{:version 1
 :app "myapp"
 :keys
 {[:auth :admins]  {:type :set, :count 3, :vhash "9ad1126f40c10b21"}
  [:database/url]  {:type :string, :vhash "32450c7262fdd852"}}}
```

Commit it. A diff of the manifest shows keys added, removed, retyped, or (via
`:vhash`) a value changed — enough to review a change meaningfully without ever
exposing a secret. `:vhash` is an HMAC keyed by a secret derived from the private
key, so someone with only the repo can't brute-force a value from it. (In
multi-recipient mode there's no single shared key, so the manifest is
structure-only — no `:vhash`.)

```sh
bb secrets verify         # regenerate from the ciphertext and check every env
bb secrets verify prod    # …or just one; exits non-zero on drift, so CI can gate
```

Add `bb secrets verify` to CI to catch a manifest that drifted from its secrets.
Disable the manifest for an environment with `:manifest false`.

## API

`com.kirahowe.secrets`
- `(load-secrets source)` / `(load-secrets source identity-file)` — decrypt + read an EDN map.
- `(get-secret m key-path)` / `(get-secret m key-path default)` — keyword or vector path.
- `(reader-literals opts)` → `{'secret … 'secret/opt …}`; `(merge-readers readers opts)`.
- `(resolve-identity-file)` / `(expand-home path)`.

`com.kirahowe.secrets.age` — `installed?`, `public-key`, `valid-recipient?`, `keygen!`, `encrypt-file!` (to an identity, a `:recipients-file`, or a `:recipients` list), `decrypt`, `decrypt-to-file!`.

`com.kirahowe.secrets.manifest` — pure manifest helpers: `entries`, `render`, `diff`, `value-type`, `hmac-key`.

`com.kirahowe.secrets.cli` — `(run! config args)` and the individual command fns. Config keys: `:app`, `:default-environment`, `:environments {env {:secrets-file … :key-file … :template … :manifest … :recipients-file …}}`.

## Development

```sh
bb test                    # run the suite under babashka (needs age installed)
bb secrets help            # demo the CLI against a throwaway tmp/ file
clojure -T:build install   # build + install the jar to ~/.m2 (needs a JDK)
```

## Trade-offs and limitations

This is the "encrypted secrets in git" model (like SOPS, git-crypt, sealed-
secrets), made EDN-native and age-backed. It's a deliberately small tool; know
what you're trading for that simplicity.

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
  detect manifest/ciphertext *drift*, not a forged commit.
- **`age` is a runtime dependency.** Decryption shells out, so every environment
  that decrypts — dev, CI, the production container — needs the `age` binary on
  PATH, not just the build.
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
- **Right size.** Ideal for a solo developer or small team shipping a handful of
  apps with no secrets infrastructure. If you need dynamic secrets, centralized
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

## License

MIT © 2026 Kira Howe. See [LICENSE](LICENSE).
