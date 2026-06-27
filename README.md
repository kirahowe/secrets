# com.kirahowe/secrets

Manage application secrets as a single **version-controlled, age-encrypted EDN
file** instead of a sprawl of environment variables. One private key decrypts it;
everything else — structure, defaults, and the encrypted ciphertext itself —
lives in git and is reviewed like any other code.

- **Pluggable.** Zero runtime dependencies beyond Clojure. Loads and runs
  identically under JVM Clojure and [babashka](https://babashka.org).
- **A `bb secrets` task.** `keygen` · `new` · `edit` · `show-key` · `encrypt` ·
  `decrypt`, wired into any project with one task definition.
- **Two ways to consume secrets:** `#secret` / `#secret/opt` EDN reader literals,
  or a plain `load-secrets` map for Integrant/component setups.

It wraps [`age`](https://age-encryption.org) — a small, audited, modern
file-encryption tool — so there are no GPG keyrings, no KMS, no vault to run.

## Why not environment variables?

Env vars for secrets are easy to start with and painful to live with: they
sprawl (every integration adds another), they're untyped strings (a
comma-separated allowlist becomes parsing code), and they aren't
version-controlled (no history, no review, just mutable state in a deploy
platform). Encrypting a plain EDN map fixes all three — the map is real data
(sets, nested maps, numbers), the encrypted form is committed and diffable, and
the only out-of-band secret is one `age` key.

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
self-documenting. Saving writes `secrets.edn.age` — commit that; it's ciphertext.

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

## API

`com.kirahowe.secrets`
- `(load-secrets source)` / `(load-secrets source identity-file)` — decrypt + read an EDN map.
- `(get-secret m key-path)` / `(get-secret m key-path default)` — keyword or vector path.
- `(reader-literals opts)` → `{'secret … 'secret/opt …}`; `(merge-readers readers opts)`.
- `(resolve-identity-file)` / `(expand-home path)`.

`com.kirahowe.secrets.age` — `installed?`, `public-key`, `keygen!`, `encrypt-file!`, `decrypt`, `decrypt-to-file!`.

`com.kirahowe.secrets.cli` — `(run! config args)` and the individual command fns.

## Development

```sh
bb test                    # run the suite under babashka (needs age installed)
bb secrets help            # demo the CLI against a throwaway tmp/ file
clojure -T:build install   # build + install the jar to ~/.m2 (needs a JDK)
```

## Security notes

- Never commit decrypted plaintext — only `*.edn.age` (encrypted) and
  `*.edn.example` (templates). `edit`/`new` keep plaintext in an owner-only temp
  file and securely delete it.
- Back up the private key (a password manager). It is not in git and cannot be
  recovered; losing it means re-keying every secret.
- The decrypted map lives in process memory like any config; an RCE in the host
  app can read it. Encryption protects secrets at rest and in git, not from a
  compromised running process.

## License

MIT © 2026 Kira Howe. See [LICENSE](LICENSE).
