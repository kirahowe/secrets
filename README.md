# com.kirahowe/secrets

Manage application secrets as a single **version-controlled, age-encrypted EDN
file** instead of a pile of environment variables. One private key decrypts it;
everything else — structure, defaults, and the encrypted ciphertext itself —
lives in git, with a committed value-free manifest that makes each change
reviewable.

- **One private key to deploy.** Production receives a single age identity
  through an environment variable or a mounted file, not a list of secret
  values.
- **Real EDN at runtime.** Sets, vectors, nested maps, and numbers, not just
  strings. Load the whole map, or reference values from your EDN config with
  `#secret/req` and `#secret/opt`. Works with Aero, and the plain map suits
  Integrant or component.
- **Encrypted secrets live in git** beside the code that uses them, one file
  per environment. Load them from disk or from inside the jar.
- **Reviewable changes.** Every write updates a value-free manifest, so a
  diff shows which keys were added, removed, or changed. CI can check that
  the manifest is fresh without holding a key.
- **Solo or team.** Encrypt to your own key, or to a committed list of
  recipients so each teammate decrypts with their own.
- **A `bb secrets` task** for the day to day: edit in your editor, set one
  value from a hidden prompt or from stdin, diagnose with `doctor`, and a
  project initializer that previews before it writes.
- **Just files and age.** No secrets server, no KMS, no cloud account, no
  GPG keyring.

It wraps [`age`](https://age-encryption.org) — a small, audited, modern
file-encryption tool — so there are no GPG keyrings, no KMS, no vault to run.
Command-line parsing uses [babashka/cli](https://github.com/babashka/cli),
which is built into Babashka and included as a JVM dependency for
reproducible resolution; the project otherwise uses core Clojure APIs plus
the `age` CLI.

## Why not environment variables?

Environment variables are easy to start with and painful to live with. They
sprawl: every integration adds another, and nobody can tell from the
repository what the application needs. They are untyped strings, so a
comma-separated allowlist becomes parsing code. And they live outside version
control, as mutable state in a deploy platform, with no history and no review.

Encrypting a plain EDN map fixes all three. The map is real data, the
encrypted form is committed, and the only out-of-band secret is one `age` key.
The ciphertext itself diffs opaquely, since age re-encrypts the whole file, so
the committed [manifest](#manifest-seeing-what-changed) is what makes changes
*reviewable*: it records the shape of the secrets, and a PR shows which keys
were added, removed, or changed without revealing any value. Secrets travel
with the code that needs them, so a new environment is a checkout and one key
rather than a checklist copied between dashboards.

That is the configuration-management principle behind
[*Continuous Delivery*](https://continuousdelivery.com/foundations/configuration-management/): version everything required to build, test,
and deploy the system, application configuration included, so that any
environment can be reproduced and any change traced. Secrets are the part of
that configuration usually kept out of version control because they are
sensitive. Encrypting them is what lets them in.

This is a deliberately small tool for solo developers and small teams whose
secrets change infrequently. If you need dynamic credentials, per-secret
access rules, or automatic rotation, see
[Trade-offs and limitations](#trade-offs-and-limitations).

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
;; or Maven, after `clojure -T:build install` locally or a Clojars release (see
;; [Releasing](#releasing) — nothing is published yet)
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

Use the same launcher with `-h` or `--help` to see the initializer's readable
usage and option list without supplying `--app`.

The initializer proposes a minimal `dev` store, names every file it would
create, merge, or leave alone, and then offers to apply it, print the
configuration for manual integration, or cancel. `--keygen` is an explicit
request to generate the identity at `~/.config/myapp/key.txt`; it runs only
after you accept and the public scaffold succeeds. Omit it to leave all
private-key handling for a later `bb secrets keygen` command. Nothing is
committed automatically.

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

For a non-interactive scaffold, the first run is preview-only and explicitly
says that no files changed. When the project path is trusted and changes are
pending, rerun with `--apply`; an untrusted preview instead explains that apply
will be refused and does not offer it as a successful next step. Applied runs
print paths and actions only. Other layout options are described under
[Initialization layouts](#initialization-layouts), and what a preview does and
does not print under [Preview output](#initializer-preview-output).

**2. Set the first value.** Run `set` from a terminal and it prompts for the
value with echo turned off, so nothing lands in shell history or a process
argument:

```sh
bb secrets set :example/api-key
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
`:template` and `:manifest` explicitly. Every resolved artifact path — the
ciphertext, manifest, template, key file, recipients file, and the identity an
environment actually reads — is canonicalized and checked as one global table
across all environments, so reusing a path for an incompatible role is rejected
before any command touches the filesystem, within one environment or between
two. Exactly three kinds of sharing are permitted: one identity/key artifact
(`:identity-file` defaults to `:key-file`, and `:key-file` defaults to one
app-wide path), one recipients list shared by several environments, and one
shared template. Anything else — two environments writing one ciphertext or one
manifest, an identity path doubling as a manifest, a key file doubling as
ciphertext — is a configuration error.

An optional top-level `:limits` map bounds untrusted inputs before any `age`
subprocess starts. It is merged over the defaults and resolved onto every
environment:

```clojure
{:limits {:max-recipients       256      ; entries in a recipients file
          :max-recipient-chars  1024     ; characters in one recipient entry
          :max-recipients-bytes 262144}} ; total size of a recipients file
```

Supply only the keys you want to change. Every supplied value must be a
positive integer, and an unknown key inside `:limits` is rejected rather than
ignored — a typo in a security limit must not read as "leave it at the
default".

To create a store through an editor instead of the stdin-based three-command
flow:

```sh
bb secrets keygen dev    # → ~/.config/myapp/key.txt  (BACK THIS UP — not in git)
bb secrets new dev       # opens $EDITOR with the template; fill in, save, encrypt
```

`new` seeds your editor from `secrets.edn.example` (if present) so the shape is
self-documenting. Saving writes `secrets.edn.age` (ciphertext) and
`secrets.edn.manifest` (its value-free shape) — commit both.

`new` and `edit` open `$VISUAL`, then `$EDITOR`, then `vim`. A variable that is
set but blank counts as unset and falls through to the next source, so an empty
`VISUAL` can't shadow a working `EDITOR`. The value may carry arguments
(`EDITOR="code --wait"`, `EDITOR="emacsclient -t"`); the file is passed to it as
a separate positional argument, never interpolated into the command.

Day to day:

```sh
bb secrets edit dev      # decrypt → $EDITOR → re-encrypt (no plaintext left on disk)
bb secrets show-key       # print public key(s) to share with teammates
bb secrets decrypt dev secrets/secrets.edn.age  # plaintext to stdout
```

Discover the full command list or one command's exact operands without touching
the encrypted files:

```sh
bb secrets              # empty arguments show the same global help
bb secrets --help
bb secrets help set       # the same command help is available as: bb secrets set -h
```

`-h` and `--help` are recognized anywhere before the `--` operand
terminator. After `--`, a flag-shaped value remains a filename, key, or
environment operand. Only `set` recognizes `--edn`, also anywhere before the
terminator; other commands preserve that spelling as an operand.

Every command takes the environment first (`bb secrets decrypt [env] <file>`);
omit it to use the default environment. `decrypt` writes to stdout byte-for-byte,
so it works for any `.age` file, not just EDN.

From a terminal, `set` prompts for the value with echo turned off. In a
script or CI, where stdin is a pipe or a file, it reads the whole input
instead:

```sh
printf %s "$OPENROUTER_API_KEY" | bb secrets set dev :openrouter/api-key
printf %s '#{"a@b.com" "b@b.com"}' | bb secrets set dev :auth/admins --edn
bb secrets rm dev :openrouter/old-key
```

`set` never takes the value as a command-line argument, so it never lands in
shell history or `ps`. Piped input loses one trailing newline. Values are
stored verbatim as strings unless you pass `--edn`, in which case the input
is parsed as EDN and its type follows from the syntax: a set, a number, a
nested map. `set` creates the environment's secrets file when it doesn't
exist yet, so bootstrapping a new environment end to end is scriptable. A
blank value is refused, because an unset CI variable expands to nothing and
storing that silently is worse than failing loudly; pass `--edn` with `""` if
you genuinely want an empty string. `rm` fails, rather than quietly doing
nothing, when the key or the file doesn't exist. `<key>` is a keyword
(`:some/key`) or a vector path (`[:a :b]`) for both commands, and both
refresh the manifest like every other write.

Two things can still expose the value. If you type the value itself into a
`printf` command at an interactive shell, the shell saves that command, value
included, in its history. Use the prompt instead. If shell tracing (`set -x`)
is on, the shell prints each command with its variables expanded before
running it, so the value appears in the trace output. Turn tracing off before
the `set` line and back on after it.

Runnable starter projects for each application shape, from a Babashka script
to an Integrant service and a team with keyless CI, are listed under
[Examples](#examples).

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
cached, including a genuine decryption failure. The cache key is the secrets
config map itself: two reads passing equal maps deliberately share one
decrypted store, and any distinguishing key — a `:tenant`, a different `:file`
— is a distinct entry. In a long-running REPL, edit the ciphertext out of
process, call `reset-cache!`, and only then re-read the whole config:

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

That cache belongs to the registration live when it was populated, so
`register!` retires it: replacing the default, or clearing it with
`(register! nil)`, drops every decrypted store and every cached failure held
under the previous registration. An equal replacement is still a new
lifecycle — re-registering a config map that compares equal to the one it
replaces clears the cache exactly as a different map would, because equal maps
from two lifecycles are not one secret. The cost is one decryption per config
at start-up and nothing after it: inside one lifecycle a config is still
decrypted once, however many tags or reads use it.

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

### Source provenance: local only

Runtime source loading performs no remote network operation. `load-secrets`
accepts filesystem path strings, `File`/`Path` values, local `file:` locators,
and `jar:file:` classpath resources such as the URL returned by `io/resource`
inside an uberjar. `reader-literals` and `merge-readers` resolve `:file` as a
filesystem path and `:resource` on the classpath, then pass the result through
that same boundary. `bb secrets` configuration is stricter still: every
artifact location is a filesystem path string, not a URL.

HTTP(S), other nonlocal schemes, remote or multiply nested `jar:` locators,
`file:` locators with an authority, malformed local locators, InputStreams, and
arbitrary `clojure.java.io/input-stream` values are rejected with
`:reason :disallowed-source`. Rejection happens from the locator alone, before
DNS resolution, connection setup, redirects, or response reads. Allowed URL
objects are reconstructed as a local file or opened directly with `JarFile`, so
a caller-provided URL handler cannot turn an allowed-looking locator into
network access.

There is deliberately no HTTP loading option and therefore no connect/read
timeout or redirect policy to configure. Fetch a remote ciphertext in an
explicit, policy-aware application step, then pass the resulting trusted local
path here; that fetcher, not this local loader, owns scheme, DNS/address, port,
redirect-hop, and finite timeout policy.

### Resource limits

Every runtime entry point — `load-secrets`, `reader-literals`, `merge-readers`
— takes an optional `:limits` map in its opts, merged over
`secrets/default-limits`:

| limit                  | default | bounds                                                   |
| ---------------------- | ------- | -------------------------------------------------------- |
| `:max-source-bytes`    | 16 MiB  | ciphertext bytes in a local file or classpath-jar entry  |
| `:max-plaintext-bytes` | 8 MiB   | plaintext bytes `age` may produce                        |
| `:max-edn-depth`       | 100     | collection nesting depth of the decrypted EDN            |

```clojure
(secrets/load-secrets (io/resource "secrets.edn.age")
                      {:app "myapp" :limits {:max-source-bytes 65536}})
```

The defaults sit far above every example in this README — a real store is
kilobytes — so ordinary use never meets them. They exist because a ciphertext
someone else can replace is otherwise an unbounded write to disk or heap
(CWE-400).

Bounds are enforced before or *while* bytes move, not after they have all been
allocated. An existing filesystem source is length-checked before `age` starts;
a classpath-jar entry is counted chunk by chunk while it is copied, without
trusting its declared size, and the copy is abandoned before the first byte past
the bound is written. Plaintext is captured from
`age`'s stdout the same way, which is why decryption runs through
`ProcessBuilder` rather than `clojure.java.shell/sh`: `sh` materializes the
complete output before any caller can look at its size. Passing a bound kills
the `age` process (`destroy`, escalating to `destroyForcibly`), drops the
partial plaintext, removes the partial temp copy or staging file immediately
rather than at JVM exit, and throws with a distinguishing `:reason` —
`:source-too-large`, `:plaintext-too-large`, or `:edn-too-deep` — carrying the
byte count and the limit, never any content.

Parsing needs one further bound and no more. EDN has no aliasing or expansion
mechanism, so a parsed graph's size is linear in the plaintext's byte count and
`:max-plaintext-bytes` already covers it; what a byte bound cannot cover is
parser recursion, so a linear pre-scan rejects nesting past `:max-edn-depth`
before `clojure.edn` — which, having no custom readers, evaluates nothing at
all — ever sees the text.

A malformed `:limits` is refused rather than read as the defaults: a non-map, an
unknown key, or a value that is not a positive integer throws with
`:invalid-limits`, because a typo in a security limit must not read as "leave it
at the default". (The management CLI's separate `:limits` config key bounds
recipients; these are the runtime's own, on a different surface.)

These bound a *secrets store*. `bb secrets decrypt <file>.age` is the
general-purpose counterpart to `bb secrets encrypt <file>` — it decrypts
whatever file you name — so it carries its own far larger 1 GiB bound instead.
A store past 8 MiB is hostile or broken; an arbitrary file past it is ordinary,
and refusing it would break a documented command.

## Production & CI: injecting the key

Locally the key lives at `~/.config/<app>/key.txt`. Anywhere else, provide it
through one of three environment variables, checked in this order (and before
the local default path):

| Var                 | Value                                                                 |
| ------------------- | --------------------------------------------------------------------- |
| `SECRETS_AGE_IDENTITY_FILE` | a path to the key file                                                |
| `SECRETS_AGE_IDENTITY`      | the key file *contents*, used verbatim (never decoded) — materialized to an owner-only (0600) temp file |
| `SECRETS_AGE_IDENTITY_B64`  | canonical base64 of the key file contents; documented ASCII wrapping is allowed, and every other malformed input throws |

For `SECRETS_AGE_IDENTITY_B64`, wrapping may contain only ASCII space (`U+0020`),
horizontal tab (`U+0009`), carriage return (`U+000D`), and line feed (`U+000A`);
those four characters are removed anywhere in single- or multi-line environment
values before decoding. Unicode whitespace, punctuation, omitted or malformed
padding, nonzero padding bits, and every other noncanonical encoding throw
without materializing an identity or echoing the input. There is no raw-content
fallback.

A variable that is **set but empty** throws, naming itself, rather than being
treated as absent. CI runners expand a missing or misnamed secret to the empty
string (`SECRETS_AGE_IDENTITY: ${{ secrets.AGE_KEY }}` with no such secret), and
falling through to the local `~/.config/<app>/key.txt` would let that broken
deployment config quietly succeed on a developer machine. Unset the variable to
fall back deliberately.

So a Fly / Docker / CI deployment sets exactly one secret. `bb secrets keygen`
prints this line for you, in the form every generated snippet uses: POSIX `sh`,
one single-quoted word per dynamic argument, and `cat --` so a key path can
never be read as an option. `:key-file` is already `~`-expanded, so the path is
absolute:

```sh
flyctl secrets set SECRETS_AGE_IDENTITY="$(cat -- '/Users/you/.config/myapp/key.txt')"
```

The surrounding `"$(…)"` is the shell's own construct rather than interpolated
configuration, and is what makes the whole key file one argument to `flyctl`.

The container image needs the `age` binary (e.g. `apt-get install -y age`). The
encrypted `secrets.edn.age` ships in the image — in the jar or on the classpath.
`load-secrets` and the reader literals handle `jar:` resource URLs from inside
an uberjar (the ciphertext is copied to an owner-only temp file so `age` can
read it), so the file works the same whether it sits on disk or inside the jar.
`SECRETS_AGE_IDENTITY` decrypts it at startup.

### The temp file `SECRETS_AGE_IDENTITY` writes

`age` reads its identity from a file, so raw and base64 contents are materialized
to an owner-only (0600) temp file, one per distinct value. That file is this
library's to remove. `(secrets/reset-identity-cache!)` checks deletion of every
identity materialized from `SECRETS_AGE_IDENTITY` or
`SECRETS_AGE_IDENTITY_B64`; a failed deletion remains tracked for the next reset,
and a later read materializes afresh instead of reusing a retired path. Identity
files *you* own — `SECRETS_AGE_IDENTITY_FILE`, an explicit `:identity-file`,
`~/.config/<app>/key.txt` — are never touched. It returns
`{:generation g :deleted n :absent n :failed n :pending n}`: successful
deletions, already-absent paths, retained failures, and newly deferred leases,
with no path, digest, or key content.

Deletion waits for the decryption using the file. `load-secrets` holds the
identity for the whole call — which covers the reader literals and the Aero
readers, since both load through it — so a reset that lands mid-decryption defers
to the last release rather than deleting a file `age` is still reading. A path
you took out of `resolve-identity-file` and use later is outside that lease;
wrap it in `(secrets/with-identity path (fn [p] …))` when you hand it to `age`
yourself. No API can hold a lease a caller never opened.

`deleteOnExit` stays registered, but only as the backstop for a process that
never calls the reset. **An abnormal exit — `SIGKILL`, a container OOM kill, a
hard crash — can still leave the file on disk** (CWE-459), and no deletion here
is secure erasure: on a journaling or copy-on-write filesystem the bytes can
outlive the unlink. So prefer not materializing at all where the platform
allows it. `SECRETS_AGE_IDENTITY_FILE` pointing at a secret file the platform
mounts (a Kubernetes `Secret` volume, systemd `LoadCredential`, a Docker/Fly
secret file) writes no key anywhere and is the better deployment shape wherever
it exists; failing that, a memory-backed temp directory
(`-Djava.io.tmpdir=/dev/shm`, a `tmpfs` mount) keeps a materialized identity out
of persistent storage.

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

Those are steps, not a whole job. The job around them wants the hardening in
[Verifying in CI](#verifying-in-ci): the identity on the consuming step only,
minimal `permissions:`, every action pinned to a commit SHA, and fork pull
requests kept out of the keyed path.

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

The initializer requires `--app`, defaults to `--env dev`, and accepts `-h` or
`--help` for its launcher-neutral usage and options. It supports these explicit
layouts:

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

Before applying anything, the initializer proves that no other principal can
tamper with the project root's ancestry: every directory from the filesystem
root down to and including the root itself is owned by you or by `root` and is
writable by nobody else. Other-write needs the sticky bit; group write needs the
sticky bit or a group whose name is the owner's, the user-private group of
Fedora, RHEL, and Debian, because a group holding nobody but the owner is not
another principal and a `umask 002` checkout at mode 0775 is exactly as safe as
one at 0755. Sticky means only an entry's own owner may rename or delete it,
which is why a root under `/tmp` is fine. The path as written is checked too, so
a symbolic link on the way in that someone else could repoint is refused even
when what it resolves to is private. Anything else is refused, naming the
offending directory, and a filesystem that cannot report POSIX ownership and
mode attributes is refused rather than assumed safe. This ancestry proof is what
replaces openat-style anchoring: Babashka cannot reach `SecureDirectoryStream`,
so instead of re-walking ancestors an attacker might have swapped, the
initializer establishes that nobody is able to swap them and refuses to write
when it cannot. Every mutation then re-verifies at the operation point —
directories are created with an explicit mode a umask can only narrow, never
widen, and checked one segment at a time under the verified root, each file is
staged with `O_CREAT|O_EXCL` under an unguessable name and published with an
atomic rename, and the rollback path uses those same checked operations. A
preview never needs the guarantee, because it writes nothing, but it reports
whether applying would be refused so you learn that before choosing to apply.

The four included consumers illustrate different needs rather than four copies
of one schema: quickstart, Aero, and team-CI carry CLI configuration in
`bb.edn`; the Integrant service uses JVM runtime wiring and a shell bootstrap.
The common CLI schema is only `:app`, `:default-environment`, and an environment
with `:secrets-file`. Template, manifest, and key paths derive from that minimum;
disposable and multi-recipient layouts make their exceptional paths explicit.

### Initializer preview output

The file most likely to be replaced is the consumer's own `bb.edn`, which may
already hold a credential. A preview therefore has three modes, and the safe
one is the default:

| Run | Printed |
| --- | --- |
| noninteractive, or `--apply` | every path and its action (create, merge, leave as is) plus the counts — no file bodies at all |
| interactive, no flag | the same summary, plus the changed region of each file only: redacted, escaped, and line-length bounded |
| `--show-contents` | complete old and new bodies, unredacted, behind a warning printed first |

`--show-contents` is the only route to complete contents. Neither `--apply` nor
a noninteractive run nor anything else implies it, and when both could apply the
safe mode wins: an interactive `--apply` run prints no bodies either. The
warning it prints says plainly that a credential already sitting in one of these
files is about to reach stdout.

Redaction in the interactive mode is a targeted guard, not a secret scanner:
three rules cover a value under a key named like a secret, an
`AGE-SECRET-KEY-1…` identity, and a long opaque token, each replaced by a marker
naming how many characters it hid. It over-redacts by design — a Git SHA and a
`:secrets-file` path go the same way as a real credential — and
`--show-contents` is how to read what a preview hid. Control characters,
`ESC` first among them, are rendered as printable escapes rather than emitted,
because a previewed file is untrusted input to the terminal: a crafted `bb.edn`
must not be able to repaint what the operator is deciding on.

The plan behind the preview keeps no file bodies it does not need. Existing
contents are read to detect a change and classify the action, then dropped;
`init!`'s status map carries `:actions` and `:trust` and no contents at all, so
a programmatic caller printing it discloses nothing either.

## Environments

Each environment is an independent encrypted file. By default they share one key
(`~/.config/<app>/key.txt`) — simplest for a solo project. Give an environment
its own `:key-file` to isolate it (e.g. so a dev key can't read prod). The same
resource name (`secrets.edn.age`) can live on each environment's own classpath,
so one set of reader literals serves every environment.

## Teams: multiple recipients

The default single-key model means everyone shares one private key. For a team,
point an environment at a **recipients file** — a committed list of age public
keys — and it encrypts to all of them. Each person decrypts with their own
private identity; private identities are never shared.

```clojure
;; bb.edn — add :recipients-file to an environment
{:prod {:secrets-file    "env/prod/resources/secrets.edn.age"
        :recipients-file "env/prod/recipients.txt"}}
```

Every command that encrypts reads and validates that list exactly once, up
front — before an editor opens, before stdin is read, before anything is
decrypted — and encrypts to those exact public keys. The recipients pathname is
never handed to `age`, so replacing, truncating, or restoring the file while
the command is still running cannot change who can decrypt what it writes.
Bounds and validation are applied to that one read: a file over
`:max-recipients-bytes`, more entries than `:max-recipients`, an entry over
`:max-recipient-chars`, a line that is not an age recipient, and an empty list
each fail the command before `age` starts. `bb secrets recipients` stays a
read-only listing and marks any line encryption would refuse.

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
{:version 2
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

`:version` is the manifest encoding version, and it is part of the `:vhash`
derivation, not just a label. Version 2 encodes a value as a recursively typed,
length-framed string: every scalar, collection, map key, and map value carries
its own type tag and its own length, so a `=` or `;` inside a value can't be
mistaken for structure and `[[1]]` doesn't encode like `[(1)]`. That string is
hashed as its raw UTF-16 code units rather than through a charset encoder, which
would fold distinct values together by substituting for unpaired surrogates.
Two different secret graphs therefore cannot share a `:vhash`. Version 1 did
neither, so it is rejected outright rather than reinterpreted: `verify` reports
an unsupported version as drift, and a v1 manifest must be regenerated with
`bb secrets reencrypt <env>`.

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

Placement matters in the keyed job. Give the identity to the one step that runs
`verify`, keep untrusted code out of that job, ask for the least permission that
can check the repository out, and pin every action to a commit:

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
    - run: sudo apt-get update && sudo apt-get install -y age
    - uses: turtlequeue/setup-babashka@d78ec6570aea3b614bc695cafcceb82eb45c2af9 # v1.8.0
      with: {babashka-version: 1.12.208}
    - run: bb secrets verify
      env:
        SECRETS_AGE_IDENTITY: ${{ secrets.SECRETS_AGE_IDENTITY }}
```

A job-level `env:` would hand that identity to checkout, the `apt-get` install,
and a third-party setup action, none of which needs a key; a tag in place of a
commit SHA would let upstream change what runs beside it. A fork's
`pull_request` receives no repository secrets, so the `if:` is not what stops a
leak today — it stops this from being edited into a `pull_request_target`
workflow that hands the key to unreviewed code. The keyless variant needs none
of the gating, because it holds nothing to take; the production chapter under
`book/chapters` works through both.

`verify` reads the manifest's `:version` and treats anything but 2 — including a
legacy v1 manifest — as drift, never as a shape to diff. Disable the manifest
for an environment with `:manifest false`.

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
and a readable version-2 manifest contains `:ciphertext-sha`; full verification
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

### What a failure carries

These exceptions are meant to be safe to hand to an error reporter, so their
context is an allowlist rather than a rendering. Every failure about a secrets
source carries `:source`: a local or rejected locator's scheme, host, port, and
path with **userinfo, query, and fragment dropped**; a File, Path, or path
string's path, which is yours already; or, for any rejected object, its class
name alone. Nothing calls `str` or `pr-str` on an arbitrary object you passed
in, because a `toString` you wrote is exactly how a credential-bearing object
leaks. A *path* can carry a token too, so keeping it is a judgement rather than
a safe default: a diagnostic that cannot name the failing resource is not one,
and that residual risk is real, not zero.

An identity path is named only when you supplied it. A path materialized from
`SECRETS_AGE_IDENTITY` / `SECRETS_AGE_IDENTITY_B64` appears in no message, no
`ex-data`, and no `bb secrets` output: you never saw that path, and it points at
key material. `age/decrypt`, `age/decrypt-bytes`, and `age/decrypt-to-file!`
therefore leave the identity path out unless the call passes
`{:identity-nameable? true}`; a wrong key still says so, with the captured
stderr and its hint.

An I/O failure's own message travels only with a filesystem path source, where
it can name nothing the failure does not already name. A local locator failure
keeps the exception's class instead of its message and does not attach it as a
cause — printing an exception prints its causes' messages too. A rejected
source has no I/O cause because policy runs before opening. Aero failures name
the `:profile` and the opts map's *key names*, never a value: an
opts map can hold a resolver, a database password, or a whole configuration. A
bound that trips carries the byte count and the limit, never content.

## API

`com.kirahowe.secrets`
- `(load-secrets source)` / `(load-secrets source identity-or-opts)` — decrypt + read an EDN map. `source` is local-only: a filesystem path string, File, Path, local `file:` locator, or `jar:file:` classpath resource; the second arg is an identity path String/File or an opts map `{:identity-file … :app …}`. Every failure throws `ex-info` with a `:reason`: `:no-identity`, `:no-file`, or `:disallowed-source` for anything outside the provenance contract. No HTTP operation exists and no DNS, connection, redirect, or response read occurs for a rejected locator. Every failure about the source also carries `:source`, allowlisted metadata naming which source failed and never the source value — see *What a failure carries*.
- `(get-secret m key-path)` / `(get-secret m key-path default)` — keyword or vector path.
- `(reader-literals opts)` → `{'secret/req … 'secret/opt …}`; `(merge-readers readers opts)`.
- `(identity-from-env)` — identity path from `SECRETS_AGE_IDENTITY_FILE` / `SECRETS_AGE_IDENTITY` / `SECRETS_AGE_IDENTITY_B64`, or nil when none is set. A variable that is set but empty throws.
- `(resolve-identity-file)` / `(resolve-identity-file app-or-opts)` — the env vars first, then `~/.config/<app>/key.txt` when an app name is known; nil otherwise. The path is *conventional* — it's never checked for existence, so a non-nil result doesn't mean a usable key is actually there.
- `(identity-available?)` / `(identity-available? app-or-opts)` — true when an identity actually resolves **and** its file exists on disk. The "do I have a key, or should I tell the user to run `keygen`?" check; `app-or-opts` also accepts an opts map's `:identity-file`.
- `(reset-identity-cache!)` — retire every identity temp file materialized from `SECRETS_AGE_IDENTITY` / `SECRETS_AGE_IDENTITY_B64`: check deletion of each one no decryption is using, defer the rest to their last release, retain failures for retry, and materialize afresh on the next read. Idempotent; never touches an identity file you own. Returns path-free `{:generation g :deleted n :absent n :failed n :pending n}` outcome counts.
- `(with-identity path f)` — call `(f path)` with `path` held against `reset-identity-cache!` for exactly that call. `load-secrets` already does this for its own decryption; use it when you hand a resolved path to `age` yourself.
- `(owner-only-temp-file! prefix suffix)` — a delete-on-exit temp file that is 0600 from the moment it exists.
- `(expand-home path)`.

`com.kirahowe.secrets.age` — `version`, `installed?`, `public-key`, `valid-recipient?`, `keygen!`, `encrypt-file!` (to an identity file, a `:recipients-file`, or a `:recipients` list — a bare String/File always means an identity-file *path*; bare `age1…` public-key strings throw, pass them as `{:recipients […]}`), `decrypt` (UTF-8 string), `decrypt-bytes` (byte array, binary-safe), `decrypt-to-file!` (byte-for-byte). The positional input is passed behind an option terminator (`--`), and every path-valued argument — that input, the `-o` output, the `-i` identity, the `-R` recipients file — is normalized so a dash-leading path becomes `./-name`, so filenames beginning with `-` (including names identical to age options) work like any other file; a blank or nil path throws `ex-info` instead of falling back to stdin. `:recipients` strings are recipient *values*, not paths, and are passed through as given. `decrypt-to-file!` publishes plaintext only through an owner-only (0600) sibling staging file that is then atomically moved over the destination: the published file is 0600 whatever the umask and whatever mode the destination had before, the destination's final component is validated without following links so a symlink or other non-regular destination is refused, and a decryption, write, or move failure removes the staging plaintext and leaves the previous destination intact. On a filesystem without POSIX permissions it fails closed rather than writing plaintext with default permissions — use `decrypt-bytes` or `decrypt`, which never write plaintext to disk.

`com.kirahowe.secrets.manifest` — pure manifest helpers: `entries`, `(render {:app … :ciphertext-sha …} entries)`, `diff`, `value-type`, `hmac-key`.

`com.kirahowe.secrets.cli` — `(run! config args)` and the individual command fns. The command fns are a REPL-safe API: they return data (paths, result maps, `:aborted` from a declined overwrite prompt) and throw `ex-info` on failure — only `run!` prints error data and exits. `(verify! config env)` returns `{:results {env status} :exit code}`; `(doctor! config env)` safely normalizes one raw selected/default environment and returns its structured age, artifact, identity-source, recipient, and verification-capability fields plus `:status` and `:exit`. Config keys: `:app`, `:default-environment`, `:environments {env {:secrets-file … :key-file … :identity-file … :template … :manifest … :recipients-file …}}` — validated on load (`:app` and `:secrets-file` required, no blank path strings, `.age` extension unless both `:template` and `:manifest` are explicit), and each environment's decrypt-side identity resolves from the `SECRETS_AGE_IDENTITY*` env vars before an explicit `:identity-file`, then falls back to its configured/default `:key-file`.

`com.kirahowe.secrets.init` — Babashka-only project bootstrap entrypoint.
`(-main & args)` parses `--app`, optional `--env`, `--layout`, `--team`,
`--keygen`, `--apply`, and `--show-contents`; `(init! opts)` exposes the
preview/apply operation for programmatic use, returning a status map that
carries the `:trust` report the preview printed and `:actions`, one path and
action per proposed file, and deliberately no file contents. It preserves
`bb.edn` formatting with Babashka's bundled `rewrite-clj`, refuses conflicts and
unsafe paths, prints paths and actions rather than file bodies unless
`--show-contents` explicitly asks for them, and refuses to mutate a project at
all unless `(trusted-ancestry! root)` proves the root's ancestry untamperable
and `(filesystem-capability)` reports the POSIX attributes that proof needs.

## Examples

See the [examples guide](examples/README.md) for a choice matrix and runnable
starters: [quickstart-bb](examples/quickstart-bb/README.md),
[integrant-service](examples/integrant-service/README.md),
[aero-profiles](examples/aero-profiles/README.md), and
[team-ci](examples/team-ci/README.md).

## Development

Project Clojure code follows a 100-column policy. Book files under `book/chapters`
are exempt so prose can use editor soft wrapping; other lint checks still apply.
Tests require `age` and a JDK.

```sh
bb format          # format Clojure source with cljfmt
bb format:check    # check formatting without changing files
bb lint            # lint Clojure source with clj-kondo
bb test            # run the suite under Babashka
clojure -M:test    # run the suite under JVM Clojure
```

Both runners include the property-based suites, the `*_property_test.clj`
files under `test/`. They use test.check to generate inputs for the pure parts
of the library: the EDN boundary, the manifest, the CLI's argument and quoting
helpers, and the initializer's rendering and merging. A failing property prints
the seed and the smallest failing input it found. To replay one, call the spec
as a function with that seed, for example
`(parse-reads-back-every-printable-value 200 :seed 1234)`.

Other development tasks:

```sh
bb secrets help            # demo the CLI against a throwaway tmp/ file
clojure -T:build install   # build + install the jar to ~/.m2 (needs a JDK)
```

### Continuous integration

CI runs the Babashka and JVM suites, builds and inspects the jar, renders the
book, and deploys it to Pages from `main`. Every executable dependency it runs
is immutable: each `uses:` is a full commit SHA with the version that commit is
recorded beside it, and the Babashka container is an `@sha256:` digest whose
release tag survives only as a comment. A tag or registry reference that moves
upstream therefore cannot change what a build executes without a reviewed diff
here — which matters most for the Pages deployment, the only job holding
`pages: write` and `id-token: write`, gated on `main` and on the protected
`github-pages` environment. Every other job runs with the workflow's top-level
`contents: read`.

`com.kirahowe.secrets.workflow-policy`, under `build/`, is what decides that,
and `bb test` runs it over every `.github/workflows/*.yml` it discovers rather
than a list of names, so a workflow added later is covered without anyone
extending the test. It refuses a tag, a branch, a short SHA, a reference form it
has no pinning rule for, an image without a digest, and a bare SHA carrying no
version comment — a pin nobody can review is not a pin. Dependabot proposes the
upgrades weekly, bumping the SHA and rewriting the comment beside it, so staying
current is a reviewable diff rather than tag drift.

### The documentation book

Full documentation lives in a [Quarto](https://quarto.org) book under
`book/chapters` — quick start, design rationale, runtime/CLI/teams/manifest
guides, production & CI, caveats, and a generated API reference. Chapters are
literate Clojure namespaces rendered with [Clay](https://scicloj.github.io/clay/),
so every example is evaluated against the real library at build time.

```sh
bb book:build     # render the book into book/rendered (needs JDK + quarto + age)
bb book:preview   # serve the rendered book locally
bb book:watch     # re-render a chapter when you save it, and reload it in the browser
```

The published book carries no third-party executable assets. Clay injects jQuery
and jQuery UI into every page and this book calls neither, so `bb book:build`
strips them — an unused dependency is removed rather than vendored — along with
the Google Fonts stylesheet Quarto's Bootstrap theme imports, and Quarto's build
cache. Each page then gets a `<meta>` Content Security Policy: `default-src
'self'`, and a `script-src` that admits its own inline scripts and event
handlers by SHA-256 hash, computed at build time from the exact bytes Quarto
generated, never by `'unsafe-inline'` and never with `'unsafe-eval'`.
`com.kirahowe.secrets.site-policy`, under `build/`, performs both the rewrite and
the check, and `bb book:build` fails on any finding — an external script or
stylesheet URL, an inline script no hash admits, an inline or eval allowance, a
page without a policy — so a render cannot produce an artifact CI would reject.

## Releasing

A release is built once, from the tag, and the bytes that were inspected are the
bytes that get published.

1. Write the `CHANGELOG.md` entry under a `## [<version>]` heading and commit it.
   The version lives in exactly one place, `src/com/kirahowe/secrets/coordinate.edn`,
   beside the Maven coordinate and the git tag the initializer scaffolds. The
   release guards read that file from the repository and the initializer reads
   it as a classpath resource, and the tag, jar name, pom, embedded
   `pom.properties`, CHANGELOG heading, and the coordinates this README shows
   are all checked against it rather than maintained beside it.
2. Tag that commit `v<version>` and push the tag.
3. The `release` workflow takes over: it is restricted to the protected
   `release` GitHub environment, builds from the tag, inspects the artifact, and
   uploads it. The Clojars credentials are visible only to its final deploy
   step; checkout, build, and inspection never have them in their environment.

The same flow by hand, when a release has to be cut locally:

```sh
clojure -T:build release   # guarded build, writes target/release.edn
bash .github/scripts/inspect-jar.sh target/secrets-0.1.0.jar
clojure -M:deploy          # uploads exactly the files named in the receipt
```

`release` refuses a working tree with modified *or untracked* files, a `HEAD`
that is not exactly the tag naming the declared version (a descendant of the tag
is a refusal, not a pass), a version the CHANGELOG does not document, and a
scaffolded git pin whose tag does not name the commit it records. It
then exports the tag with `git worktree` and builds from that snapshot, so
nothing that changes after the guards pass can reach the jar. The artifact must
name the version in its file name, in both embedded Maven descriptors, and as
the `<scm><tag>` it was built from — a release that claims no provenance is
refused — and `target/release.edn` records the jar, the pom that ships beside
it, the commit, and the jar's SHA-256.

`clojure -M:deploy` builds nothing. It re-reads that receipt, re-checks the
version, tag, commit, and embedded metadata, recomputes the digest, confirms the
pom it is about to publish is byte-identical to the one inside that jar, and
uploads exactly those two files. A jar or pom changed after inspection, a
missing receipt, or a `HEAD` that has moved off the tag each fail before any
credential is used, and so does a `CLOJARS_USERNAME` or `CLOJARS_PASSWORD` that
is missing *or* set but blank — in CI a misnamed secret expands to the empty
string, which means a broken release environment, not an anonymous upload.

The upload is a separate alias rather than a build task because it is the only
step that holds a credential. `:deploy` *replaces* `:deps` and `:paths` instead
of extending them, so the JVM holding the Clojars token carries
`com.kirahowe.secrets.publish`, the release guards beside it, and Maven's own
deploy code — 25 jars, no `tools.build`, no library source, no test
dependencies. Clojars is a plain Maven repository over HTTPS, so the upload goes
through `maven-resolver` directly and resolves no wagon and none of the S3, AWS,
logging, or serialization branches a wagon-based publisher brings with it. Every
dependency on that classpath has a recorded dependency path and disposition in
[doc/release-dependency-review.md](doc/release-dependency-review.md), and three
tests fail the suite if the resolved graph drifts from it. A deploy prints three
SLF4J "NOP logger" lines to stderr: no logging binding is on that classpath, by
choice.

The Clojars **deploy token** is the only credential a release needs. Scope it to
deployment of `com.kirahowe/secrets` and nothing else, inject it into the deploy
step's environment alone — never job-wide, so checkout, build, and inspection
cannot read it — and rotate it in Clojars, and in the `release` environment's
secrets, if it is ever exposed or if the machine that held it is in doubt. The
publisher never prints either credential: publication output is the coordinate,
version, tag, jar path, SHA-256, and the fixed
`https://repo.clojars.org` repository URL. The production entry point accepts no
repository override: every argument and every nonblank value of the retired
`SECRETS_DEPLOY_REPOSITORY_URL` input is rejected before credentials are read or
network I/O can begin. The authenticated local-recorder test calls the
lower-level `deploy!` seam directly with its HTTP URL and fixture credentials;
those test-only values cannot change production target selection.

`clojure -T:build jar` is a development build from the live working tree: it
makes no provenance claim (its pom carries no `<scm><tag>`) and is not
publishable. `clojure -T:build install` installs that same development jar into
`~/.m2`.

## Authenticity contract and threat model

age encrypts *to* recipients; it does not sign. This project accepts that
deliberately: **the reviewed repository and the deployment channel are the
sender-authenticity boundary.** The alternative — a detached signature over
every ciphertext — needs a second key that is separately provisioned,
distributed, rotated, and trusted, a signing step in every write path, and a
sidecar artifact to carry the signature. That is an entire second key
infrastructure, which is the thing "no GPG keyrings, no KMS, no vault to run"
exists to avoid. The channel is therefore the chosen model, and this section
states it in full rather than leaving it implied by a caveat.

### Four properties, kept apart

- **Confidentiality — age provides it.** Only a holder of a private identity
  matching one of the file's recipients can decrypt `secrets.edn.age`. A reader
  with the repository and no identity learns the manifest's shape (key names,
  types, collection sizes) and nothing else.
- **Ciphertext integrity — age provides it.** age is authenticated encryption:
  a modified, truncated, or spliced ciphertext fails to decrypt rather than
  yielding altered plaintext. That is integrity *of the payload against
  corruption and splicing*. It establishes that the bytes are intact and were
  produced by *someone* holding a recipient; it is not evidence of *who*
  produced them.
- **Sender authenticity — age does not provide it, and neither does this
  library.** A public recipient (`age1…`) is meant to be shared and committed;
  it permits *encryption* and is not a signing key. Anyone holding one can
  author a ciphertext that decrypts cleanly for every recipient. A successful
  decryption proves *readability*, never *authorship*.
- **Repository trust — you provide it.** This is a requirement on the operator,
  not a property of the tool. The values a process loads are exactly as
  trustworthy as the commit that carried the ciphertext and the channel that
  delivered it, and no more.

### Threat model

- **Who may hold a public recipient: anyone.** `recipients.txt` is committed in
  the clear and `bb secrets show-key` prints public keys precisely so they can
  be shared. Treat every public recipient as known to every reader of the
  repository — for a public repository, to everyone. This is by design: an
  unpublished recipient is not a control, and this project does not offer it as
  one.
- **Who may replace a deployed artifact: whoever can write the repository or
  the deployment channel.** That is anyone who can land a commit on the ref a
  deploy builds from, anyone who can write the image, bundle, or bucket the
  ciphertext travels in, and anyone who can write the filesystem the running
  process reads it from.
- **Trusted computing base:** the reviewers and ref protection of the
  repository, the CI/CD identity that builds and ships the artifact, the
  transfer between the reviewed commit and the running process, and the host
  that decrypts. Compromise any one of them and the loaded configuration is
  attacker-chosen. Hold all of them and it is what was reviewed.

### What an attacker with a public recipient and write access can do

The attacker here holds a public recipient (freely available) and can replace
the ciphertext the application reads. In *both* modes they can author a payload
that decrypts cleanly — that is the property age does not offer. The modes
differ in whether the committed manifest exposes it, and the difference is the
substance of this section.

- **Single-key mode — the manifest exposes a changed value.** Manifest entries
  carry a `:vhash`, an HMAC keyed by material derived from the *private*
  identity. The attacker cannot recompute one, so a forged ciphertext plus a
  refreshed `:ciphertext-sha` fails a full `bb secrets verify`: the entry is
  reported as changed. `public-recipient-forgery-fails-verification-test` pins
  this. It is still drift detection that happens to catch a forgery, not
  authentication — it works only because the attacker lacks a key, and only a
  *keyed* `verify` run sees it.
- **Multi-recipient (team) mode — the manifest exposes nothing.** A team has no
  shared private key, so there is no HMAC key and team manifests are
  structure-only. The attacker can encrypt a chosen payload to the committed
  recipient list, regenerate the manifest from it (the generator is pure and
  needs no key), and refresh `:ciphertext-sha`. If the payload keeps the same
  key paths and types, the regenerated manifest is byte-identical apart from
  that one hash, and a full `verify` run by a legitimate teammate passes.
  `team-mode-manifest-is-not-a-value-integrity-signal-test` pins this as a
  known, documented boundary; if it ever starts failing, this section is what
  needs updating.

Neither case is a defect in age, and neither is a check the manifest was ever
meant to be: the manifest is a review aid, not an authorization decision. What
both cases share is that the forgery *must modify committed artifacts* — the
ciphertext and the manifest are tracked files — which is what makes it
reviewable, and is why the boundary is placed on the repository.

### What the model requires of a deployment

Accepting the channel is only honest if the channel is actually held. Three
requirements, in the order they bite:

1. **Reviewed, protected refs.** The artifact is only as trustworthy as the
   commit that carried it, so require review and protect the branches and tags
   a deploy builds from. An unreviewed push to that ref is an unreviewed change
   to production configuration.
2. **Immutable artifact transfer.** Nothing between the reviewed commit and the
   running process may be able to substitute the ciphertext: build from the
   protected ref, address every intermediate artifact and dependency by digest
   rather than by a movable tag, and check the bytes you ship are the bytes you
   inspected.
3. **Least-privilege writes.** Whatever serves the ciphertext — repository,
   registry, bucket, mounted volume — grants write access to as few principals
   and as few build steps as the deployment can function with, since each one
   is a party that can choose your configuration.

This repository holds itself to that, and the controls are worth copying:

- **Releases are gated on an environment, not on a ref alone.** A workflow has
  no trustworthy view of tag protection, so the protected `release`
  environment — its required reviewers and its tag restriction — decides
  whether the job runs at all, and it holds the only copy of the Clojars
  credentials. The build takes the pushed `v*` tag rather than the working
  tree, and only the final deploy step has the credential in its environment;
  checkout, build, and inspection never do. `clojure -M:deploy` re-checks the
  receipt and uploads exactly the inspected bytes (see
  [Releasing](#releasing)).
- **CI executes nothing mutable.** Every `uses:` is a full commit SHA and the
  Babashka container is an `@sha256:` digest, and
  `com.kirahowe.secrets.workflow-policy` fails `bb test` on any workflow that
  drifts from that — a tag moving upstream cannot change what a build runs
  without a reviewed diff (see [Continuous
  integration](#continuous-integration)).
- **Privilege is step- and job-scoped.** The only job holding `pages: write`
  and `id-token: write` is the Pages deployment, gated on `main` and the
  protected `github-pages` environment; every other job runs with the
  workflow's top-level `contents: read`. The keyed `verify` recipe this project
  ships does the same for an age identity: `SECRETS_AGE_IDENTITY` is declared
  on the one step that runs `verify`, and the job gates on the pull request
  coming from the repository rather than a fork, so no third-party action ever
  shares an environment with the key (see [Verifying in
  CI](#verifying-in-ci)).

### Failure behaviour

There is no signature in this model, so "missing", "invalid", or "replayed"
*authorization evidence* mostly has nothing to refer to — stated here rather
than left looking like an unimplemented check. What does exist is `verify`'s
drift reporting, and it fails closed:

- **Missing evidence** — no ciphertext, no manifest, or a manifest with no
  `:ciphertext-sha` and no identity to fall back on: `verify` exits 2. It never
  reports a pass it could not establish.
- **Invalid evidence** — a manifest that is not EDN, or whose `:version` is
  anything but 2 (including a legacy v1 manifest): drift, exit 1, never diffed
  as a shape.
- **Replay** — no signature and no nonce, so a replayed ciphertext is visible
  only where it disagrees with the committed manifest (`:ciphertext-sha`, plus
  the `:vhash`es in single-key mode). Rolling the ciphertext *and* its manifest
  back to an earlier committed pair is a repository change, and the repository
  is the boundary.
- **Wrong app** — the manifest records `:app`, and `verify` refuses a manifest
  whose `:app` is not this project's, or that records none, as drift rather than
  diffing it as a shape. This matters most in team mode: with no `:vhash`es to
  disagree, a foreign structure-only manifest with a refreshed
  `:ciphertext-sha` would otherwise verify clean.
- **Wrong environment** — environments are separate files at separately
  configured paths, so a "wrong environment" is a misconfigured path, which
  `bb secrets doctor` reports per environment. No ciphertext is
  cryptographically bound to an environment name.

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
  The full statement of what age does and does not give, the threat model, and
  what the accepted channel requires of a deployment are in [Authenticity
  contract and threat model](#authenticity-contract-and-threat-model).
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
  In team mode the manifest is therefore not a value-integrity signal at all —
  see [Authenticity contract and threat
  model](#authenticity-contract-and-threat-model).
- **Where it fits.** A solo developer or small team shipping a handful of apps
  with no secrets infrastructure. If you need dynamic secrets, centralized
  audit, fine-grained IAM, or automatic rotation, a dedicated secrets manager
  (Vault, a cloud KMS / secret manager) earns its extra complexity.

## Security notes

Report a suspected vulnerability through the private route in the
[security policy](SECURITY.md), not a public issue. Never put sensitive report
details, real secrets or user data, proof-of-concept payloads, or unpatched
exploit instructions in a public issue.

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
  creation — the library targets POSIX systems. An injected identity is deleted
  by `reset-identity-cache!` rather than only at JVM exit; see [the temp file
  `SECRETS_AGE_IDENTITY` writes](#the-temp-file-secrets_age_identity-writes) for
  what an abnormal exit still leaves behind.
- **Decrypted plaintext files are published 0600, never written in place.**
  `decrypt-to-file!` writes into an owner-only sibling staging file and then
  atomically renames it over the destination, so the result does not depend on
  the umask or on the destination's previous mode and no permissive or partial
  plaintext is ever observable there. A destination that is a symlink,
  directory, or other non-regular file is refused rather than written through,
  and a filesystem without POSIX permissions fails closed — decrypt in memory
  with `decrypt-bytes` / `decrypt` instead.
- **Pathnames reaching `age` are data, never options.** Encryption and
  decryption shell out to the `age` binary, so a path that arrived on its
  command line as an option would let a filename choose the operation instead of
  naming the file it operates on. Every invocation that takes an input pathname
  therefore terminates its options with `--` before it, and every path argument
  that starts with a dash is passed as `./-name` — age reads a bare `-` from
  standard input even behind a terminator, so the prefix is the part that keeps
  a filename a filename.
- **A filename cannot change how the CLI parses its own arguments either.**
  `--edn` is `set`'s flag, so only `set`'s arguments are searched for it; every
  other command reads a `--edn` operand as the filename or key it is. `--` ends
  the options for every command and is consumed rather than passed on, so
  `bb secrets encrypt dev -- --edn` encrypts the file. `[env]` stays positional
  and optional throughout.

## License

MIT © 2026 Kira Howe. See [LICENSE](LICENSE).
