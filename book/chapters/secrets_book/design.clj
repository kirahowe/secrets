;; # Design and rationale

^{:kindly/hide-code true}
(ns secrets-book.design
  (:require [clojure.edn :as edn]
            [clojure.string :as str]))

;; This chapter explains why the library works the way it does. None of the
;; ideas in it are new. The interesting part is which ideas it borrows, and
;; which it refuses.

;; ## The problem with environment variables

;; Env vars are where most apps start, and they have three problems that get
;; worse over time.

;; They sprawl. Every integration adds another variable, and after two years
;; nobody can say what the app actually needs to boot. The repo does not know;
;; the deploy platform's web UI does, which means your configuration's source
;; of truth is mutable state behind someone's login.

;; They are untyped. An env var is a string, so a list of admin emails becomes
;; a comma-separated string and a parser you now maintain. Compare the two
;; directly. The env var version:

(str/split "kira@example.com,sam@example.com" #",")

;; The EDN version:

(edn/read-string "#{\"kira@example.com\" \"sam@example.com\"}")

;; One of these is a vector of strings that happens to look like a set, built
;; by code that will mishandle a space after a comma someday. The other is a
;; set. When your secrets file is EDN, every value is real data: nested maps
;; for a service's settings, keywords for modes, numbers that are numbers.

;; They have no history. When a deploy breaks because a var changed, there is
;; no diff to read, no commit message, no way to bisect. Someone changed
;; something in a dashboard.

;; ## The model

;; The library commits the secrets to git, encrypted:

;; ```
;; secrets.edn        plaintext, never committed, exists only during edits
;;      |  age -e -i key.txt
;;      v
;; secrets.edn.age    ciphertext, committed
;;      |  age -d -i key.txt
;;      v
;; {:database/url "..." :auth/admins #{...}}    a plain Clojure map, in memory
;; ```

;; Now the repo is the source of truth. Adding a secret is a commit. Removing
;; one is a commit. Reviewing a change is a pull request. The only thing that
;; lives outside git is one private key, and the whole design hangs on keeping
;; that one small thing safe, which is a much easier problem than keeping
;; forty env vars coherent.

;; ## Why age

;; [age](https://age-encryption.org) is a file encryption tool by Filippo
;; Valsorda with a short spec, modern primitives (X25519, ChaCha20-Poly1305),
;; and no configuration. A key is two lines of text. There is no keyring, no
;; trust database, no expiry ceremony, none of the GPG surface area that makes
;; teams give up on encrypted files.

;; Two properties matter for this library. First, an identity file can both
;; encrypt and decrypt, so a solo developer needs exactly one file. Second,
;; age natively encrypts to multiple recipients, which is the entire
;; [team story](secrets_book.teams.html): a committed list of public keys,
;; each person decrypting with their own private one.

;; The library shells out to the `age` binary rather than reimplementing the
;; format. That is a real trade-off (your production image needs the binary),
;; but it means the cryptography in your secrets pipeline is the audited tool
;; itself, not a port of it.

;; ## Why one file per environment

;; A single EDN map per environment keeps the mental model flat: prod has a
;; file, dev has a file, each encrypts on its own, and each can have its own
;; key. There is no overlay algebra and no partial sharing. When the whole
;; file decrypts in one motion, you always know exactly what the app sees.

;; The cost is coarseness, and it is deliberate. Per-secret granularity is
;; what SOPS does, and it buys reviewable values at the price of a much more
;; complicated tool. This library takes the other branch and then patches the
;; one real casualty, reviewability, with the
;; [manifest](secrets_book.manifest.html).

;; ## Prior art, and what got borrowed

;; The model is not experimental. Rails has shipped it as a framework default
;; since 5.2: an encrypted credentials file in the repo, one master key
;; outside it. Years of production use across a very large community is the
;; strongest evidence this shape holds up.

;; | Tool | Granularity | Keys | What it taught this library |
;; |------|-------------|------|------------------------------|
;; | Rails credentials | whole file | one master key | the core model works |
;; | SOPS | per value | KMS, age, GPG | reviewable diffs matter |
;; | git-crypt | whole file, transparent | GPG | transparency hides too much |
;; | Vault | per secret, dynamic | server-side | some needs deserve a server |

;; From SOPS it takes the lesson that an opaque diff is a real cost, and
;; answers with the manifest instead of per-value encryption. From git-crypt
;; it takes a warning: when encryption is invisible, people forget it is
;; there, so this library keeps encryption explicit. You run `bb secrets
;; edit`; nothing happens behind your back.

;; ## What it refuses to be

;; There is no server, no daemon, no cloud account, and no rotation scheduler.
;; A secrets manager like Vault earns its complexity when you need dynamic
;; database credentials, fine-grained access policy, or a central audit log.
;; Most small apps need none of that, and the operational weight of running a
;; secrets server dwarfs the problem it solves for them. The
;; [caveats chapter](secrets_book.caveats.html) draws the line precisely, so
;; you can tell when you have outgrown this tool.

;; ## The EDN choice

;; The file is EDN and reads with `clojure.edn`, never `eval`. This is worth a
;; sentence of paranoia: the secrets file is data, and even a malicious one
;; cannot execute code at load time. Sets, maps, keywords, and comments all
;; work, and your secrets file can document itself:

;; ```clojure
;; {;; Rotated 2026-06-01, next rotation due September.
;;  :stripe/api-key "sk_live_..."
;;
;;  ;; People who can access /admin. Yes, a set.
;;  :auth/admins #{"kira@example.com"}}
;; ```

;; Comments survive `bb secrets edit` round trips, because the CLI re-encrypts
;; the text you saved, not a re-serialization of it.
