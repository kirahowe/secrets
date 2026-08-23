;; # Design and rationale

^:kindly/hide-code
(ns secrets-book.design
  (:require [clojure.edn :as edn]
            [clojure.string :as str]))

;; This chapter explains the main design choices and their trade-offs.

;; ## The problem with environment variables

;; Environment variables are a common starting point, but they have limits.

;; Each integration adds more variables, while the repository may contain no
;; complete list of what the application needs. The active configuration then
;; lives in deployment settings rather than beside the code.

;; They are untyped. An env var is a string, so a list of admin emails becomes
;; a comma-separated string and a parser you now maintain. Compare the two
;; directly. The env var version:

(str/split "kira@example.com,sam@example.com" #",")

;; The EDN version:

(edn/read-string "#{\"kira@example.com\" \"sam@example.com\"}")

;; The first result is a vector and requires the application to define parsing
;; rules. The second is a set. EDN also represents nested maps, keywords, and
;; numbers without application-specific string parsing.

;; Git does not record changes made in a deployment dashboard. A platform may
;; have its own audit history, but it is separate from the code change that
;; consumes the secret.

;; ## The model

;; The library commits the secrets to git, encrypted:

;; ```
;; secrets.edn        temporary plaintext during management operations
;;      |  age -e -i key.txt
;;      v
;; secrets.edn.age    ciphertext, committed
;;      |  age -d -i key.txt
;;      v
;; {:database/url "..." :auth/admins #{...}}    a plain Clojure map, in memory
;; ```

;; The repository now records additions and removals. Private identities stay
;; outside git: one shared identity in the basic setup, or one per recipient in
;; team mode.

;; ## Why age

;; [age](https://age-encryption.org) is a file encryption tool with small text
;; keys and support for X25519 and SSH recipients. It does not require a
;; keyring or trust database.

;; Two properties matter here. An identity file can select its own recipient
;; for encryption and can decrypt the result, so the single-key setup needs one
;; file. Age can also encrypt to multiple recipients; the
;; [teams chapter](secrets_book.teams.html) uses a committed list of public keys
;; while each person retains a separate private identity.

;; The library shells out to the upstream `age` binary rather than implementing
;; the format. Every environment that decrypts therefore needs that binary.

;; ## Why one file per environment

;; Each environment has one EDN map and one ciphertext. Environments share the
;; app's default key unless a `:key-file` override separates them. There are no
;; overlays or partially shared files, so the decrypted map is the complete
;; value the application receives.

;; The trade-off is coarse access: an identity opens the entire file. SOPS
;; encrypts individual values, which makes encrypted diffs field-specific.
;; This library keeps whole-file encryption and adds a
;; [manifest](secrets_book.manifest.html) that records structural changes.

;; ## Prior art, and what got borrowed

;; Rails 5.2 also uses an encrypted credentials file in the repository and a
;; master key outside it. Other tools make different choices about granularity
;; and key management:

;; | Tool | Granularity | Key model | Relevant design choice |
;; |------|-------------|-----------|------------------------|
;; | Rails credentials | whole file | master key outside git | encrypted file committed with the app |
;; | SOPS | per value | KMS, age, or PGP | document keys stay visible; leaf values are encrypted |
;; | git-crypt | whole file | GPG or symmetric key | encryption runs through git filters |
;; | Vault | per secret, dynamic | server-side | central policy, audit, and dynamic credentials |

;; SOPS keeps document keys visible and encrypts leaf values, so a diff shows
;; which encrypted field changed. This library uses a separate manifest for
;; that information. Git-crypt applies encryption through git filters; this
;; library instead uses explicit `bb secrets` commands.

;; ## Scope

;; There is no server, daemon, cloud account, or rotation scheduler. Use a
;; secrets manager when you need dynamic credentials, fine-grained access
;; policy, or a central audit log. The [caveats chapter](secrets_book.caveats.html)
;; describes those limits.

;; ## The EDN choice

;; The file is read with `clojure.edn`, not `eval`, so reading it does not
;; execute Clojure forms. Sets, maps, keywords, and comments are supported:

;; ```clojure
;; {;; Rotated 2026-06-01, next rotation due September.
;;  :stripe/api-key "sk_live_..."
;;
;;  ;; People who can access /admin. Yes, a set.
;;  :auth/admins #{"kira@example.com"}}
;; ```

;; Comments survive `bb secrets edit` round trips, because the CLI re-encrypts
;; the text you saved, not a re-serialization of it.
