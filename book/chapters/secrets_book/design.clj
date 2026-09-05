;; # Design and rationale

^:kindly/hide-code
(ns secrets-book.design
  (:require [clojure.edn :as edn]
            [clojure.string :as str]))

;; There are many perfectly reasonable ways to manage secrets. This library is
;; opinionated about a few of them, so it is worth being clear about the model
;; and the trade-offs before getting too attached to it.

;; ## The problem with environment variables

;; Environment variables are a perfectly good place to start. The
;; [Twelve-Factor App](https://12factor.net/config) makes the case for keeping
;; configuration out of code, since "config varies substantially across
;; deploys, code does not", and prescribes environment variables as the
;; mechanism. This library keeps the separation and replaces the mechanism.
;; The trouble is that most applications do not stop at three variables.

;; Each integration adds a few more variables, while the repository may contain
;; no complete list of what the application actually needs. Before long the
;; active configuration lives in a deployment dashboard rather than beside the
;; code that consumes it.

;; They are untyped. An env var is a string, so a list of admin emails becomes
;; a comma-separated string and a parser you now maintain. Compare the two
;; directly. The env var version:

(str/split "kira@example.com,sam@example.com" #",")

;; The EDN version:

(edn/read-string "#{\"kira@example.com\" \"sam@example.com\"}")

;; The first result is a vector and still requires the application to decide
;; what commas, blanks, and whitespace mean. The second is already a set. EDN
;; also gives us nested maps, keywords, numbers, and booleans without inventing
;; a tiny string format for each setting.

;; Git does not record changes made in a deployment dashboard. A platform may
;; have its own audit history, but it is separate from the code change that
;; consumes the secret. Twelve-Factor's own
;; [build, release, run](https://12factor.net/build-release-run) factor makes
;; the same point from the other side: a release is a build combined with its
;; configuration, uniquely identified, and immutable once created. The code
;; alone does not describe what was deployed. Configuration is half of the
;; release, and when it lives in a dashboard, half of the release has no
;; history.

;; ## Configuration belongs in version control

;; The positive case is older than this library. *Continuous Delivery* treats
;; [configuration management](https://continuousdelivery.com/foundations/configuration-management/) as a foundation: version control
;; everything required to build, test, and deploy, "including source code,
;; test and deployment scripts, infrastructure and application configuration
;; information". It names two goals. Reproducibility: "we should be able to
;; provision any environment in a fully automated fashion, and know that any
;; new environment reproduced from the same configuration is identical."
;; Traceability: for any environment, determine precisely what went into it,
;; and compare it with a previous version to see what changed.

;; In an [interview about the book](https://www.infoq.com/articles/humble-farley-continuous-delivery/), Jez Humble puts the rule bluntly:
;; "everything that is required to build, test and deploy your system should
;; be in version control. It should be possible to plug in a new workstation,
;; and check out everything you need to build, test and deploy your system to
;; any environment." David Farley describes the deployment side: when
;; deployments are tied to version-controlled release numbers, the record of
;; which version went to which environment, and who approved it, is an audit
;; trail.

;; Secrets are the part of application configuration that this discipline
;; usually stops short of, because committing them in the clear is
;; unacceptable. Encrypting them is what lets them in. A checkout plus one
;; identity reproduces an environment's configuration, and the
;; [manifest](secrets_book.manifest.html) makes each change to it traceable.

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

;; The repository now records the encrypted store along with the code that uses
;; it. Private identities stay outside git: one identity in the basic setup, or
;; one per person in team mode.

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

;; ## Prior art, and what I borrowed

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
;; library instead uses explicit `bb secrets` commands. Vault and the cloud
;; secret managers are services, and the
;; [caveats chapter](secrets_book.caveats.html#when-to-use-something-else)
;; says when their dynamic credentials, access policy, and audit log are worth
;; running one.

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
