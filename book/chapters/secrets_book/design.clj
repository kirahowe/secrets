;; # Design and rationale

^:kindly/hide-code
(ns secrets-book.design
  (:require [clojure.edn :as edn]
            [clojure.string :as str]))

;; This library stores encrypted secrets alongside application code. Here's
;; why it works that way, how it relates to other tools, and where the approach
;; has limitations.

;; ## The problem with environment variables

;; Environment variables are a reasonable place to start. The
;; [Twelve-Factor App](https://12factor.net/config) makes the case for keeping
;; configuration out of code, since "config varies substantially across
;; deploys, code does not", and prescribes environment variables as the
;; mechanism. We can keep configuration separate from code while storing it
;; differently, though. The problem with environment variables is that most
;; applications eventually need quite a few of them.

;; Each integration adds a few more, and there may be no complete list in the
;; repository of what the application actually needs. Eventually you have to
;; go through a deployment dashboard to figure out how the app is configured.

;; Environment variables are also always strings. If you want a list of admin
;; emails, for example, you have to decide how to represent it as a string and
;; then write code to parse it. Here's a typical way to do that:

(str/split "kira@example.com,sam@example.com" #",")

;; In EDN, we can represent the same emails as a set:

(edn/read-string "#{\"kira@example.com\" \"sam@example.com\"}")

;; The first result is a vector, and we still have to decide how to handle
;; commas, blanks, and whitespace. The second is already a set. EDN also
;; supports nested maps, keywords, numbers, and booleans, so we don't have to
;; come up with a string format for each setting.

;; Git does not record changes made in a deployment dashboard. A platform may
;; have its own audit history, but it is separate from the code change that
;; consumes the secret. Twelve-Factor's own
;; [build, release, run](https://12factor.net/build-release-run) factor makes
;; a related point: a release is a build combined with its configuration,
;; uniquely identified and immutable once created. To know what was deployed,
;; we need both the code and the configuration. If the configuration only lives
;; in a dashboard, git can't give us that complete history.

;; ## Configuration belongs in version control

;; *Continuous Delivery* treats
;; [configuration management](https://continuousdelivery.com/foundations/configuration-management/) as a foundation: version control
;; everything required to build, test, and deploy, "including source code,
;; test and deployment scripts, infrastructure and application configuration
;; information". The goals are reproducibility and traceability. For
;; reproducibility, "we should be able to provision any environment in a fully
;; automated fashion, and know that any
;; new environment reproduced from the same configuration is identical."
;; Traceability means being able to determine precisely what went into any
;; environment and compare it with a previous version to see what changed.

;; In an [interview about the book](https://www.infoq.com/articles/humble-farley-continuous-delivery/), Jez Humble explains:
;; "everything that is required to build, test and deploy your system should
;; be in version control. It should be possible to plug in a new workstation,
;; and check out everything you need to build, test and deploy your system to
;; any environment." David Farley describes the deployment side: when
;; deployments are tied to version-controlled release numbers, the record of
;; which version went to which environment, and who approved it, is an audit
;; trail.

;; Secrets usually get left out of this process because we can't commit them
;; in plaintext. Encrypting them lets us keep them in version control too. A
;; checkout and one identity give us an environment's configuration, and the
;; [manifest](secrets_book.manifest.html) lets us trace changes to it.

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

;; An identity file contains enough information to encrypt a file to its own
;; recipient and decrypt the result, so we only need one key file for a
;; single-key setup. Age can also encrypt to multiple recipients. In the
;; [teams chapter](secrets_book.teams.html), we'll use a committed list of
;; public keys so each person can keep their own private identity.

;; The library shells out to the upstream `age` binary rather than implementing
;; the format. Every environment that decrypts therefore needs that binary.

;; ## Why one file per environment

;; Each environment has one EDN map and one ciphertext. Environments share the
;; app's default key unless you set a separate `:key-file` for an environment.
;; There are no overlays or partially shared files to combine when loading
;; secrets. The decrypted map contains everything the application receives.

;; This does mean that anyone who can decrypt the file can read every value in
;; it. SOPS encrypts individual values, which makes encrypted diffs
;; field-specific.
;; This library keeps whole-file encryption and adds a
;; [manifest](secrets_book.manifest.html) that records each key path, its
;; type, and a keyed hash that changes when the value does.

;; ## Why the manifest has its own key

;; A hash of a password is only safe to publish if nobody can test guesses
;; against it, so each value hash is an HMAC under a random key. That key
;; lives inside the encrypted store. Everyone who can decrypt the store can
;; compute the hashes, a solo store and a team store work the same way, and
;; nothing is derived from anyone's age identity. The cost is that the key is
;; shared with every recipient, so it is replaced whenever the recipient set
;; changes. The [manifest chapter](secrets_book.manifest.html) covers the
;; rule, and the repository's
;; [threat model](https://github.com/kirahowe/secrets/blob/main/doc/threat-model.md)
;; records the tradeoffs that were accepted.

;; ## What the library leaves out

;; The library manages one configured store per environment. It has no
;; commands for encrypting arbitrary files, because `age` already does that.
;; Its size bounds are fixed, because they exist to catch a wrong file and
;; nobody needs to tune that. The Aero integration keeps no cache between
;; reads. The initializer creates missing files and prints what to add to the
;; ones you have, and it never edits a file. In each case the threat model
;; names no need for more.

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
;; discusses when you might need their dynamic credentials, access policy, and
;; audit log.

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

;; Comments survive `bb secrets edit` round trips, because the CLI encrypts the
;; text you saved. `set` and `rm` print the map again, so comments don't
;; survive those.
