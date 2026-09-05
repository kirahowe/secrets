^:kindly/hide-code
(ns secrets-book.index)

;; # Introduction

;; `com.kirahowe/secrets` manages application secrets as a single
;; **version-controlled, age-encrypted EDN file** instead of a pile of
;; environment variables. One private key decrypts it. Everything else, the
;; structure, the defaults, and the ciphertext itself, lives in git, with a
;; committed value-free manifest that makes each change reviewable.

;; ## Features

;; - **One private key to deploy.** Production receives a single age identity
;;   through an environment variable or a mounted file, not a list of secret
;;   values.
;; - **Real EDN at runtime.** Sets, vectors, nested maps, and numbers, not just
;;   strings. Load the whole map, or reference values from your EDN config with
;;   `#secret/req` and `#secret/opt`. Works with Aero, and the plain map suits
;;   Integrant or component.
;; - **Encrypted secrets live in git** beside the code that uses them, one file
;;   per environment. Load them from disk or from inside the jar.
;; - **Reviewable changes.** Every write updates a value-free manifest, so a
;;   diff shows which keys were added, removed, or changed. CI can check that
;;   the manifest is fresh without holding a key.
;; - **Solo or team.** Encrypt to your own key, or to a committed list of
;;   recipients so each teammate decrypts with their own.
;; - **A `bb secrets` task** for the day to day: edit in your editor, set from
;;   stdin, diagnose with `doctor`, and a project initializer that previews
;;   before it writes.
;; - **Just files and age.** No secrets server, no KMS, no cloud account, no
;;   GPG keyring.

;; ## Why not environment variables?

;; Environment variables are easy to start with and painful to live with. They
;; sprawl: every integration adds another, and nobody can tell from the
;; repository what the application needs. They are untyped strings, so a
;; comma-separated allowlist becomes parsing code. And they live outside version
;; control, as mutable state in a deploy platform, with no history and no
;; review.

;; Encrypting a plain EDN map fixes all three. The map is real data, the
;; encrypted form is committed, and the only out-of-band secret is one age key.
;; The ciphertext itself diffs opaquely, since age re-encrypts the whole file,
;; so the committed manifest is what makes changes reviewable: it records the
;; shape of the secrets, and a pull request shows which keys were added,
;; removed, or changed without revealing any value. Secrets travel with the
;; code that needs them, so a new environment is a checkout and one key rather
;; than a checklist copied between dashboards.

;; This is a deliberately small tool for solo developers and small teams whose
;; secrets change infrequently. If you need dynamic credentials, per-secret
;; access rules, or automatic rotation, see
;; [when to use something else](secrets_book.caveats.html#when-to-use-something-else).

;; ## How this book is organized

;; - [Quick start](secrets_book.quickstart.html) installs the tools,
;;   initializes a project, and writes and reads the first secrets.
;; - [The CLI](secrets_book.cli.html) covers the initializer, configuration,
;;   and every command.
;; - [Runtime](secrets_book.runtime.html) covers loading secrets in an
;;   application: the map, reader literals, Aero, and caching.
;; - [Teams](secrets_book.teams.html) gives every teammate their own private
;;   identity.
;; - [The manifest](secrets_book.manifest.html) explains reviewable changes
;;   without plaintext.
;; - [Production and CI](secrets_book.production.html) shows how to inject an
;;   identity and gate on the manifest.
;; - [Design and rationale](secrets_book.design.html) sets out the model, why
;;   age, and the prior art.
;; - [Caveats and threat model](secrets_book.caveats.html) is the boundary of
;;   what this library does and does not protect.
;; - [Reference](secrets_book.reference.html) lists the API, configuration
;;   keys, environment variables, and exit codes.
