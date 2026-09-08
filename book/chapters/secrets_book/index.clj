^:kindly/hide-code
(ns secrets-book.index)

;; # Introduction

;; `com.kirahowe/secrets` is a library for managing secrets in your Clojure projects as a single version-controlled, age-encrypted EDN file. One private key decrypts the file, which is your app's only secret. Everything else gets committed in your repo with a value-free manifest so each change is reviewable.

;; ## Features

;; - You only need to supply one private key to production, either through an environment variable or a mounted file.
;; - Secrets are ordinary EDN, so you can use sets, vectors, nested maps, and numbers. Load the whole map or reference individual values in your EDN config with `#secret/req` and `#secret/opt`. There's an Aero integration, and the map works with Integrant or component.
;; - The encrypted files live in git alongside the code that uses them, with one file per environment. You can load them from disk or inside a jar.
;; - Every write updates a manifest that lets you review which keys were added, removed, or changed without exposing their values. CI can check whether the manifest is up to date without needing a private key.
;; - You can encrypt to your own key or to a committed list of public keys so each teammate can decrypt with their own private key.
;; - The `bb secrets` task lets you edit secrets in your editor, set values from stdin, and troubleshoot your setup with `doctor`. The project initializer shows you what it will change before writing anything.
;; - It uses only files and age. You don't need a secrets server, KMS, cloud account, or GPG keyring.

;; ## Why not environment variables?

;; Environment variables work fine when you only have a few of them. As you add integrations, though, it gets harder to keep track of what the app needs. They're also all strings, so even something simple like a list of admin emails needs parsing code. And when you change them in a deployment dashboard, those changes aren't part of your git history or code review.

;; With an encrypted EDN map, we can keep structured data in version control and only manage one age key separately. There's still a problem with reviewing changes, though, because age re-encrypts the whole file each time. The encrypted diff doesn't tell us what changed, so that's what the manifest is for -- it records the structure of the secrets so a pull request can show which keys were added, removed, or changed without revealing their values.

;; Environment variables also make setting up a new environment annoying. How many times have you had to ask a coworker to ask for a secret over slack to get your local setup working? When all of the app's config is stored in a single file, you only need to supply a valid key to get everything working. This follows the configuration-management principle described in [*Continuous Delivery*](https://continuousdelivery.com/foundations/configuration-management/): everything required to build, test, and deploy the system should be versioned, including the application configuration, so that any environment can be reproduced and any change traced. We usually leave secrets out of version control because they're sensitive, but encrypting them lets us track them along with the rest of the configuration.

;; This library is intended for solo developers and small teams whose secrets change infrequently. If you need dynamic credentials, per-secret access rules, or automatic rotation, see [when to use something else](secrets_book.caveats.html#when-to-use-something-else).

;; ## How this book is organized

;; - [Quick start](secrets_book.quickstart.html) covers installation, project initialization, and basic usage.
;; - [The CLI](secrets_book.cli.html) covers the initializer, configuration, and every command.
;; - [Runtime](secrets_book.runtime.html) covers loading secrets in an application -- the map, reader literals, Aero, and caching.
;; - [Teams](secrets_book.teams.html) gives every teammate their own private identity.
;; - [The manifest](secrets_book.manifest.html) explains how changes are reviewable without revealing secrets.
;; - [Production and CI](secrets_book.production.html) shows how to inject an identity and check the manifest in CI so that CI can check whether the manifest is up to date without needing a private key.
;; - [Design and rationale](secrets_book.design.html) explains the model, why it uses age, and the ideas and tools it's based on.
;; - [Caveats and threat model](secrets_book.caveats.html) explains what the library protects and what you still need to handle yourself.
;; - [API Docs](secrets_book.reference.html) is generated API documentation from the code.

;; There are also some [runnable example starter projects](https://github.com/kirahowe/secrets/tree/main/examples) that demo a few common setups.
