^:kindly/hide-code
(ns secrets-book.index)

;; # Introduction

;; `com.kirahowe/secrets` is a library for keeping a Clojure project's secrets in one age-encrypted EDN file per environment, committed with the code. One private key decrypts the file, and that key is the only secret you manage outside the repository. A manifest that holds no values is committed beside the ciphertext so each change can be reviewed.

;; ## Features

;; - You supply one private key to production, through an environment variable or a mounted file.
;; - On your own machine the private key is not a plaintext file. It lives in the macOS Keychain, or in a password manager that prints it on request, and reaches `age` on standard input.
;; - Secrets are ordinary EDN, so you can use sets, vectors, nested maps, and numbers. Load the whole map, or reference individual values in your EDN config with `#secret/req` and `#secret/opt`. There's an Aero integration, and the map works with Integrant or Component.
;; - The encrypted files live in git alongside the code that uses them, with one file per environment. You can load them from disk or from inside a jar.
;; - Every write updates a manifest that shows which keys were added, removed, or changed without exposing their values. CI can check that the manifest matches the ciphertext without a private key.
;; - You can encrypt to your own key, or to a committed list of public keys so each teammate decrypts with their own private key. The manifest works the same way in both cases.
;; - The `bb secrets` task edits secrets in your editor, sets one value from a hidden prompt or stdin, and diagnoses your setup with `doctor`. The project initializer previews what it will create and never edits a file you already have.
;; - It uses only files and age. You don't need a secrets server, KMS, cloud account, or GPG keyring.

;; The library is alpha software. Its API, commands, and file formats can still change between releases.

;; ## Why not environment variables?

;; Environment variables work fine when you only have a few of them. As you add integrations, though, it gets harder to keep track of what the app needs. They're also all strings, so even something simple like a list of admin emails needs parsing code. And when you change them in a deployment dashboard, those changes aren't part of your git history or code review.

;; With an encrypted EDN map, we can keep structured data in version control and only manage one age key separately. There's still a problem with reviewing changes, though, because age re-encrypts the whole file each time. The encrypted diff doesn't tell us what changed, and that's what the manifest is for. It records the structure of the secrets and a keyed hash of each value, so a pull request can show which keys were added, removed, or changed without revealing their values.

;; Environment variables also make setting up a new environment annoying. How many times have you had to ask a coworker for a secret over Slack to get your local setup working? When all of the app's secrets are stored in a single file, you only need a valid key to get everything working. This follows the configuration-management principle described in [*Continuous Delivery*](https://continuousdelivery.com/foundations/configuration-management/): everything required to build, test, and deploy the system should be versioned, including the application configuration, so that any environment can be reproduced and any change traced. We usually leave secrets out of version control because they're sensitive, but encrypting them lets us track them along with the rest of the configuration.

;; This library is intended for solo developers and small teams whose secrets change infrequently. If you need dynamic credentials, per-secret access rules, or automatic rotation, see [when to use something else](secrets_book.caveats.html#when-to-use-something-else).

;; ## How this book is organized

;; - [Quick start](secrets_book.quickstart.html) covers installation, project initialization, and basic usage.
;; - [The CLI](secrets_book.cli.html) covers the initializer, configuration, and every command.
;; - [Runtime](secrets_book.runtime.html) covers loading secrets in an application: the map, reader literals, Aero, and how the key is found.
;; - [Teams](secrets_book.teams.html) gives every teammate their own private identity, and covers adding and removing people.
;; - [The manifest](secrets_book.manifest.html) explains how changes are reviewable without revealing secrets, and what the manifest discloses.
;; - [Production and CI](secrets_book.production.html) shows how to inject an identity and how to check the manifest in CI, with or without a key.
;; - [Design and rationale](secrets_book.design.html) explains the model, why it uses age, and the ideas and tools it's based on.
;; - [Caveats and threat model](secrets_book.caveats.html) explains what the library protects and what you still need to handle yourself.
;; - [Reference](secrets_book.reference.html) lists the public API from the code, the configuration keys, and the exit codes.

;; There are also some [runnable example starter projects](https://github.com/kirahowe/secrets/tree/main/examples) that demo a few common setups.
