^:kindly/hide-code
(ns secrets-book.quickstart)

;; # Quick start

;; This chapter takes a project from nothing to reading its first secret. Each
;; step has a chapter of its own later in the book; this one only shows the
;; default path.

;; ## What you need

;; Install [age](https://age-encryption.org) and
;; [Babashka](https://babashka.org). The one-time dependency resolution shown
;; below also needs Java; a JVM Clojure project will normally have that already.

;; ```sh
;; brew install age babashka
;; ```

;; On Debian or Ubuntu, `apt install age` installs age. Follow Babashka's
;; [installation instructions](https://github.com/babashka/babashka#installation)
;; for the current Babashka package on your platform.

;; ## Set up a project

;; Add the library to your project's `bb.edn`:

;; ```clojure
;; {:deps {com.kirahowe/secrets {:mvn/version "0.1.0"}}}
;; ```

;; A JVM Clojure application also needs the same coordinate in its `deps.edn`;
;; `bb.edn` supplies the management task, while `deps.edn` supplies application
;; code at runtime.

;; Now run the initializer from the same directory. Change `myapp` to your
;; application's name:

;; ```sh
;; bb -m com.kirahowe.secrets.init --app myapp --keygen
;; ```

;; The first run is a preview. It lists the files it wants to create or merge
;; and changes nothing. If the preview looks right, run the same command with
;; `--apply`:

;; ```sh
;; bb -m com.kirahowe.secrets.init --app myapp --keygen --apply
;; ```

;; This keeps the dependency you just added, merges a `bb secrets` task into
;; `bb.edn`, creates a safe plaintext template, and generates the age identity at
;; `~/.config/myapp/key.txt`. Existing `bb.edn` comments and unrelated forms are
;; preserved. A conflicting dependency or task is refused instead of replaced.

;; Back up `~/.config/myapp/key.txt` somewhere outside git, such as a password
;; manager. It is the only way to decrypt this store, and the library cannot
;; recover it for you.

;; ## Create the first secrets file

;; ```sh
;; bb secrets new
;; ```

;; This opens the generated template in `$VISUAL`, `$EDITOR`, or `vim`. The file
;; you edit is ordinary EDN, so values can be strings, numbers, sets, vectors, or
;; nested maps:

;; ```clojure
;; {:database/url "jdbc:postgresql://db.internal/app"
;;  :stripe/api-key "sk_live_..."
;;  :auth/admins #{"kira@example.com" "sam@example.com"}}
;; ```

;; Saving creates two files:

;; ```text
;; secrets/secrets.edn.age       # encrypted values
;; secrets/secrets.edn.manifest  # value-free description of what changed
;; ```

;; Commit both. Keep `~/.config/myapp/key.txt` out of the repository.

;; If you would rather not open an editor, `set` reads a value from standard
;; input. It never accepts the value as a command-line argument:

;; ```sh
;; printf %s "$DATABASE_URL" | bb secrets set :database/url
;; printf %s '#{"kira@example.com" "sam@example.com"}' \
;;   | bb secrets set :auth/admins --edn
;; ```

;; `set` creates the encrypted file when it does not exist yet. Without `--edn`
;; it stores a string; with `--edn` it reads the value as EDN.

;; ## Read secrets in the app

;; `load-secrets` decrypts the complete map. Passing `{:app "myapp"}` uses the
;; identity the initializer created locally and still allows production to
;; override it with a `SECRETS_AGE_IDENTITY*` environment variable:

;; ```clojure
;; (require '[com.kirahowe.secrets :as secrets])
;;
;; (def secret-values
;;   (secrets/load-secrets "secrets/secrets.edn.age" {:app "myapp"}))
;;
;; (secrets/get-secret secret-values :database/url)
;; (secrets/get-secret secret-values [:r2 :account-id])
;; ```

;; If the rest of your configuration is EDN, reader literals keep each secret
;; reference beside the setting that uses it:

;; ```clojure
;; (require '[clojure.edn :as edn])
;;
;; (def readers
;;   (secrets/reader-literals
;;    {:file "secrets/secrets.edn.age" :app "myapp"}))
;;
;; (edn/read-string
;;  {:readers readers}
;;  "{:db {:jdbc-url #secret/req :database/url}
;;    :email {:api-key #secret/opt :postmark/api-key}}")
;; ```

;; `#secret/req` throws when the value cannot be loaded. `#secret/opt` returns
;; `nil` when the secret, ciphertext, or identity is absent, but it still throws
;; when an existing ciphertext fails to decrypt. The
;; [runtime chapter](secrets_book.runtime.html) covers both APIs, classpath
;; resources, caching, Aero, and input limits.

;; ## Check the setup

;; ```sh
;; bb secrets doctor
;; bb secrets verify
;; ```

;; `doctor` explains whether age, the configured identity, ciphertext, template,
;; recipients, and manifest are ready. It does not print secret values or mutate
;; anything. `verify` checks that the committed manifest belongs to this app and
;; agrees with the ciphertext.

;; Day to day, this is usually all you need:

;; ```sh
;; bb secrets edit             # decrypt, edit, and re-encrypt
;; bb secrets set :some/key    # read a replacement from stdin
;; bb secrets rm :old/key      # remove a value
;; bb secrets verify           # check the manifest before committing
;; ```

;; Run `bb secrets --help` or `bb secrets help set` whenever you need the exact
;; command syntax. The [CLI chapter](secrets_book.cli.html) covers every
;; command and the configuration behind them, and
;; [Production and CI](secrets_book.production.html) shows how to get the
;; identity into a deployment.

;; ## Runnable examples

;; The repository's [examples directory](https://github.com/kirahowe/secrets/tree/main/examples) has small starter projects that
;; run from a checkout. Pick the one closest to your application's shape:

;; - [quickstart-bb](https://github.com/kirahowe/secrets/tree/main/examples/quickstart-bb): a minimal Babashka consumer using
;;   `clojure.edn` reader tags.
;; - [integrant-service](https://github.com/kirahowe/secrets/tree/main/examples/integrant-service): a JVM HTTP service with
;;   secrets as an Integrant component.
;; - [aero-profiles](https://github.com/kirahowe/secrets/tree/main/examples/aero-profiles): profile-aware EDN configuration with
;;   the Aero integration.
;; - [team-ci](https://github.com/kirahowe/secrets/tree/main/examples/team-ci): multiple age recipients and keyless CI manifest
;;   verification.
