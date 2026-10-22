^:kindly/hide-code
(ns secrets-book.quickstart)

;; # Quick start

;; In this chapter we'll set up a project, create an encrypted secrets file, and read it from the app. We'll use the default configuration here and get into the other options later in the book.

;; ## Requirements

;; Install [age](https://age-encryption.org) and [Babashka](https://babashka.org). Babashka resolves the dependencies in `bb.edn` through Java, so you need a JDK on your `PATH` as well. A JVM Clojure project will normally have that already.

;; ```sh
;; brew install age babashka
;; ```

;; On Debian or Ubuntu, `apt install age` installs age. Follow Babashka's [installation instructions](https://github.com/babashka/babashka#installation) for the current Babashka package on your platform.

;; ## Set up a project

;; Nothing is published to Clojars yet, so the quickest way to start is from a clone of the [repository](https://github.com/kirahowe/secrets). Run the initializer from your own project's directory, pointing Babashka at the clone's `src`. Change `myapp` to your application's name:

;; ```sh
;; bb -cp /path/to/secrets/src -m com.kirahowe.secrets.init --app myapp --keygen
;; ```

;; The output is a preview. It lists the files the initializer would create and writes nothing. An option's value is a separate argument, so write `--app myapp` and not `--app=myapp`. If the preview looks right, run the same command with `--apply`:

;; ```sh
;; bb -cp /path/to/secrets/src -m com.kirahowe.secrets.init --app myapp --keygen --apply
;; ```

;; In a project with no `bb.edn`, this creates two files and a key:
;;
;; - a `bb.edn` that declares the library and a `bb secrets` task,
;; - a plaintext template with a placeholder value at `secrets/secrets.edn.example`, and
;; - an age identity in your macOS login Keychain, as the item `com.kirahowe.secrets` with account `myapp`.
;;
;; The key goes from `age-keygen` into the Keychain without touching the disk. `--keygen` needs the macOS Keychain. On another system, leave it off, store a key in your password manager, and tell the environment how to read it with `:key-command`, as the [CLI chapter](secrets_book.cli.html#the-config-map) shows.

;; The initializer only creates files that don't exist. If you already have a `bb.edn`, it prints the dependency and the task for you to add and leaves your file alone. The [CLI chapter](secrets_book.cli.html#the-initializer) covers that case, and projects with a `deps.edn`.

;; The dependency it writes pins the commit your clone is at. If that commit isn't a release tag, the output says so, and the commit has to be on GitHub before another machine can resolve it.

;; You'll want to back up the key somewhere outside of version control, such as a password manager. Treat it like a password: it decrypts all of your app's secrets, and **it is unrecoverable if you lose it**. This prints it from the Keychain:
;;
;; ```sh
;; security find-generic-password -s com.kirahowe.secrets -a myapp -w
;; ```

;; ## Create the first secrets file

;; ```sh
;; bb secrets new
;; ```

;; This opens the template in `$VISUAL`, `$EDITOR`, or `vim`. The file you edit is one EDN map. Its values can be any EDN, like strings, numbers, sets, vectors, or nested maps, and comments are kept when you use `new` and `edit`:

;; ```clojure
;; {:database/url "jdbc:postgresql://db.internal/app"
;;  :stripe/api-key "sk_live_..."
;;  :auth/admins #{"kira@example.com" "sam@example.com"}}
;; ```

;; Saving creates two files:

;; ```text
;; secrets/secrets.edn.age       # encrypted values
;; secrets/secrets.edn.manifest  # key paths, types, and keyed value hashes
;; ```

;; You commit both of these. The private key stays in the Keychain and never goes into the repository.

;; If you would rather not open an editor, `set` stores one value at a time, and creates the store if there isn't one yet. Run it from a terminal and it prompts for the value with echo turned off:
;;
;; ```sh
;; bb secrets set :database/url
;; ```
;;
;; In a script or CI, you can pipe the value in instead. `set` never accepts the value as a command-line argument, so it never appears in shell history or `ps`:
;;
;; ```sh
;; printf %s "$DATABASE_URL" | bb secrets set :database/url
;; ```
;; Values are stored verbatim as strings unless you pass `--edn`, in which case the input is parsed as EDN and its type follows from the syntax.
;;
;; ``` sh
;; printf %s '#{"kira@example.com" "sam@example.com"}' \
;;   | bb secrets set :auth/admins --edn
;; ```

;; ## Read secrets in the app

;; Now we can read the secrets from the app. `load-secrets` decrypts the whole map. Locally, secrets are decrypted with the identity we just created. In production, the key can come from a single `SECRETS_AGE_IDENTITY` environment variable.

;; ```clojure
;; (require '[com.kirahowe.secrets :as secrets])
;;
;; (def secret-values
;;   (secrets/load-secrets "secrets/secrets.edn.age" {:app "myapp"}))
;;
;; (secrets/get-secret secret-values :database/url)
;; (secrets/get-secret secret-values [:r2 :account-id])
;; ```

;; If the rest of your configuration is EDN, you can use reader literals to reference a secret directly in the setting that needs it:

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

;; `#secret/req` throws when the value cannot be loaded. `#secret/opt` returns `nil` when the key isn't in the store, when there is no secrets file, or when the app has no key on this machine. It still throws when decryption fails, and when you named an identity file that doesn't exist. The [runtime chapter](secrets_book.runtime.html) covers both APIs, classpath resources, Aero, and how the key is found.

;; ## Check the setup

;; ```sh
;; bb secrets doctor
;; bb secrets verify
;; ```

;; `doctor` reports on your age installation, the configured files, the identity it resolved and where that came from, and the recipients, and tells you if anything needs attention. It doesn't print secret values or change any files. `verify` checks that the committed manifest belongs to this app and agrees with the ciphertext.

;; Day to day, this is usually all you need:

;; ```sh
;; bb secrets edit             # decrypt, edit, and re-encrypt
;; bb secrets set :some/key    # set one value from a prompt or stdin
;; bb secrets rm :old/key      # remove a value
;; bb secrets verify           # check the manifest before committing
;; ```

;; Run `bb secrets --help` or `bb secrets help set` whenever you need the exact command syntax. The [CLI chapter](secrets_book.cli.html) covers every command and the configuration behind them, and [Production and CI](secrets_book.production.html) shows how to get the identity into a deployment.

;; ## Runnable examples

;; The repository's [examples directory](https://github.com/kirahowe/secrets/tree/main/examples) has some small starter projects showing different ways to use the library, depending on what else you are already using:

;; - [quickstart-bb](https://github.com/kirahowe/secrets/tree/main/examples/quickstart-bb): a minimal Babashka consumer using `clojure.edn` reader tags.
;; - [integrant-service](https://github.com/kirahowe/secrets/tree/main/examples/integrant-service): a JVM HTTP service with secrets as an Integrant component.
;; - [aero-profiles](https://github.com/kirahowe/secrets/tree/main/examples/aero-profiles): profile-aware EDN configuration with the Aero integration.
;; - [team-ci](https://github.com/kirahowe/secrets/tree/main/examples/team-ci): multiple age recipients and keyless CI manifest verification.
