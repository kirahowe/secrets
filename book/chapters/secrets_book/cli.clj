;; # The CLI: managing secrets from the terminal

^:kindly/hide-code
(ns secrets-book.cli
  (:require [clojure.java.io :as io]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.cli :as cli]))

;; The management commands are exposed through one Babashka task. Underneath,
;; they're ordinary Clojure functions that take a config map, return data, and
;; throw `ex-info` when something goes wrong. You can use the same operations
;; from a terminal, a REPL, or a script.

;; ## Let the initializer wire it up

;; The [quick start](secrets_book.quickstart.html) runs the project
;; initializer once to preview the changes and once with `--apply`. This gives
;; you a working task definition without having to edit it by hand. This section
;; covers the other choices the initializer offers.

;; The default `tracked` layout commits ciphertext and manifests while keeping
;; the identity under `~/.config/<app>`. The `disposable` layout keeps every
;; artifact, including its key, under the ignored `.local/secrets` directory.
;; It's useful for demos and throwaway projects, but it isn't a durable store.
;; Add `--team` to create a recipients file. Run the initializer with `--help`
;; for all options.

;; An interactive preview shows only the regions that changed and redacts
;; obvious opaque values. Non-interactive runs print paths and actions rather
;; than complete file bodies. Use `--show-contents` when you need to inspect the
;; full proposed files. Before applying anything, the initializer checks the
;; project path's ownership and permissions. If it can't rule out another user
;; swapping a directory underneath the write, it explains the problem and
;; leaves the project alone.

;; ## The config map

;; The setup starts with a `bb.edn` map from environment names to file
;; locations:

;; ```clojure
;; {:app "myapp"
;;  :default-environment :prod
;;  :environments
;;  {:prod {:secrets-file "env/prod/resources/secrets.edn.age"}
;;   :dev  {:secrets-file "env/dev/resources/secrets.edn.age"}}}
;; ```

;; The CLI calls `normalize-config` first. Calling it directly shows the
;; expanded defaults:

(-> {:app "myapp"
     :environments {:prod {:secrets-file "env/prod/resources/secrets.edn.age"}}}
    cli/normalize-config
    (get-in [:environments :prod]))

;; In that output, `:template` and `:manifest` are derived from the secrets file
;; name. `:key-file` is the durable path where `keygen` writes, while
;; `:identity-file` is the path decryption uses. They are separate because the
;; `SECRETS_AGE_IDENTITY*` environment variables override `:identity-file` but
;; never `:key-file`. A CI runner can decrypt and verify using one of those
;; environment variables, while `keygen` on your laptop still writes to the
;; configured path.

;; ## Validating the configuration {#validation-catches-the-dangerous-config}

;; `:app` is required. It names the default key path; using an implicit app
;; name could make unrelated projects share `~/.config/<app>/key.txt`.

(try
  (cli/normalize-config {:environments {:dev {:secrets-file "s.edn.age"}}})
  (catch Exception e (ex-message e)))

;; A `:secrets-file` that does not end in `.age` would derive a template and
;; manifest name equal to the ciphertext path itself, and writing the manifest
;; would then overwrite your encrypted secrets. The config loader refuses:

(try
  (cli/normalize-config {:app "myapp"
                         :environments {:dev {:secrets-file "secrets.enc"}}})
  (catch Exception e (ex-message e)))

;; Set `:template` and `:manifest` explicitly if you really need another
;; extension.

;; Normalization also turns every artifact path in every environment into a
;; canonical path. Environments can intentionally share an app identity, a
;; recipients list, or a template. Other collisions are errors: a manifest
;; can't also be a key, and two environments can't write the same ciphertext.
;; The check runs before a command touches the filesystem.

;; ## The commands

;; | Command | Args | What it does |
;; |---------|------|--------------|
;; | `keygen` | `[env]` | generate the age key for an environment |
;; | `new` | `[env]` | create a secrets file from a template, using `$VISUAL`, `$EDITOR`, or `vim` |
;; | `edit` | `[env]` | decrypt, edit, re-encrypt |
;; | `set` | `[env] <key> [--edn]` | set a key's value from stdin (creates the file if missing) |
;; | `rm` | `[env] <key>` | remove a key (fails if the key or file is absent) |
;; | `verify` | `[env]` | check the committed manifest against the secrets |
;; | `doctor` | `[env]` | diagnose configuration and verification readiness without revealing values |
;; | `show-key` | `[env]` | print public keys for sharing |
;; | `add-recipient` | `[env] [key]` | add a public key to the recipients file |
;; | `recipients` | `[env]` | list the configured recipient public keys |
;; | `reencrypt` | `[env]` | re-encrypt to the current recipients |
;; | `encrypt` | `[env] <file>` | encrypt any file to `<file>.age` |
;; | `decrypt` | `[env] <file>` | decrypt any `.age` file to stdout |

;; Commands that operate on an environment take it first, and omitting it uses
;; `:default-environment`. `decrypt` writes the original bytes to stdout, so it
;; also supports encrypted binary files.

;; Global and command-specific help are generated from the same command
;; definitions used for parsing:

;; ```sh
;; bb secrets --help
;; bb secrets help set
;; bb secrets set --help
;; ```

;; `-h` and `--help` work anywhere before `--`. Everything after `--` is an
;; operand, even when it looks like an option. That makes dash-leading file and
;; key names unambiguous.

;; `set` and `rm` don't open an editor. `set` reads the value from **stdin**, so
;; it isn't exposed as a process argument. By default the value is stored as a
;; string. With `--edn`, stdin is parsed as EDN first, so a set, number, or
;; nested map is stored as that value rather than as a string of digits or
;; braces. A blank value on stdin is rejected. The library applies the same rule
;; to a set-but-empty `SECRETS_AGE_IDENTITY`, because a blank usually means an
;; unset variable expanded to nothing. To store an empty string intentionally,
;; use `--edn` with `""`.
;;
;; If the environment's secrets file doesn't exist yet, `set` creates it from
;; an empty map. This makes it possible to bootstrap a new environment from a
;; script. `rm` fails when the key or file is absent. For both commands, `<key>`
;; can be an EDN keyword (`:some/key`) or a vector path (`[:a :b]`). Both
;; commands re-encrypt the secrets and refresh the manifest. They also re-render
;; the EDN, so plaintext comments don't survive a `set` or `rm`.

;; Every command that writes secrets validates the complete EDN and encrypts to
;; staged sibling files. It then replaces the ciphertext and manifest together,
;; atomically, with rollback. An invalid edit or a failed manifest write leaves
;; the previous pair in place. In team mode, the recipients file is read,
;; bounded, and validated once before editing or decryption begins. That exact
;; list is then passed to age.

;; ## A complete workflow

;; The interactive commands (`new`, `edit`) need an editor. This example uses
;; the non-interactive functions in a temporary directory:

(def dir
  (str (java.nio.file.Files/createTempDirectory
        "secrets-cli-"
        (into-array java.nio.file.attribute.FileAttribute []))))

(def config
  (cli/normalize-config
   {:app "cli-demo"
    :default-environment :dev
    :environments {:dev {:secrets-file (str dir "/secrets.edn.age")
                         :key-file (str dir "/key.txt")}}}))

^:kindly/hide-code
(age/keygen! (str dir "/key.txt"))

^:kindly/hide-code
(spit (str dir "/secrets.edn.example")
      "{:api/token \"replace-me\" :flags #{}}\n")

;; Create the encrypted file the way `bb secrets new` would, minus the editor:

(let [plain (str dir "/plain.edn")]
  (spit plain (pr-str {:api/token "t-123" :flags #{:beta}}))
  (age/encrypt-file! (str dir "/key.txt") plain (str dir "/secrets.edn.age"))
  (io/delete-file plain))

;; `reencrypt!` decrypts and re-encrypts to the current recipients, and as a
;; side effect writes the manifest:

(cli/reencrypt! config "dev")

;; We can now call `verify!`. It returns data instead of exiting, so the same
;; function works from a REPL or in CI:

(cli/verify! config "dev")

;; The `:exit` value is what `bb secrets verify` uses as its process status: 0
;; for a match, 1 for drift, and 2 for a missing ciphertext or manifest (or an
;; older manifest with no ciphertext hash when no identity is available).

;; `doctor!` checks the setup without revealing any values. It examines the raw
;; config, age installation, artifact state, identity availability, encryption
;; readiness, and whether keyless or full verification is possible. It returns
;; exit 0 when everything is healthy, 1 when some action is needed, and 2 when
;; the config is invalid:

(cli/doctor! config "dev")

;; `encrypt!` handles arbitrary files:

(do
  (spit (str dir "/service-account.json") "{\"type\": \"service_account\"}")
  (cli/encrypt! config "dev" (str dir "/service-account.json")))

;; ## Understanding errors {#errors-carry-their-remediation}

;; Command functions throw `ex-info` with the exit code and any suggestions in
;; the exception data. The `run!` dispatcher prints those details and exits with
;; the attached status. At the REPL, you can read the same information from the
;; exception:

(try
  (cli/verify! config "nope")
  (catch clojure.lang.ExceptionInfo e
    {:message (ex-message e) :data (ex-data e)}))

;; ## REPL safety

;; Command functions print progress but do not call `System/exit`. They return
;; a path, a result map, or `:aborted` after a declined confirmation prompt.
;; Only `run!`, the entry point wired into `bb.edn`, translates failures into
;; process exit codes.

;; ## Bounding CLI inputs

;; A top-level `:limits` map overrides the input bounds for every environment.
;; The CLI uses the runtime limits for plaintext size and EDN depth, and adds
;; limits for recipients and manifests. Include only the values you want to
;; change:

;; ```clojure
;; {:app "myapp"
;;  :limits {:max-plaintext-bytes 2097152
;;           :max-recipients 32}
;;  :environments {:dev {:secrets-file "secrets/secrets.edn.age"}}}
;; ```

;; Every value must be a positive integer, and unknown keys are rejected rather
;; than silently ignored. The
;; [reference](secrets_book.reference.html#configuration-limits) lists every
;; limit and its default.

^:kindly/hide-code
(doseq [f (reverse (file-seq (io/file dir)))]
  (.delete f))
