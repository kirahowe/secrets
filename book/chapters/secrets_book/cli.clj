;; # The CLI: managing secrets from the terminal

^:kindly/hide-code
(ns secrets-book.cli
  (:require [clojure.java.io :as io]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.cli :as cli]))

;; The management commands are exposed through one Babashka task. The task is a
;; small dispatcher over ordinary Clojure functions: they take a config map,
;; return data, and throw `ex-info` when something is wrong. That makes the same
;; operations usable from a terminal, a REPL, or a script.

;; ## Let the initializer wire it up

;; The [quick start](index.html) uses the project initializer because hand
;; editing a task definition is not a particularly interesting way to spend
;; your first five minutes with a library. Once the released dependency is in
;; `bb.edn`, run the initializer once to preview, then again with `--apply` when
;; the proposal looks right:

;; ```sh
;; bb -m com.kirahowe.secrets.init --app myapp --keygen
;;
;; bb -m com.kirahowe.secrets.init --app myapp --keygen --apply
;; ```

;; The initializer merges into `bb.edn` without reformatting existing forms or
;; dropping comments. It refuses conflicting dependencies and tasks. It also
;; creates the template and, only after an accepted scaffold succeeds,
;; generates the private identity requested by `--keygen`.

;; The default `tracked` layout commits ciphertext and manifests while keeping
;; the identity under `~/.config/<app>`. A `disposable` layout keeps every
;; artifact, including its key, under ignored `.local/secrets`; it is useful for
;; demos and throwaway projects, not a durable store. Add `--team` to create a
;; recipients file. Run the initializer with `--help` for all options.

;; An interactive preview shows only changed regions and redacts obvious opaque
;; values. Non-interactive runs print paths and actions, never complete file
;; bodies. `--show-contents` is an explicit escape hatch when you genuinely need
;; to inspect the full proposed files. Before applying, the initializer also
;; checks that the project path has trustworthy ownership and permissions; if
;; it cannot establish that another user cannot swap a directory underneath the
;; write, it explains the problem and changes nothing.

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

;; In that output, `:template` and `:manifest` derive from the
;; secrets file name, `:key-file` is the durable path `keygen` writes to, and
;; `:identity-file` is what decryption actually uses. The two are separate
;; because the `SECRETS_AGE_IDENTITY*` environment variables override
;; `:identity-file` but never `:key-file`. A CI runner holding one env var decrypts and
;; verifies with it; `keygen` on your laptop still writes to the configured
;; path.

;; ## Validation catches the dangerous config

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

;; Normalization also canonicalizes every artifact path in every environment.
;; Environments may intentionally share an app identity, a recipients list, or
;; a template. Other role collisions are errors: a manifest cannot also be a
;; key, and two environments cannot write the same ciphertext. This check runs
;; before a command touches the filesystem.

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

;; `set` and `rm` are the non-interactive path: no editor is opened. `set`
;; reads the value from **stdin**, which avoids exposing it as a process
;; argument. The value is stored as a
;; string unless `--edn` parses stdin as EDN first, so a set, a number, or a
;; nested map can be set as itself rather than a string of digits or braces.
;; A blank value on stdin is refused rather than stored — the same rule the
;; library applies to a set-but-empty `SECRETS_AGE_IDENTITY`, because a blank
;; is almost always an unset variable expanding to nothing, and `--edn` with
;; `""` is the deliberate way to store an empty string on purpose. `set`
;; creates the environment's secrets file from an empty map when it doesn't
;; exist yet, which is what makes bootstrapping a brand-new environment
;; scriptable. `rm` fails when the key or file is absent. In both commands,
;; `<key>` is an EDN keyword (`:some/key`) or a vector path (`[:a :b]`). Both
;; re-encrypt and refresh the manifest. Unlike `edit`, they re-render the EDN,
;; so comments in the plaintext do not survive a `set` or `rm`.

;; Every secrets-writing command validates the complete EDN, encrypts to staged
;; sibling files, and atomically replaces the ciphertext and manifest as one
;; operation with rollback. An invalid edit or a failed manifest write leaves
;; the previous pair in place. In team mode the recipients file is read,
;; bounded, and validated once before editing or decryption begins; that exact
;; list is the one handed to age.

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

;; Now `verify!`. It returns data rather than exiting, which makes it as
;; useful from a REPL as from CI:

(cli/verify! config "dev")

;; The `:exit` value is what `bb secrets verify` uses as its process status: 0
;; for a match, 1 for drift, and 2 for a missing ciphertext or manifest (or an
;; older manifest with no ciphertext hash when no identity is available).

;; `doctor!` is the value-free troubleshooting counterpart. It checks the raw
;; config, age installation, artifact state, identity availability, encryption
;; readiness, and whether keyless or full verification is possible. It returns
;; exit 0 for healthy, 1 when some action is needed, and 2 for invalid config:

(cli/doctor! config "dev")

;; `encrypt!` handles arbitrary files:

(do
  (spit (str dir "/service-account.json") "{\"type\": \"service_account\"}")
  (cli/encrypt! config "dev" (str dir "/service-account.json")))

;; ## Errors carry their remediation

;; Command functions throw `ex-info` with the exit code and any hints in the
;; data. The `run!` dispatcher prints those details and exits with the attached
;; status. From a REPL, the same information is available in the exception:

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
;; The CLI shares the runtime plaintext and EDN-depth limits and adds bounds for
;; recipients and manifests:

;; ```clojure
;; {:app "myapp"
;;  :limits {:max-plaintext-bytes 8388608
;;           :max-edn-depth 100
;;           :max-recipients 256
;;           :max-recipient-chars 1024
;;           :max-recipients-bytes 262144
;;           :max-manifest-bytes 1048576
;;           :max-manifest-entries 10000}
;;  :environments {:dev {:secrets-file "secrets/secrets.edn.age"}}}
;; ```

;; You only need to supply values you want to change. Every value must be a
;; positive integer, and unknown keys are rejected rather than silently ignored.

^:kindly/hide-code
(doseq [f (reverse (file-seq (io/file dir)))]
  (.delete f))
