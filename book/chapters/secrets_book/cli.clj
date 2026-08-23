;; # The CLI: managing secrets from the terminal

^:kindly/hide-code
(ns secrets-book.cli
  (:require [clojure.java.io :as io]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.cli :as cli]))

;; The management commands are exposed through one babashka task. The task is
;; a dispatcher over functions in
;; `com.kirahowe.secrets.cli`, and those functions are ordinary Clojure: they
;; take a config map, return data, and throw `ex-info` when something is
;; wrong. This chapter evaluates several of them.

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

;; ## The commands

;; | Command | Args | What it does |
;; |---------|------|--------------|
;; | `keygen` | `[env]` | generate the age key for an environment |
;; | `new` | `[env]` | create a secrets file from a template, using `$VISUAL`, `$EDITOR`, or `vim` |
;; | `edit` | `[env]` | decrypt, edit, re-encrypt |
;; | `set` | `[env] <key> [--edn]` | set a key's value from stdin (creates the file if missing) |
;; | `rm` | `[env] <key>` | remove a key (fails if the key or file is absent) |
;; | `verify` | `[env]` | check the committed manifest against the secrets |
;; | `show-key` | `[env]` | print public keys for sharing |
;; | `add-recipient` | `[env] [key]` | add a public key to the recipients file |
;; | `recipients` | `[env]` | list the configured recipient public keys |
;; | `reencrypt` | `[env]` | re-encrypt to the current recipients |
;; | `encrypt` | `[env] <file>` | encrypt any file to `<file>.age` |
;; | `decrypt` | `[env] <file>` | decrypt any `.age` file to stdout |

;; Commands that operate on an environment take it first, and omitting it uses
;; `:default-environment`. `decrypt` writes the original bytes to stdout, so it
;; also supports encrypted binary files.

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

^:kindly/hide-code
(doseq [f (reverse (file-seq (io/file dir)))]
  (.delete f))
