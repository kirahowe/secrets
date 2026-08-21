;; # The CLI: managing secrets from the terminal

^{:kindly/hide-code true}
(ns secrets-book.cli
  (:require [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.cli :as cli]
            [clojure.java.io :as io]))

;; Everything you do to a secrets file besides reading it at runtime goes
;; through one babashka task. The task is a thin dispatcher over functions in
;; `com.kirahowe.secrets.cli`, and those functions are ordinary Clojure: they
;; take a config map, return data, and throw `ex-info` when something is
;; wrong. This chapter runs several of them live.

;; ## The config map

;; The [quick start](secrets_book.quick_start.html) showed the `bb.edn`
;; wiring. The heart of it is a map from environment names to file locations:

;; ```clojure
;; {:app "myapp"
;;  :default-environment :prod
;;  :environments
;;  {:prod {:secrets-file "env/prod/resources/secrets.edn.age"}
;;   :dev  {:secrets-file "env/dev/resources/secrets.edn.age"}}}
;; ```

;; `normalize-config` is what the CLI runs first, and you can call it
;; yourself to see exactly what the defaults expand to:

(-> {:app "myapp"
     :environments {:prod {:secrets-file "env/prod/resources/secrets.edn.age"}}}
    cli/normalize-config
    (get-in [:environments :prod]))

;; Worth noticing in that output: `:template` and `:manifest` derive from the
;; secrets file name, `:key-file` is the durable path `keygen` writes to, and
;; `:identity-file` is what decryption actually uses. The two are separate
;; because the `SECRETS_AGE_IDENTITY*` environment variables override `:identity-file`
;; but never `:key-file`. A CI runner holding one env var decrypts and
;; verifies with it; `keygen` on your laptop still writes to the configured
;; path.

;; ## Validation catches the dangerous config

;; `:app` is required, with no default. It names the default key path, and a
;; defaulted app name would mean two unrelated projects quietly sharing
;; `~/.config/secrets/key.txt`, which is exactly the guessing the runtime
;; side refuses to do.

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
;; | `new` | `[env]` | create a secrets file from a template, via `$EDITOR` |
;; | `edit` | `[env]` | decrypt, edit, re-encrypt |
;; | `set` | `[env] <key> [--edn]` | set a key's value from stdin (creates the file if missing) |
;; | `rm` | `[env] <key>` | remove a key (fails if the key or file is absent) |
;; | `verify` | `[env]` | check the committed manifest against the secrets |
;; | `show-key` | `[env]` | print public keys for sharing |
;; | `add-recipient` | `[env] [key]` | add a public key to the recipients file |
;; | `recipients` | `[env]` | list who can decrypt |
;; | `reencrypt` | `[env]` | re-encrypt to the current recipients |
;; | `encrypt` | `[env] <file>` | encrypt any file to `<file>.age` |
;; | `decrypt` | `[env] <file>` | decrypt any `.age` file to stdout |

;; Every command takes the environment first, and omitting it uses
;; `:default-environment`. `decrypt` writes bytes, not text, so certificates
;; and keystores round-trip as faithfully as EDN does.

;; `set` and `rm` are the non-interactive path: no `$EDITOR`, value read from
;; **stdin** so it never lands in shell history or `ps`, which is what makes
;; them safe to call from a script or a CI step. `set`'s value is stored as a
;; string unless `--edn` parses stdin as EDN first, so a set, a number, or a
;; nested map can be set as itself rather than a string of digits or braces.
;; A blank value on stdin is refused rather than stored — the same rule the
;; library applies to a set-but-empty `SECRETS_AGE_IDENTITY`, because a blank
;; is almost always an unset variable expanding to nothing, and `--edn` with
;; `""` is the deliberate way to store an empty string on purpose. `set`
;; creates the environment's secrets file from an empty map when it doesn't
;; exist yet, which is what makes bootstrapping a brand-new environment
;; scriptable end to end. `rm` fails, rather than quietly doing nothing, when
;; the key or the file isn't there — a typo'd path is a mistake worth
;; catching. In both, `<key>` is an EDN keyword (`:some/key`) or a vector path
;; (`[:a :b]`), and both re-encrypt and refresh the manifest exactly like
;; `edit`.

;; ## A whole workflow, live

;; The interactive commands (`new`, `edit`) need an editor, but the rest run
;; fine here. Set up an environment in a temp directory:

(def dir (str (java.nio.file.Files/createTempDirectory
               "secrets-cli-" (into-array java.nio.file.attribute.FileAttribute []))))

(def config
  (cli/normalize-config
   {:app "cli-demo"
    :default-environment :dev
    :environments {:dev {:secrets-file (str dir "/secrets.edn.age")
                         :key-file     (str dir "/key.txt")}}}))

^{:kindly/hide-code true}
(age/keygen! (str dir "/key.txt"))

;; Create the encrypted file the way `bb secrets new` would, minus the editor:

(let [plain (str dir "/plain.edn")]
  (spit plain (pr-str {:api/token "t-123" :flags #{:beta}}))
  (age/encrypt-file! (str dir "/key.txt") plain (str dir "/secrets.edn.age"))
  (io/delete-file plain))

;; `reencrypt!` decrypts and re-encrypts to the current recipients, and as a
;; side effect writes the manifest. Watch the output lines; they are what you
;; would see in a terminal:

(cli/reencrypt! config "dev")

;; Now `verify!`. It returns data rather than exiting, which makes it as
;; useful from a REPL as from CI:

(cli/verify! config "dev")

;; The `:exit` value is what `bb secrets verify` exits with: 0 for a match, 1
;; for drift, 2 when something needed is missing. Drift and missing are
;; distinct codes so CI can tell "the secrets are wrong" from "this runner is
;; not provisioned".

;; `encrypt!` handles arbitrary files:

(do (spit (str dir "/service-account.json") "{\"type\": \"service_account\"}")
    (cli/encrypt! config "dev" (str dir "/service-account.json")))

;; ## Errors carry their remediation

;; Command functions throw `ex-info` with the exit code and any hints in the
;; data. The `run!` dispatcher is the only place that prints and exits, and it
;; prints the hint lines too, so a wrong key in a terminal shows the age
;; error, not a bare "failed". From a REPL you see the same information in
;; the exception:

(try
  (cli/verify! config "nope")
  (catch clojure.lang.ExceptionInfo e
    {:message (ex-message e) :data (ex-data e)}))

;; ## REPL safety, stated plainly

;; CLI tools love to call `System/exit` inside command functions, which turns
;; a REPL experiment into a dead REPL. Here the contract is: command functions
;; print their progress, but they never exit, and they always give back
;; something you can inspect: a path, a result map, `:aborted` from a
;; declined confirmation prompt. Only `run!`, the function your `bb.edn`
;; wires to the task, translates failures into process exit codes.

^{:kindly/hide-code true}
(doseq [f (reverse (file-seq (io/file dir)))]
  (.delete f))
