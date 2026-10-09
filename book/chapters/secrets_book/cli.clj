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

;; ## The initializer

;; The [quick start](secrets_book.quickstart.html#set-up-a-project) runs the
;; project initializer, `com.kirahowe.secrets.init`. It takes five options:

;; | Option | Meaning |
;; |--------|---------|
;; | `--app NAME` | the application name; required |
;; | `--env NAME` | the environment name; default `dev` |
;; | `--keygen` | also generate an age identity at `~/.config/<app>/key.txt` |
;; | `--apply` | create the files instead of previewing |
;; | `--help` | show usage |

;; An option's value is a separate argument: `--app myapp`, not `--app=myapp`.

;; Without `--apply` it prints what it would do and writes nothing. It only
;; ever creates files. What it does about `bb.edn` and `deps.edn` depends on
;; what the project already has:

;; | The project has | The initializer |
;; |-----------------|-----------------|
;; | neither file | creates a `bb.edn` with the library and the `secrets` task |
;; | a `bb.edn` | prints the dependency and the task for you to add |
;; | a `deps.edn` and no `bb.edn` | creates a `bb.edn` with the task and a `:local/root "."` dependency on the project, and prints the library entry to add to `deps.edn` |

;; In the last case the library is declared once, in `deps.edn`, and Babashka
;; reaches it through the project, so the JVM application and the task load
;; the same version. In every case it also creates the template,
;; `secrets/secrets.edn.example`, unless one is already there.

;; The app and environment names have to be plain: letters, digits, dots,
;; hyphens, and underscores, starting with a letter. If a file appears at a
;; path between the plan and the write, the run stops and leaves it alone.

;; The library coordinate it writes is the commit of the checkout it runs
;; from, with the release tag beside it when that commit is the tag. Run from
;; a published jar, it writes the jar's Maven version instead.

;; ## The config map

;; The task passes one map to `cli/run!`, from environment names to file
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

;; In that output, `:template` and `:manifest` are derived from the secrets
;; file name. `:key-file` is the path where `keygen` writes and `show-key`
;; reads. Normalization validates the configured paths and expands a leading
;; `~` in each. It does not read the identity environment variables or create
;; any file. Each command resolves its identity when it runs: the environment
;; variables, then `:key-file` or the app default. The
;; [runtime chapter](secrets_book.runtime.html#how-the-key-is-found) has the
;; full rule.

;; The [reference](secrets_book.reference.html#configuration-keys) lists every
;; key.

;; ## Validating the configuration {#validation-catches-the-dangerous-config}

;; `:app` is required. It names the default key path, and an implicit app name
;; could make unrelated projects share `~/.config/<app>/key.txt`.

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

;; A key the library doesn't know is an error too, at the top level and inside
;; an environment. A misspelled key would otherwise configure nothing and say
;; nothing:

(try
  (cli/normalize-config {:app "myapp"
                         :environments {:dev {:secrets-fle "s.edn.age"}}})
  (catch Exception e (ex-message e)))

;; Every environment setting is a path, so each value has to be a string.
;; `:manifest` may also be `false`, which keeps no manifest. `:manifest true`
;; is an error, where it could have been read as a silent "off":

(try
  (cli/normalize-config {:app "myapp"
                         :environments {:dev {:secrets-file "s.edn.age"
                                              :manifest true}}})
  (catch Exception e (ex-message e)))

;; `:environments` has to be a map from a keyword to a map, and
;; `:default-environment` has to name one of them. Paths have to be local
;; filesystem paths. A value that looks like a URI, and key contents pasted
;; where a path belongs, are refused without being printed.

;; No file may serve two purposes. Across all environments, a file is a
;; secrets file, a manifest, a template, an identity, or a recipients file,
;; and only one of them. Paths are compared in canonical form, so `key.txt`
;; and `./key.txt` are one file. Environments can share a template, a key or
;; identity file, or a recipients list. Two environments can name the same
;; secrets file or manifest only when they name both the same, which makes
;; them one store under two names:

(try
  (cli/normalize-config
   {:app "myapp"
    :environments {:dev {:secrets-file "dev.edn.age" :manifest "shared.manifest"}
                   :prod {:secrets-file "prod.edn.age" :manifest "shared.manifest"}}})
  (catch Exception e (ex-message e)))

;; ## The commands

;; | Command | Args | What it does |
;; |---------|------|--------------|
;; | `keygen` | `[env]` | generate the age key for an environment and print its public key |
;; | `new` | `[env]` | create a secrets file from a template, using `$VISUAL`, `$EDITOR`, or `vim` |
;; | `edit` | `[env]` | decrypt, edit, re-encrypt |
;; | `set` | `[env] <key> [--edn]` | set a key's value from a hidden prompt or stdin (creates the file if missing) |
;; | `rm` | `[env] <key>` | remove a key (fails if the key or file is absent) |
;; | `verify` | `[env]` | check the committed manifest against the secrets |
;; | `doctor` | `[env]` | report on the setup: age, the files, the identity, and the recipients |
;; | `show-key` | `[env]` | print public keys for sharing |
;; | `add-recipient` | `[env] [public-key]` | add a public key to the recipients file; a single argument that is a public key goes to the default environment, and any other single argument is the environment |
;; | `recipients` | `[env]` | list the configured recipient public keys |
;; | `reencrypt` | `[env]` | re-encrypt to the current recipients, with a new manifest key |
;; | `help` | `[command]` | show global or command-specific help |

;; Commands take the environment first, and omitting it uses
;; `:default-environment`. The CLI manages the configured stores only. To
;; encrypt or decrypt some other file, use `age` directly.

;; There is help for the whole task and for each command:

;; ```sh
;; bb secrets --help
;; bb secrets help set
;; bb secrets set --help
;; ```

;; Before a `--`, an argument that starts with a dash is an option, for every
;; command, and an option the command doesn't define is an error. Everything
;; after `--` is an argument, even one that looks like an option. Command
;; names are case sensitive.

;; A usage error prints the command's usage and never repeats the argument
;; that caused it. That covers an unknown command and an unknown environment
;; too. A value typed in the wrong place is the likeliest thing to end up
;; there, and it shouldn't be printed back to the terminal.

;; ### `new` and `edit`

;; Both open `$VISUAL`, then `$EDITOR`, then `vim`. A variable that is set but
;; blank counts as unset. The value may carry arguments, such as
;; `EDITOR="code --wait"`.

;; `new` starts from the environment's template when that file exists and from
;; a built-in placeholder otherwise. `edit` decrypts the store into an
;; owner-only temporary file and re-encrypts only if you changed the text.
;; Both encrypt the text you saved, so your comments survive. The store has to
;; be one EDN map, and that map has to be the first form in the file.

;; The store also holds metadata of the library's own, under the reserved
;; top-level key `:com.kirahowe.secrets/store`. The editor never shows it, and
;; a plaintext that comes back with that key typed in is refused. The
;; [manifest chapter](secrets_book.manifest.html#the-stores-manifest-key)
;; explains what it is for.

;; ### `set` and `rm`

;; `set` and `rm` don't open an editor. `set` never takes the value as a
;; command-line argument, so it isn't exposed in `ps` or shell history. From a
;; terminal it prompts for the value with echo turned off. When stdin is a pipe
;; or a file, as in a script or CI, it reads the whole input minus one trailing
;; newline. Values are stored verbatim as strings unless you pass `--edn`, in
;; which case the input is parsed as EDN and its type follows from the syntax,
;; so a set, number, or nested map is stored as that value. A blank value is
;; rejected, because a blank usually means an unset variable expanded to
;; nothing. To store an empty string on purpose, use `--edn` with `""`.
;;
;; Two things can still expose the value. If you type the value itself into a
;; `printf` command at an interactive shell, the shell saves that command, value
;; included, in its history. Use the prompt instead. If shell tracing (`set -x`)
;; is on, the shell prints each command with its variables expanded before
;; running it, so the value appears in the trace output. Turn tracing off before
;; the `set` line and back on after it.
;;
;; If the environment's secrets file doesn't exist yet, `set` creates it. This
;; makes it possible to bootstrap a new environment from a script. `rm` fails
;; when the key or file is absent. For both commands, `<key>` can be an EDN
;; keyword (`:some/key`) or a vector path (`[:a :b]`). A path that passes
;; through a value that isn't a map is refused, since there is nothing under a
;; string or a set to change. Both commands re-render the EDN, so plaintext
;; comments don't survive a `set` or `rm`.

;; ### What a write does {#what-a-write-does}

;; Every command that writes secrets first validates the complete plaintext,
;; encrypts it to a file beside the ciphertext, and renders the manifest.
;; Nothing has been replaced at that point, so an invalid edit leaves both
;; files as they were. The command then replaces the ciphertext with an atomic
;; rename, and then the manifest the same way.
;;
;; The two renames are not one transaction, and nothing is rolled back. The
;; ciphertext is the authoritative file and the manifest is derived from it.
;; If the manifest can't be replaced after the ciphertext was, the command
;; fails and says the manifest is stale. If the process dies between the two,
;; nothing reports it at the time. Either way `verify` shows the drift
;; afterwards, and `bb secrets reencrypt` regenerates the manifest.
;;
;; Each file is staged beside its target under a name like
;; `.secrets.edn.age.<uuid>.tmp` and deleted when the command ends. A command
;; that is killed can leave that file behind. It is safe to delete, and a
;; `.*.tmp` line in `.gitignore` keeps it out of a commit.
;;
;; The ciphertext, the manifest, and the recipients file are written with
;; ordinary file permissions, since they are meant to be committed. In team
;; mode the recipients file is read and validated once, before anything is
;; decrypted or an editor opens, and that exact list is what the store is
;; encrypted to.

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
(def public-key (age/keygen! (str dir "/key.txt")))

^:kindly/hide-code
(defn set-from-pipe!
  "Calls `cli/set-secret!` with `value` on stdin and no terminal attached."
  [config env k value edn?]
  (with-redefs-fn {#'cli/tty? (constantly false)}
    #(with-in-str value (cli/set-secret! config env k {:edn? edn?}))))

;; `set-from-pipe!` is a helper for this chapter. It calls `cli/set-secret!`
;; with a string on stdin, the way `printf %s t-123 | bb secrets set dev
;; :api/token` would. The first call creates the store and its manifest:

(set-from-pipe! config "dev" ":api/token" "t-123" false)

;; With `--edn`, the input is parsed:

(set-from-pipe! config "dev" ":flags" "#{:beta}" true)

;; This is the manifest those two writes left:

^:kindly/hide-code
(defn show-file [path]
  (println (slurp path)))

(show-file (str dir "/secrets.edn.manifest"))

;; `verify!` returns data instead of exiting, so the same function works from
;; a REPL or in CI:

(cli/verify! config "dev")

;; The `:exit` value is what `bb secrets verify` uses as its process status: 0
;; when everything agrees, and 1 when the only problem is drift. It is 2 when
;; anything else stopped the check: a missing ciphertext or manifest, an
;; identity that doesn't resolve, a store the identity can't decrypt, or a file
;; that can't be read. Such a failure is reported in that environment's line
;; and doesn't throw, and with no environment argument the other environments
;; are still checked. A CI job can tell a stale manifest (1) from a missing
;; key (2).

;; `remove-secret!` is `rm`:

(cli/remove-secret! config "dev" ":flags")

;; `reencrypt!` decrypts and re-encrypts to the current recipients. It also
;; gives the store a new manifest key, so every `:vhash` in the manifest is
;; different afterwards:

(cli/reencrypt! config "dev")

(show-file (str dir "/secrets.edn.manifest"))

;; `doctor!` is for finding out why a command won't run. It prints a short
;; report: whether age is installed, which files exist, which identity it
;; resolved and where that came from, and in team mode how many recipients
;; there are. It doesn't open the store or the manifest, which is `verify`'s
;; job, and it prints no file contents. It returns the report as a map:

(select-keys (cli/doctor! config "dev") [:identity :warnings :problems :exit])

;; A warning is something to act on that isn't an error, such as a file that
;; isn't there yet, and makes `:exit` 1. Here the key file is moved away, as
;; on a CI runner:

(def no-key-config
  (cli/normalize-config
   {:app "cli-demo"
    :default-environment :dev
    :environments {:dev {:secrets-file (str dir "/secrets.edn.age")
                         :key-file (str dir "/no-key-here.txt")}}}))

(select-keys (cli/doctor! no-key-config "dev") [:warnings :problems :exit])

;; A problem makes `:exit` 2: an identity that doesn't resolve, a recipients
;; file that lists nobody or holds an invalid line, an invalid configuration,
;; or an unknown environment.

;; A configured `:key-file` says where the key normally lives. When no file is
;; there, commands that need the key fail and say where they looked, and
;; `verify` checks what it can without one:

(cli/verify! no-key-config "dev")

;; ## Understanding errors {#errors-carry-their-remediation}

;; Command functions throw `ex-info`. The message says what to do next. The
;; data always has a `:reason` keyword to branch on, and may hold a `:hint`,
;; `:install`, `:error`, or `:docs` entry that `run!` prints under the
;; message. At the REPL, you can read the same information from the
;; exception:

(try
  (cli/verify! config "nope")
  (catch clojure.lang.ExceptionInfo e
    {:message (ex-message e) :data (ex-data e)}))

;; ## REPL safety

;; Command functions print progress but do not call `System/exit`. They return
;; a path, a result map, or `:aborted` after a declined confirmation prompt.
;; `verify!` and `doctor!` report most failures in their result, with the exit
;; code under `:exit`. Only `run!`, the entry point wired into `bb.edn`, exits
;; the process. It prints a failure as one line, without a stack trace, and
;; exits 1, or 2 when the command was `verify` or `doctor`. `run!` works as
;; the entry point of a JVM process as well as a Babashka task.

;; ## Size bounds

;; The CLI refuses a plaintext over 8 MiB, EDN nested more than 100
;; collections deep, a recipients file over 256 KiB, and a manifest over
;; 1 MiB. The bounds are fixed. They exist to catch an accident, such as a
;; path that names the wrong file, and a real store is nowhere near them.

^:kindly/hide-code
(doseq [f (reverse (file-seq (io/file dir)))]
  (.delete f))
