(ns com.kirahowe.secrets.cli
  "The `bb secrets` management task: a self-contained, dependency-free command
  dispatcher a host project wires into a single babashka task.

      ;; bb.edn
      {:deps  {com.kirahowe/secrets {:local/root \"../secrets\"}}
       :tasks {secrets {:task (com.kirahowe.secrets.cli/run! my-config *command-line-args*)}}}

  `my-config` describes the encrypted files per environment:

      {:app \"reader\"
       :default-environment :prod
       :environments
       {:prod {:secrets-file \"env/prod/resources/secrets.edn.age\"}
        :dev  {:secrets-file \"env/dev/resources/secrets.edn.age\"}}}

  Per-environment defaults fill in automatically:
    :key-file → ~/.config/<app>/key.txt   (one key per developer by default)
    :template → <secrets-file>.example     (secrets.edn.age → secrets.edn.example)
    :manifest → <secrets-file>.manifest    (secrets.edn.age → secrets.edn.manifest)

  Identity resolution separates two concerns per environment:
    :key-file      — the durable configured/default path above. `keygen` writes
                     here; `show-key` and `add-recipient` read the public key
                     from it.
    :identity-file — what decrypt-side operations (edit, decrypt, reencrypt,
                     verify) and single-key encryption use. Resolved in order:
                       1. $SECRETS_AGE_IDENTITY_FILE — a path to the key file
                       2. $SECRETS_AGE_IDENTITY      — raw key contents (→ 0600 temp file)
                       3. $SECRETS_AGE_IDENTITY_B64  — base64-encoded key contents
                       4. the environment's :key-file
                     So CI holding only an SECRETS_AGE_IDENTITY* variable can encrypt,
                     decrypt, and verify, while `keygen` still writes to the
                     configured key path.

  Optional per-environment keys:
    :recipients-file  path to a committed file of age public keys (one per
                      line). When set, the environment encrypts to *all* of
                      them, so each teammate can decrypt with their own key.
                      Absent ⇒ single-key mode (encrypt to own key).
    :manifest false   disable the manifest for this environment.

  Optional top-level key:
    :limits           bounds applied to untrusted inputs before any subprocess
                      starts, merged over `default-limits` and resolved onto
                      every environment.

  Commands: keygen · new · edit · set · rm · verify · doctor · show-key ·
  add-recipient · recipients · reencrypt · encrypt · decrypt · help.

  By default, each environment commits `secrets.edn.age` (ciphertext) and
  `secrets.edn.manifest` (key paths, types, counts, and optional keyed hashes).
  Editing uses an owner-only plaintext temp file and deletes it afterward on a
  best-effort basis.

  The command fns are a REPL-safe API: they return data (a path, a results
  map, or :aborted) and signal failures by throwing `ex-info` (carrying
  :secrets/exit) instead of exiting. `run!` — the CLI entry point — is the
  only fn here that prints error data and calls System/exit."
  (:refer-clojure :exclude [run!])
  (:require [clojure.java.io :as io]
            [clojure.java.shell :as shell]
            [clojure.pprint :as pprint]
            [clojure.string :as str]
            [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.fs :as fs]
            [com.kirahowe.secrets.manifest :as manifest]
            [com.kirahowe.secrets.safe-edn :as safe-edn]))

;;;; Generated shell commands

;;; Every command this namespace prints for an operator to paste is POSIX `sh`,
;;; and every value interpolated into one goes through `shell-quote`. The CLI
;;; never executes these strings itself; the hazard is the instruction handed
;;; to the operator, so the rendering is where it has to be fixed.

(defn- shell-quote
  "Render `s` as a single POSIX `sh` word: wrap it in `'`, splicing each
  embedded `'` as `'\\''`. The empty string renders as `''`, one empty word.

  Single quotes rather than backslash-escaping because inside `'…'` every
  character except `'` is literal. There is no metacharacter set to keep up to
  date and no interaction with `$`, backticks, `\\`, newlines, or globs —
  escaping would need a character class that is correct for every shell and
  every position, while this needs the one rule."
  [s]
  (str "'" (str/replace (str s) "'" "'\\''") "'"))

;;;; Output

(def ^:private ansi
  {:reset "\033[0m" :bold "\033[1m" :dim "\033[2m"
   :red "\033[31m" :green "\033[32m" :yellow "\033[33m" :blue "\033[34m"})

(defn- tty? [] (some? (System/console)))
(defn- paint [color s] (if (tty?) (str (ansi color) s (ansi :reset)) s))

(defn- info [& xs] (println (paint :blue "•") (str/join " " xs)))
(defn- ok [& xs] (println (paint :green "✓") (str/join " " xs)))
(defn- warn [& xs] (println (paint :yellow "⚠") (str/join " " xs)))
(defn- oops [& xs] (binding [*out* *err*] (println (paint :red "✗") (str/join " " xs))))

(defn- fail!
  "Throw an `ex-info` for a user-facing failure. `run!` catches these, prints
  the message (plus any :hint / :install / :error / :docs in the data), and
  exits with (:secrets/exit data 1) — command fns never kill the process (or
  a REPL) themselves."
  ([msg] (fail! msg {}))
  ([msg data] (throw (ex-info msg (merge {:secrets/exit 1} data)))))

(defn- confirm!
  "Prompt y/N; true on \"y\", false otherwise. Never exits — callers decide
  what a declined prompt means."
  [prompt]
  (print (str (paint :yellow "?") " " prompt " [y/N] "))
  (flush)
  (= "y" (some-> (read-line) str/trim str/lower-case)))

;;;; Config

(defn- canonical-path
  "Canonicalize `path`, so aliases like `./key.txt` and `key.txt` compare
  equal — used both for the artifact-collision check and for deciding which
  environments share a key file."
  [path]
  (.getCanonicalPath (io/file (str path))))

(defn- default-key-file
  "The app-wide default key path an environment falls back to when it has no
  explicit :key-file. One path per app, not one per environment: the common
  case is a single key per developer."
  [app]
  (secrets/expand-home (str "~/.config/" app "/key.txt")))

(def ^:private identity-env-sources
  [["SECRETS_AGE_IDENTITY_FILE" :secrets-age-identity-file]
   ["SECRETS_AGE_IDENTITY" :secrets-age-identity]
   ["SECRETS_AGE_IDENTITY_B64" :secrets-age-identity-b64]])

(def ^:private identity-source-display-label
  "How a message or a `doctor` report names where an identity came from."
  {:secrets-age-identity-file "SECRETS_AGE_IDENTITY_FILE"
   :secrets-age-identity "SECRETS_AGE_IDENTITY"
   :secrets-age-identity-b64 "SECRETS_AGE_IDENTITY_B64"
   :identity-file ":identity-file"
   :configured-key-file "configured key path"
   :default-key-file "default key path"})

(defn- getenv [variable-name]
  (System/getenv variable-name))

(defn- configured-identity-source
  "Name the first configured identity environment variable without retaining or
  returning its value. `identity-from-env` remains responsible for validation
  and materialization."
  []
  (some (fn [[variable source]]
          (when (some? (getenv variable)) source))
        identity-env-sources))

(def ^:private materialized-identity-sources
  "The identity sources `com.kirahowe.secrets` materializes into a temp file:
  both carry key *contents*, and `age` reads its identity from a file."
  #{:secrets-age-identity :secrets-age-identity-b64})

(defn- nameable-identity
  "The environment's decrypt-side identity path when a message may name it, else
  nil. A caller-supplied path — an env var naming a file, an explicit
  `:identity-file`, a configured or default key path — is the caller's own, and
  naming it is most of a failure's value. A path materialized from key contents
  is not: the caller never saw it, and it points at key material."
  [{:keys [identity-file identity-source]}]
  (when-not (materialized-identity-sources identity-source)
    (str identity-file)))

(defn- identity-location
  "Where a message says the environment's decrypt-side identity is: `at <path>`
  when the caller supplied that path, else `from <VARIABLE>` — the variable the
  key contents arrived in, never the temp path they were materialized to."
  [{:keys [identity-source] :as env}]
  (if-let [path (nameable-identity env)]
    (str "at " path)
    (str "from " (identity-source-display-label identity-source))))

(defn- decrypt-opts
  "The trailing `age` options for decrypting with this environment's identity:
  whether a failure may name the identity path and the resolved plaintext
  bound."
  [env]
  {:identity-nameable? (some? (nameable-identity env))
   :limits (select-keys (:limits env) [:max-plaintext-bytes])})

(def ^:private artifact-uri-scheme
  "A URI scheme at the start of a configured artifact location."
  #"^([A-Za-z][A-Za-z0-9+.\-]*):")

(def ^:private windows-absolute-path
  "A Windows drive path, which is not a URI locator."
  #"(?i)^[a-z]:[\\/]")

(defn- require-path!
  "Reject blank or URI-like artifact locations, returning `path` otherwise.

  CLI artifacts are filesystem paths only; accepting a locator here would create
  a second source contract beside `load-secrets`. Documented non-string values
  such as `:manifest false` retain their meaning, and Windows drive paths are
  paths rather than one-letter schemes."
  [env kind path]
  (when (and (string? path) (str/blank? path))
    (fail! (str "Environment " env " has a blank " kind " (a path string must not be empty).\n"
                "    An empty path resolves to the working directory, not a file.")
           {:environment env :field kind :path path}))
  (when-let [scheme (and (string? path)
                         (not (re-find windows-absolute-path path))
                         (second (re-find artifact-uri-scheme path)))]
    (fail! (str "Environment " env " " kind " must be a filesystem path, not a URI locator.")
           {:environment env
            :field kind
            :reason :disallowed-source-location
            :scheme (str/lower-case scheme)}))
  path)

(def ^:private artifact-roles
  "Every path-valued artifact role a command can touch. `:identity-file` is the
  *resolved* identity an environment carries — the value commands actually read
  — not only an explicitly configured one."
  [:secrets-file :manifest :template :key-file :recipients-file :identity-file])

(def ^:private compatible-role-sets
  "The only role combinations allowed to share one canonical path. Everything
  else is rejected: compatible sharing is enumerated here, never inferred from
  role names or matching path strings.

  - `#{:key-file :identity-file}`, or either role alone — one underlying
    identity artifact. `:identity-file` *defaults* to `:key-file`, so equality
    inside one environment is the normal case rather than an error, and
    `:key-file` defaults to one app-wide path, so several environments
    legitimately share one key ([[sharing-environments]] reports that set).
  - `#{:recipients-file}` alone — a committed list of public keys, read-only;
    one team list shared by several environments is ordinary.
  - `#{:template}` alone — a read-only example file; one template shared across
    environments is ordinary.

  `#{:secrets-file}` and `#{:manifest}` are deliberately absent: two
  environments writing one ciphertext, or one manifest, is a configuration bug."
  #{#{:key-file}
    #{:identity-file}
    #{:key-file :identity-file}
    #{:recipients-file}
    #{:template}})

(defn- artifact-canonical-path
  "`canonical-path` for a configured artifact, failing closed. `.getCanonicalPath`
  raises IOException on a path it cannot resolve; falling back to a string
  comparison there would let exactly the paths hardest to reason about skip the
  collision check, and an escaping IOException would surface unattributed."
  [environment-name role path]
  (try
    (canonical-path path)
    (catch java.io.IOException e
      (fail! (str "Environment " environment-name " has an unresolvable " (name role)
                  " path — " path "\n    " (ex-message e))
             {:environment environment-name :role role :path path}))))

(defn- artifact-entries
  "One entry — `{:environment :role :path :canonical}` — per path-valued
  artifact of a normalized environment. Non-string values are skipped, so
  `:manifest false` and an absent `:recipients-file` stay out of the table."
  [env]
  (into []
        (keep (fn [role]
                (let [path (get env role)]
                  (when (string? path)
                    {:environment (:name env)
                     :role role
                     :path path
                     :canonical (artifact-canonical-path (:name env) role path)}))))
        artifact-roles))

(defn- role-collision-message
  "Diagnostic for one canonical path carrying incompatible roles: every
  environment and role in the group, and only the pathnames the configuration
  already carried — never file contents."
  [canonical entries]
  (str "Configuration assigns one path to incompatible artifact roles:\n"
       "    " canonical "\n"
       (str/join "\n" (map (fn [{:keys [environment role path]}]
                             (str "      " environment " " (name role) " — " path))
                           entries))
       "\n    A path may be shared only as one identity/key artifact, one shared"
       "\n    recipients list, or one shared template."))

(defn- validate-artifact-roles!
  "Reject any canonical path carrying an incompatible combination of artifact
  roles, over every environment at once: checking environments independently
  accepted one environment's ciphertext path as another's key path.

  Canonicalization resolves the configuration as it reads now. This is a
  configuration check, not a defence against the filesystem changing
  afterwards — race-safe operation is a separate concern."
  [environments]
  (let [groups (->> (vals environments)
                    (mapcat artifact-entries)
                    (group-by :canonical)
                    (sort-by key))
        incompatible? (fn [[_ entries]]
                        (and (> (count entries) 1)
                             (not (compatible-role-sets (set (map :role entries))))))]
    (when-let [[canonical entries] (first (filter incompatible? groups))]
      (let [entries (vec (sort-by (juxt (comp name :environment) (comp name :role)) entries))]
        (fail! (role-collision-message canonical entries)
               {:canonical-path canonical :path-collision entries})))))

(def ^:private default-limits
  "Bounds applied to untrusted inputs before parsing or starting a subprocess,
  overridable through the top-level `:limits` config key. Runtime plaintext and
  EDN depth policy is shared rather than independently redefined here."
  (merge (select-keys secrets/default-limits
                      [:max-plaintext-bytes :max-edn-depth])
         {:max-recipients 256
          :max-recipient-chars 1024
          :max-recipients-bytes 262144
          :max-manifest-bytes 1048576
          :max-manifest-entries 10000}))

(defn- resolve-limits
  "Merge a configured `:limits` map over `default-limits`. Rejects anything a
  later read would silently see as a default: a non-map, an unknown key (a typo
  in a security limit must not read as \"unset\"), or a value that is not a
  positive integer."
  [limits]
  (when-not (or (nil? limits) (map? limits))
    (fail! "secrets config :limits must be a map of limit name → positive integer."
           {:limits limits}))
  (let [unknown (sort (remove (set (keys default-limits)) (keys limits)))]
    (when (seq unknown)
      (fail! (str "secrets config :limits has unknown key(s): "
                  (str/join ", " unknown) ".\n"
                  "    Known limits: "
                  (str/join ", " (sort (keys default-limits))) ".")
             {:limits limits :unknown-keys (vec unknown)})))
  (doseq [[limit value] limits]
    (when-not (and (integer? value) (pos? value))
      (fail! (str "secrets config :limits " limit " must be a positive integer, got "
                  (pr-str value) ".")
             {:limits limits :limit limit :value value})))
  (merge default-limits limits))

(defn- normalize-environment
  [{:keys [app limits]} environment-name
   {:keys [secrets-file key-file identity-file template manifest recipients-file]
    :as env-config}]
  (when-not (string? secrets-file)
    (fail! (str "Environment " environment-name
                " has no :secrets-file (a path string is required).")
           {:environment environment-name
            :env-config env-config}))
  (require-path! environment-name :secrets-file secrets-file)
  (when (and (not (str/ends-with? secrets-file ".age"))
             (not (and (contains? env-config :template)
                       (contains? env-config :manifest))))
    (fail! (str "Environment " environment-name " :secrets-file (" secrets-file
                ") does not end in .age, so the\n"
                "    derived :template/:manifest names would collide with — and overwrite — "
                "the\n"
                "    ciphertext itself. Use a .age extension, or set :template and :manifest\n"
                "    explicitly.")
           {:environment environment-name
            :secrets-file secrets-file}))
  (let [configured-key-file? (boolean key-file)
        configured-identity-file? (and (contains? env-config :identity-file)
                                       (some? identity-file))
        key-file (if configured-key-file?
                   (secrets/expand-home key-file)
                   (default-key-file app))
        explicit-identity (when configured-identity-file?
                            (secrets/expand-home identity-file))
        env-identity (secrets/identity-from-env)
        key-file-source (if configured-key-file? :configured :default)
        identity-source (or (when env-identity (configured-identity-source))
                            (when configured-identity-file? :identity-file)
                            (if configured-key-file?
                              :configured-key-file
                              :default-key-file))
        template (if (contains? env-config :template)
                   template
                   (str/replace secrets-file #"\.age$" ".example"))
        manifest (if (contains? env-config :manifest)
                   manifest
                   (str/replace secrets-file #"\.age$" ".manifest"))
        recipients-file (some-> recipients-file secrets/expand-home)]
    (doseq [[kind path] [[:key-file key-file]
                         [:identity-file explicit-identity]
                         [:template template]
                         [:manifest manifest]
                         [:recipients-file recipients-file]]]
      (require-path! environment-name kind path))
    (assoc env-config
           :name environment-name
           :app app
           :limits limits
           :secrets-file secrets-file
           :key-file key-file
           ;; Decrypt-side identity: SECRETS_AGE_IDENTITY* env vars win, then
           ;; an explicit :identity-file, then the configured/default key path.
           :identity-file (or env-identity explicit-identity key-file)
           :identity-source identity-source
           :key-file-source key-file-source
           ;; Explicit values (including :manifest false) are always kept;
           ;; absent values are derived from the secrets file.
           :template template
           :manifest manifest
           :recipients-file recipients-file)))

(defn normalize-config
  "Apply per-environment defaults (:key-file, :identity-file, :template,
  :manifest), resolve the input :limits, validate the configuration, and stamp
  each env with its :name and the resolved limits. Requires a non-blank :app,
  at least one environment, and a non-blank :secrets-file string per
  environment. A secrets path not ending in `.age` requires explicit :template
  and :manifest values. Every resolved artifact path is checked for role
  collisions across all environments before any command performs I/O. Throws
  ex-info on invalid input."
  [{:keys [app environments] :as config}]
  (when (empty? environments)
    (fail! "secrets config has no :environments" {:config config}))
  (when-not (and (string? app) (not (str/blank? app)))
    (fail! (str "secrets config has no :app (a name string is required). It names the\n"
                "    default key path ~/.config/<app>/key.txt and is recorded in the "
                "manifest,\n"
                "    so there is deliberately no default — projects must not share a key "
                "path\n"
                "    by accident.")
           {:config config}))
  (let [limits (resolve-limits (:limits config))
        normalized (reduce-kv (fn [normalized environment-name env-config]
                                (assoc normalized
                                       environment-name
                                       (normalize-environment {:app app :limits limits}
                                                              environment-name
                                                              env-config)))
                              {}
                              environments)]
    (validate-artifact-roles! normalized)
    (assoc config :limits limits :environments normalized)))

(defn- resolve-env
  "Resolve an environment argument string to its (defaulted) config map.
  Throws (via `fail!`) on a missing or unknown environment."
  [{:keys [environments default-environment]} env-arg]
  (let [env-key (cond
                  (and (nil? env-arg) default-environment) default-environment
                  (nil? env-arg) (fail! (str "Missing environment. One of: "
                                             (str/join ", " (map name (keys environments)))))
                  :else (keyword env-arg))]
    (or (environments env-key)
        (fail! (str "Unknown environment: " (name env-key) ". One of: "
                    (str/join ", " (map name (keys environments))))
               {:environment env-key}))))

;;;; Utilities

(defn- input-too-large!
  [kind limit-key configured observed context]
  (fail! (str kind " is larger than the configured " limit-key " limit of "
              configured " bytes.")
         (merge context
                {:reason :input-too-large
                 :limit limit-key
                 :configured configured
                 :observed observed
                 :bytes observed})))

(defn- read-bounded-bytes!
  "Read `in` under `max-bytes`, retaining at most the configured number of
  bytes. The read that detects overflow asks for only one byte beyond the
  remaining allowance, so `:observed` is stable and no oversized value is
  accumulated."
  [^java.io.InputStream in max-bytes kind limit-key context]
  (let [captured (java.io.ByteArrayOutputStream.)
        chunk (byte-array 8192)]
    (loop [total 0]
      (let [remaining (- max-bytes total)
            requested (int (min (alength chunk) (inc remaining)))
            n (.read in chunk 0 requested)]
        (if (neg? n)
          (.toByteArray captured)
          (let [observed (+ total n)]
            (when (> observed max-bytes)
              (.reset captured)
              (input-too-large! kind limit-key max-bytes observed context))
            (.write captured chunk 0 n)
            (recur observed)))))))

(defn- read-file-bounded!
  [path max-bytes kind limit-key context]
  (with-open [in (io/input-stream (io/file (str path)))]
    (String. ^bytes (read-bounded-bytes! in max-bytes kind limit-key context)
             java.nio.charset.StandardCharsets/UTF_8)))

(defn- read-reader-bounded!
  "Read character `reader` while bounding its UTF-8 representation. Counting is
  delegated to the JDK encoder, so multibyte characters and surrogate pairs use
  the same byte semantics as the resulting string."
  [^java.io.Reader reader max-bytes kind limit-key context]
  (let [total (volatile! 0)
        count-bytes! (fn [n]
                       (let [observed (+ @total n)]
                         (when (> observed max-bytes)
                           (input-too-large!
                            kind limit-key max-bytes observed context))
                         (vreset! total observed)))
        counter (proxy [java.io.OutputStream] []
                  (write
                    ([_b] (count-bytes! 1))
                    ([_bs _offset length] (count-bytes! length))))
        encoder (java.io.OutputStreamWriter.
                 counter java.nio.charset.StandardCharsets/UTF_8)
        captured (StringBuilder.)
        chunk (char-array 8192)]
    (loop []
      (let [n (.read reader chunk 0 (alength chunk))]
        (if (neg? n)
          (do
            (.close encoder)
            (.toString captured))
          (do
            (.write encoder chunk 0 n)
            (.flush encoder)
            (.append captured chunk 0 n)
            (recur)))))))

(defn- editor-value
  "The editor command to run, from the `VISUAL` value `visual` and the `EDITOR`
  value `editor`, falling back to `vim`. A variable that is set but blank counts
  as unset and falls through to the next source, so an empty `VISUAL` cannot
  shadow a working `EDITOR` or the default. Takes the values rather than reading
  them, so the rule is testable without setting process environment.

  Only leading and trailing blankness disqualifies a value: internal whitespace
  is meaningful, and `\"code --wait\"` or `\"emacsclient -t\"` comes back intact,
  arguments and all. Whitespace-only is rejected alongside empty because the
  shell drops both identically, which would leave the file being edited as the
  command word of [[editor-argv]].

  This is deliberately the opposite of `identity-env-value`, which throws on a
  set-but-blank identity variable. There every outcome is wrong but plausible:
  the blank value resolves to an empty key file, and falling through reaches the
  developer's local key while the deployment that variable was meant to
  configure stays broken. A blank editor variable has no such failure mode — the
  operator either watches the fallback editor open or gets a failure that leaves
  the store untouched, so falling through is safe here."
  [visual editor]
  (or (first (remove str/blank? [visual editor])) "vim"))

(defn- editor
  "`editor-value` applied to the live environment."
  []
  (editor-value (getenv "VISUAL") (getenv "EDITOR")))

(defn- editor-argv
  "The argv that runs editor command `command` on `path` through the shell.
  `path` is passed positionally rather than interpolated, so the shell treats it
  as data and it can never become part of the command."
  [command path]
  ["sh" "-c" (str command " \"$1\"") "editor" path])

(defn- run-editor!
  "Open `$VISUAL`/`$EDITOR` on `path`, inheriting the terminal. The editor value
  goes through the shell because it may carry arguments (\"code --wait\",
  \"emacsclient -t\"); the path is passed as a positional argument, not
  interpolated. An arbitrary editor would read a dash-leading path as its own
  option and `--` is not portable across editors, so `path` is made absolute
  before it reaches the editor. Throws if the editor exits non-zero, naming the
  editor command — a misconfigured one is otherwise indistinguishable from an
  editor that genuinely failed. The command is configuration, not a secret; the
  plaintext path stays out of the message."
  [path]
  (let [command (editor)
        path (.getAbsolutePath (io/file (str path)))
        proc (-> (ProcessBuilder. (into-array String (editor-argv command path)))
                 (.inheritIO)
                 (.start))]
    (when-not (zero? (.waitFor proc))
      (fail! (str "Editor exited with an error; leaving secrets unchanged."
                  " Editor: " command)))))

(defn- secure-delete!
  "Best-effort secure delete of a plaintext temp file. `rm`/`shred` receive
  `--` and an absolute path, which can neither begin with a dash nor be the
  bare `-` that `shred -u` rejects as a non-file — either one silently
  downgrades the overwrite to the plain `.delete` fallback below."
  [path]
  (let [f (io/file (str path))]
    (when (.exists f)
      (try
        (cond
          (str/starts-with? (System/getProperty "os.name") "Mac")
          (shell/sh "rm" "-P" "--" (.getAbsolutePath f))
          (zero? (:exit (shell/sh "sh" "-c" "command -v shred")))
          (shell/sh "shred" "-u" "--" (.getAbsolutePath f))
          :else (.delete f))
        (catch Exception _ (.delete f)))
      (when (.exists f) (.delete f)))))

(defn- temp-plaintext!
  "Create an owner-only (0600 from the moment it exists) temp file for
  plaintext secrets."
  []
  (fs/owner-only-temp-file! "secrets-" ".edn"))

(defn- distinct-by [f coll]
  (->> coll (group-by f) vals (map first)))

(defn- sha256 [path]
  (let [md (java.security.MessageDigest/getInstance "SHA-256")]
    (with-open [in (io/input-stream (io/file (str path)))]
      (let [buf (byte-array 8192)]
        (loop []
          (let [n (.read in buf)]
            (when (pos? n) (.update md buf 0 n) (recur))))))
    (apply str (map #(format "%02x" %) (.digest md)))))

(def ^:private default-template
  (str ";; Encrypted secrets (age). Edit with `bb secrets edit`; never commit the\n"
       ";; decrypted form. Values are plain EDN — strings, sets, nested maps, etc.\n"
       "{:example/api-key \"replace-me\"\n"
       " :example/allowed #{}}\n"))

(defn- template-content [{:keys [template limits]}]
  (let [f (io/file (str template))]
    (if (.exists f)
      (read-file-bounded! f (:max-plaintext-bytes limits)
                          "Template plaintext" :max-plaintext-bytes
                          {:template (str template)})
      default-template)))

(defn- require-age! []
  (when-not (age/installed?)
    (fail! (str "The `age` tool is not installed.\n"
                "    macOS:  brew install age\n"
                "    Ubuntu: apt install age\n"
                "    Docs:   https://age-encryption.org"))))

(defn- require-identity!
  "Ensure the environment's decrypt-side identity file exists.

  The failure names a caller-supplied path, which is the overwhelmingly common
  case and most of the message's value. A path materialized from
  SECRETS_AGE_IDENTITY / SECRETS_AGE_IDENTITY_B64 is named by the variable it
  came from instead: that path is a temp file holding key material, and the
  caller never saw it."
  [{environment-name :name :as env}]
  (when-not (.exists (io/file (:identity-file env)))
    (let [nameable (nameable-identity env)]
      (fail! (str "No age identity for " (clojure.core/name environment-name)
                  " " (identity-location env)
                  "\n"
                  "    Create one with:  bb secrets keygen "
                  (shell-quote (clojure.core/name environment-name)) "\n"
                  "    Or point at an existing key via SECRETS_AGE_IDENTITY_FILE (a path),\n"
                  "    SECRETS_AGE_IDENTITY (raw key contents), or "
                  "SECRETS_AGE_IDENTITY_B64 (base64 contents).")
             (cond-> {:environment environment-name}
               nameable (assoc :identity-file nameable))))))

;;;; Recipients (multi-recipient mode)

(defn- line-prefix
  "A short prefix of a rejected recipients line: enough to recognize the line,
  never the whole of whatever a hand edit put there."
  [s]
  (if (> (count s) 16) (str (subs s 0 16) "…") s))

(defn- recipient-entries
  "The `[line-number recipient]` pairs in `content`, numbered from 1 against the
  file as written, with blank lines and `#` comments dropped."
  [content]
  (->> (str/split-lines content)
       (map-indexed (fn [i line] [(inc i) (str/trim line)]))
       (remove (fn [[_ line]]
                 (or (str/blank? line) (str/starts-with? line "#"))))))

(defn- recipient-file-snapshot
  "Read one recipients file under the same byte and entry limits for every
  command. Returns its exact text plus numbered entries and recipient values,
  or nil when the file is absent."
  [{:keys [recipients-file limits] environment-name :name}]
  (let [{:keys [max-recipients max-recipients-bytes]} limits
        f (io/file (str recipients-file))]
    (when (.exists f)
      (let [content (read-file-bounded!
                     f max-recipients-bytes "Recipients file"
                     :max-recipients-bytes
                     {:recipients-file (str recipients-file)
                      :environment environment-name})
            entries (vec (recipient-entries content))
            observed (count entries)]
        (when (> observed max-recipients)
          (fail! (str "Recipients file " recipients-file " lists " observed
                      " recipients, exceeding the configured :max-recipients of "
                      max-recipients ".")
                 {:reason :too-many-recipients
                  :recipients-file (str recipients-file)
                  :environment environment-name
                  :count observed
                  :observed observed
                  :limit :max-recipients
                  :configured max-recipients}))
        {:content content
         :entries entries
         :recipients (mapv second entries)}))))

(defn- read-recipients [env]
  (:recipients (recipient-file-snapshot env)))

(defn- validate-recipient-entries!
  "Reject any entry age could not use: one longer than `:max-recipient-chars`,
  or one `age/valid-recipient?` refuses. Both name the 1-based line number and
  quote only a truncated prefix — a hand-edited line may hold anything, and a
  diagnostic is not the place to echo it."
  [{:keys [recipients-file] environment-name :name} entries max-recipient-chars]
  (let [label (clojure.core/name environment-name)]
    (doseq [[n line] entries]
      (when (> (count line) max-recipient-chars)
        (fail! (str "Recipient on line " n " of " recipients-file " (" label ") is "
                    (count line) " characters, exceeding the configured "
                    ":max-recipient-chars of " max-recipient-chars ".")
               {:recipients-file (str recipients-file) :line n
                :limit :max-recipient-chars :configured max-recipient-chars}))
      (when-not (age/valid-recipient? line)
        (fail! (str "Not a valid age recipient on line " n " of " recipients-file
                    " (" label "): " (pr-str (line-prefix line)) "\n"
                    "    Every line must be an age1… public key, an ssh-ed25519/ssh-rsa\n"
                    "    key, or a # comment.")
               {:recipients-file (str recipients-file) :line n
                :environment environment-name})))))

(defn- recipient-snapshot
  "Read the environment's recipients file exactly once and return the immutable
  vector of validated recipients to encrypt to, deduplicated in first-seen
  order.

  Reading once is the point. A pathname handed to age is read again inside age,
  and between a validating read and that one an editor session can run for
  minutes — long enough for anyone who can write the worktree to swap the list
  and choose the recipients (CWE-367). So everything the file says is decided
  here, before the sensitive work starts, and the resulting *values* are what
  gets encrypted to.

  Fails closed while streaming a file larger than `:max-recipients-bytes`, more
  entries than `:max-recipients`, an entry longer than
  `:max-recipient-chars`, an entry `age/valid-recipient?` rejects, or an empty
  result."
  [{:keys [recipients-file limits] environment-name :name :as env}]
  (let [{:keys [max-recipient-chars]} limits
        label (clojure.core/name environment-name)
        entries (or (:entries (recipient-file-snapshot env)) [])]
    (when (empty? entries)
      (fail! (str "No recipients yet for " label " in " recipients-file "\n"
                  "    Add one with:  bb secrets add-recipient "
                  (shell-quote label))
             {:recipients-file (str recipients-file)
              :environment environment-name}))
    (validate-recipient-entries! env entries max-recipient-chars)
    (vec (distinct (map second entries)))))

(defn- encrypt-target!
  "The immutable age recipient spec to encrypt with, resolved once before any
  sensitive work begins — before an editor opens, before stdin is read, before
  anything is decrypted — and threaded down to `age/encrypt-file!` from there.

  Multi-recipient mode returns the validated `{:recipients [\"age1…\" …]}`
  snapshot, so age receives repeated `-r` values and no pathname the worktree
  could redirect after validation. Single-key mode returns the environment's
  resolved `{:identity-file …}` (so SECRETS_AGE_IDENTITY* works in CI too); it
  has no separate file to race."
  [{:keys [recipients-file identity-file] :as env}]
  (if recipients-file
    {:recipients (recipient-snapshot env)}
    (do (require-identity! env)
        {:identity-file identity-file})))

;;;; Manifest

(defn- manifest-hmac-key
  "The manifest HMAC key for an environment: derived from the shared identity
  in single-key mode, nil in multi-recipient mode (no single shared key), so the
  manifest is structure-only for teams."
  [{:keys [recipients-file identity-file]}]
  (when (and (not recipients-file) (.exists (io/file identity-file)))
    (manifest/hmac-key (slurp identity-file))))

(defn- edn-location-message
  [{:keys [line column]}]
  (cond
    (and line column) (str " at line " line ", column " column)
    line (str " at line " line)
    column (str " at column " column)
    :else ""))

(defn- edn-failure-message
  [{:keys [reason depth limit] :as failure}]
  (case reason
    :edn-empty "expected one EDN value, found empty input"
    :edn-extra-values "expected one EDN value, found another"
    :edn-too-deep (str "EDN nesting depth " depth
                       " exceeds the configured :max-edn-depth of " limit)
    :edn-malformed (str "malformed EDN syntax" (edn-location-message failure))))

(defn- edn-failure-data
  [failure]
  (select-keys failure [:reason :line :column :depth :limit]))

(defn- validate-plaintext!
  "Parse all of `plaintext`, returning its EDN value. Fail before encryption
  when it is empty, malformed, contains more than one value, or exceeds the
  configured nesting depth."
  [secrets-file plaintext limits]
  (let [{:keys [ok? value] :as parsed} (safe-edn/parse plaintext limits)]
    (if ok?
      value
      (fail! (str "Secrets are not valid EDN (" (edn-failure-message parsed) ").\n"
                  "    Ciphertext and manifest were left unchanged.")
             (merge {:secrets-file (str secrets-file)}
                    (edn-failure-data parsed))))))

(defn- parse-key-path
  "Parse a `set`/`rm` CLI key argument as EDN into the vector `assoc-in` /
  `get-in` / `update-in` expect: a bare keyword becomes a one-element path,
  a vector of keywords/strings is a nested path. Rejects anything else —
  including a missing argument — with a `fail!` naming both accepted forms,
  so a typo'd path is caught before any file is touched."
  [s limits]
  (when (str/blank? (str s))
    (fail! (str "Missing key. Accepted forms: a keyword (:some/key) or a vector path "
                "([:a :b]).")))
  (let [{:keys [ok? value] :as parsed} (safe-edn/parse (str s) limits)]
    (when-not ok?
      (fail! (str "Invalid key: " (edn-failure-message parsed) ".\n"
                  "    Accepted forms: a keyword (:some/key) or a vector path "
                  "([:a :b]).")
             (edn-failure-data parsed)))
    (cond
      (keyword? value) [value]
      (and (vector? value)
           (seq value)
           (every? #(or (keyword? %) (string? %)) value))
      value
      :else (fail! (str "Invalid key: " (pr-str value) ".\n"
                        "    Accepted forms: a keyword (:some/key) or a vector path "
                        "([:a :b]).")
                   {:key value}))))

(defn- render-secrets
  "Render a secrets map as the plaintext `set`/`rm` re-encrypt. Pretty-printed
  so the file stays readable to the next `bb secrets edit`, and printed with
  the length/level limits unbound: a REPL that has set `*print-length*` would
  otherwise write `...` into the store and silently truncate secrets.

  Note the whole file is regenerated, so comments a human wrote in an edited
  store do not survive a `set` — the values do."
  [value]
  (binding [*print-length* nil *print-level* nil]
    (with-out-str (pprint/pprint value))))

(defn- strip-trailing-newline
  "Strip exactly one trailing newline (\\n or \\r\\n) from `s`, so
  `echo secret | bb secrets set …` stores the obvious value; anything else —
  including a value that itself ends with a blank line — passes through
  verbatim."
  [s]
  (cond
    (str/ends-with? s "\r\n") (subs s 0 (- (count s) 2))
    (str/ends-with? s "\n") (subs s 0 (- (count s) 1))
    :else s))

(defn- sibling-temp-file!
  "Create a temporary file beside `target`, ensuring an atomic move to the
  target is possible whenever the filesystem supports atomic moves."
  [target suffix]
  (let [target (.getAbsoluteFile (io/file (str target)))
        parent (.getParentFile target)]
    (.mkdirs parent)
    (.toFile
     (java.nio.file.Files/createTempFile
      (.toPath parent)
      (str "." (.getName target) ".") suffix
      (into-array java.nio.file.attribute.FileAttribute [])))))

(defn- atomic-replace!
  "Atomically replace `target` with the staged sibling file `source`."
  [source target]
  (try
    (java.nio.file.Files/move
     (.toPath (io/file source)) (.toPath (io/file target))
     (into-array java.nio.file.CopyOption
                 [java.nio.file.StandardCopyOption/ATOMIC_MOVE
                  java.nio.file.StandardCopyOption/REPLACE_EXISTING]))
    (catch Exception e
      ;; Babashka does not expose AtomicMoveNotSupportedException as a
      ;; resolvable class, so identify this one portable NIO exception by name.
      (if (= "java.nio.file.AtomicMoveNotSupportedException"
             (.getName (class e)))
        (throw (ex-info (str "The filesystem does not support an atomic secrets update for "
                             target)
                        {:source (str source) :target (str target)}
                        e))
        (throw e)))))

(defn- backup-target!
  "Copy an existing replacement target to a sibling temp file for rollback."
  [{:keys [target] :as replacement}]
  (let [target (io/file target)]
    (if-not (.exists target)
      (assoc replacement :existed? false)
      (let [backup (sibling-temp-file! target ".backup")]
        (try
          (java.nio.file.Files/copy
           (.toPath target) (.toPath backup)
           (into-array java.nio.file.CopyOption
                       [java.nio.file.StandardCopyOption/REPLACE_EXISTING
                        java.nio.file.StandardCopyOption/COPY_ATTRIBUTES]))
          (assoc replacement :existed? true :backup backup)
          (catch Exception e
            (.delete backup)
            (throw e)))))))

(defn- commit-replacements!
  "Commit staged sibling files with atomic moves. Existing targets are first
  copied to sibling rollback files so a later move failure restores every
  target already replaced during this commit."
  [replacements]
  (let [prepared (atom [])
        committed (atom [])]
    (try
      (doseq [replacement replacements]
        (swap! prepared conj (backup-target! replacement)))
      (try
        (doseq [{:keys [staged target] :as replacement} @prepared]
          (atomic-replace! staged target)
          (swap! committed conj replacement))
        (catch Exception commit-error
          (let [rollback-errors
                (reduce (fn [errors {:keys [target backup existed?]}]
                          (try
                            (if existed?
                              (atomic-replace! backup target)
                              (java.nio.file.Files/deleteIfExists
                               (.toPath (io/file target))))
                            errors
                            (catch Exception rollback-error
                              (conj errors (ex-message rollback-error)))))
                        [] (reverse @committed))]
            (throw (ex-info (if (seq rollback-errors)
                              "Could not commit the secrets update, and rollback also failed."
                              "Could not commit the secrets update; restored the previous files.")
                            (cond-> {:targets (mapv (comp str :target) replacements)}
                              (seq rollback-errors) (assoc :rollback-errors rollback-errors))
                            commit-error)))))
      (finally
        (doseq [{:keys [staged backup]} @prepared
                f [staged backup]
                :when f]
          (.delete (io/file f)))))))

(defn- write-secrets!
  "Validate `plaintext-file`, then stage its ciphertext — encrypted to the
  already-resolved `target` recipient spec, never to a pathname re-read here —
  and optional manifest beside their destinations, and commit both through
  atomic replacements."
  [{:keys [manifest app secrets-file limits] :as env} target plaintext-file]
  (let [plaintext (read-file-bounded!
                   plaintext-file (:max-plaintext-bytes limits)
                   "Secrets plaintext" :max-plaintext-bytes
                   {:secrets-file (str secrets-file)})
        value (validate-plaintext! secrets-file plaintext limits)
        ciphertext-temp (sibling-temp-file! secrets-file ".age.tmp")
        manifest-temp (when (string? manifest)
                        (sibling-temp-file! manifest ".manifest.tmp"))]
    (try
      (age/encrypt-file! target plaintext-file ciphertext-temp)
      (when manifest-temp
        (spit manifest-temp
              (manifest/render {:app app :ciphertext-sha (sha256 ciphertext-temp)}
                               (manifest/entries value (manifest-hmac-key env)))))
      (commit-replacements!
       (cond-> [{:staged ciphertext-temp :target (io/file secrets-file)}]
         manifest-temp (conj {:staged manifest-temp :target (io/file manifest)})))
      (finally
        (.delete ciphertext-temp)
        (when manifest-temp (.delete manifest-temp))))))

(defn- append-recipient!
  "Atomically replace recipients file `f` with already-bounded `content`."
  [f content]
  (let [tmp (sibling-temp-file! f ".recipients.tmp")]
    (try
      (spit tmp content)
      (atomic-replace! tmp f)
      (finally (.delete tmp)))))

;;;; Commands

(defn- sharing-environments
  "Every environment name (sorted) whose :key-file canonically resolves to the
  same file as `key-file`. :key-file defaults to one app-wide path rather than
  one per environment, so more than one environment routinely shares a single
  key; keygen! reports this set after writing so that naming one environment
  on the command line does not read as having made a key just for it."
  [environments key-file]
  (let [target (canonical-path key-file)]
    (->> (vals environments)
         (filter #(= target (canonical-path (:key-file %))))
         (map :name)
         (sort-by name))))

(defn- sole-shared-environment
  "When every configured environment's :key-file resolves to the same file, an
  environment argument cannot change keygen!'s outcome, so return that
  (arbitrary) environment rather than making the caller pick one. Returns nil
  when environments differ, leaving resolve-env's ambiguity error in place."
  [{:keys [environments]}]
  (let [envs (vals environments)]
    (when (apply = (map (comp canonical-path :key-file) envs))
      (first envs))))

(defn keygen!
  "Generate an age identity at an environment's key-file. Returns the key-file
  path, or :aborted when an existing key is kept.

  The default key path is app-wide, so the function reports every environment
  that shares it. With no environment or default, generation proceeds only
  when all configured environments resolve to the same key path; otherwise it
  throws. Existing keys require confirmation before replacement."
  [config env-arg]
  (require-age!)
  (let [{:keys [key-file recipients-file] environment-name :name}
        (or (when (and (nil? env-arg) (nil? (:default-environment config)))
              (sole-shared-environment config))
            (resolve-env config env-arg))
        proceed? (or (not (.exists (io/file key-file)))
                     (do
                       (warn "Key already exists:" key-file)
                       (confirm!
                        "Overwrite? Existing secrets encrypted to it become UNREADABLE.")))]
    (if-not proceed?
      (do (info "Aborted.") :aborted)
      (do
        (info "Generating age key for" (clojure.core/name environment-name) "…")
        (let [pub (age/keygen! key-file)
              sharing (sharing-environments (:environments config) key-file)
              app-default? (= (canonical-path key-file)
                              (canonical-path (default-key-file (:app config))))]
          (ok "Key written:" key-file)
          (println
           (str "    Used by: " (str/join ", " (map clojure.core/name sharing))
                (when app-default?
                  " — every environment without its own :key-file")))
          (println)
          (println (paint :bold "  Public key:") pub)
          (println)
          (warn "Back this key up (e.g. a password manager). It is NOT in git and")
          (println
           "    cannot be recovered. To deploy, set it as the SECRETS_AGE_IDENTITY secret:")
          (println
           (paint :dim
                  ;; `cat --` for the same reason `age`, `rm`, and `shred`
                  ;; get one: a key file named `-n` or `--help` has to reach
                  ;; cat as a pathname. The surrounding "$(…)" is the
                  ;; shell's own construct, not interpolated data, and is
                  ;; what makes the file contents one argument to flyctl.
                  (str "      flyctl secrets set SECRETS_AGE_IDENTITY=\"$(cat -- "
                       (shell-quote key-file)
                       ")\"")))
          (when recipients-file
            (println)
            (info "This project encrypts to a shared recipients file. Add your public")
            (println "    key so teammates encrypt secrets you can read:")
            (println
             (paint :dim
                    (str "      bb secrets add-recipient "
                         (shell-quote (clojure.core/name environment-name))))))
          key-file)))))

(defn new!
  "Create an encrypted secrets file from its template using $VISUAL, $EDITOR,
  or vim. Returns the secrets-file path, or :aborted when an existing file is
  kept. Plaintext is held in an owner-only temp file during editing."
  [config env-arg]
  (require-age!)
  (let [{:keys [secrets-file] environment-name :name :as env}
        (resolve-env config env-arg)
        target (encrypt-target! env)
        proceed? (or (not (.exists (io/file secrets-file)))
                     (do
                       (warn "Secrets file already exists:" secrets-file)
                       (confirm!
                        (str "Overwrite it? (To change values, use `bb secrets edit "
                             (shell-quote (clojure.core/name environment-name))
                             "` instead.)"))))]
    (if-not proceed?
      (do (info "Aborted.") :aborted)
      (let [tmp (temp-plaintext!)]
        (try
          (spit tmp (template-content env))
          (info "Opening" (editor) "…")
          (run-editor! tmp)
          (info "Encrypting…")
          (write-secrets! env target tmp)
          (ok "Encrypted secrets written:" secrets-file)
          (when (string? (:manifest env))
            (info "Manifest updated:" (:manifest env)))
          secrets-file
          (finally (secure-delete! tmp)))))))

(defn edit!
  "Edit an existing secrets file through an owner-only plaintext temp file.
  Re-encrypts only when the plaintext changes and deletes the temp file on a
  best-effort basis. Returns the secrets-file path."
  [config env-arg]
  (require-age!)
  (let [{:keys [secrets-file identity-file] environment-name :name :as env}
        (resolve-env config env-arg)]
    (require-identity! env)
    (when-not (.exists (io/file secrets-file))
      (fail! (str "No secrets file at " secrets-file "\n"
                  "    Create one with:  bb secrets new "
                  (shell-quote (clojure.core/name environment-name)))
             {:secrets-file secrets-file
              :environment environment-name}))
    (let [target (encrypt-target! env)
          tmp (temp-plaintext!)]
      (try
        (info "Decrypting" secrets-file "…")
        (age/decrypt-to-file! identity-file secrets-file tmp (decrypt-opts env))
        (let [before (sha256 tmp)]
          (run-editor! tmp)
          (if (= before (sha256 tmp))
            (warn "No changes — leaving" secrets-file "untouched.")
            (do
              (info "Re-encrypting…")
              (write-secrets! env target tmp)
              (ok "Secrets updated:" secrets-file)
              (when (string? (:manifest env))
                (info "Manifest updated:" (:manifest env))))))
        secrets-file
        (finally (secure-delete! tmp))))))

(defn set-secret!
  "Set a value read from stdin. `key-arg` is a keyword or a non-empty vector of
  keyword/string path elements. One trailing newline is removed. The value is
  a string unless `edn?` is true, in which case stdin must contain one EDN
  value. Blank input is rejected. Creates a missing secrets file from an empty
  map, then re-encrypts and updates the manifest. Returns the secrets-file
  path. Re-rendering removes plaintext comments."
  [config env-arg key-arg edn?]
  (require-age!)
  (let [env (resolve-env config env-arg)
        path (parse-key-path key-arg (:limits env))
        {:keys [secrets-file identity-file]} env
        exists? (.exists (io/file secrets-file))]
    (when exists? (require-identity! env))
    (let [target (encrypt-target! env)
          raw (strip-trailing-newline
               (read-reader-bounded!
                *in* (get-in env [:limits :max-plaintext-bytes])
                "Standard input" :max-plaintext-bytes
                {:environment (:name env) :key path}))
          _ (when (str/blank? raw)
                  ;; The same rule the library applies to a set-but-empty
                  ;; SECRETS_AGE_IDENTITY: blank almost always means an unset
                  ;; variable expanded to nothing (`echo "$KEY" | bb secrets
                  ;; set …` in CI), and storing it produces a secret that
                  ;; fails much later, far from the cause.
              (fail! (str "Nothing on stdin — refusing to store a blank value for "
                          (pr-str path) ".\n"
                          "    Pipe the value in:  printf %s \"$VALUE\" | bb secrets set …\n"
                          "    To store an empty value deliberately, use --edn with \"\".")
                     {:key path}))
          value (if edn?
                  (let [{:keys [ok? value] :as parsed}
                        (safe-edn/parse raw (:limits env))]
                    (if ok?
                      value
                      (fail! (str "Value on stdin is not valid EDN ("
                                  (edn-failure-message parsed) ").")
                             (merge {:key path} (edn-failure-data parsed)))))
                  raw)
          tmp (temp-plaintext!)]
      (try
        (let [current (if exists?
                        (do (info "Decrypting" secrets-file "…")
                            (let [{:keys [ok? value] :as parsed}
                                  (safe-edn/parse
                                   (age/decrypt identity-file secrets-file
                                                (decrypt-opts env))
                                   (:limits env))]
                              (if ok?
                                value
                                (fail! (str "Secrets are not valid EDN ("
                                            (edn-failure-message parsed) ").")
                                       (merge {:secrets-file secrets-file}
                                              (edn-failure-data parsed))))))
                        (do (info "No secrets file at" secrets-file "— creating it.")
                            {}))]
          (spit tmp (render-secrets (assoc-in current path value)))
          (info (if exists? "Re-encrypting…" "Encrypting…"))
          (write-secrets! env target tmp)
          (ok "Set" (pr-str path) "in" secrets-file)
          (when (string? (:manifest env)) (info "Manifest updated:" (:manifest env)))
          secrets-file)
        (finally (secure-delete! tmp))))))

(defn remove-secret!
  "Remove a keyword or vector key path, then re-encrypt and update the
  manifest. Throws when the file or path is absent. Empty parent maps are not
  pruned. Returns the secrets-file path. Re-rendering removes plaintext
  comments."
  [config env-arg key-arg]
  (require-age!)
  (let [env (resolve-env config env-arg)
        path (parse-key-path key-arg (:limits env))
        {:keys [secrets-file identity-file] environment-name :name} env]
    (require-identity! env)
    (when-not (.exists (io/file secrets-file))
      (fail! (str "No secrets file at " secrets-file "\n"
                  "    Create one with:  bb secrets new "
                  (shell-quote (clojure.core/name environment-name)) "\n"
                  "    or:               bb secrets set "
                  (shell-quote (clojure.core/name environment-name)) " "
                  ;; A string `key-arg` already is the EDN text argv
                  ;; carried; any other accepted value is printed to get
                  ;; that text back.
                  (shell-quote (if (string? key-arg) key-arg (pr-str key-arg))))
             {:secrets-file secrets-file
              :environment environment-name}))
    (let [target (encrypt-target! env)
          tmp (temp-plaintext!)]
      (try
        (info "Decrypting" secrets-file "…")
        (let [{:keys [ok? value] :as parsed}
              (safe-edn/parse
               (age/decrypt identity-file secrets-file (decrypt-opts env))
               (:limits env))
              current (if ok?
                        value
                        (fail! (str "Secrets are not valid EDN ("
                                    (edn-failure-message parsed) ").")
                               (merge {:secrets-file secrets-file}
                                      (edn-failure-data parsed))))]
          (when (= ::missing (get-in current path ::missing))
            (fail! (str "No such key: " (pr-str path) " in " secrets-file)
                   {:secrets-file secrets-file :key path}))
          (let [parent (butlast path)
                k (last path)
                updated (if (seq parent)
                          (update-in current (vec parent) dissoc k)
                          (dissoc current k))]
            (spit tmp (render-secrets updated))
            (info "Re-encrypting…")
            (write-secrets! env target tmp)
            (ok "Removed" (pr-str path) "from" secrets-file)
            (when (string? (:manifest env))
              (info "Manifest updated:" (:manifest env)))
            secrets-file))
        (finally (secure-delete! tmp))))))

(defn show-key!
  "Print the public key(s) — share these so teammates can encrypt to you.
  Reads the configured :key-file (not the env-var identity). Returns a map of
  env name → public key (nil when the key is missing); environments sharing a
  :key-file are reported once, under whichever env is seen first."
  [config env-arg]
  (require-age!)
  (let [envs (if env-arg
               [(resolve-env config env-arg)]
               (vals (:environments config)))]
    (into {}
          (map (fn [{:keys [key-file] environment-name :name}]
                 (let [pub (age/public-key key-file)]
                   (if pub
                     (println
                      (format "  %-6s %s"
                              (str (clojure.core/name environment-name) ":")
                              pub))
                     (warn
                      (format "%s: no key at %s"
                              (clojure.core/name environment-name)
                              key-file)))
                   [environment-name pub])))
          (distinct-by :key-file envs))))

(defn encrypt!
  "Encrypt an arbitrary plaintext file to <file>.age using an environment's
  recipients (its recipients file, or its own identity in single-key mode).
  Returns the ciphertext path."
  [config env-arg file]
  (require-age!)
  (let [env (resolve-env config env-arg)
        target (encrypt-target! env)]
    (when-not (and file (.exists (io/file file)))
      (fail! (str "No such file: " file) {:file file}))
    (let [out (str file ".age")]
      (age/encrypt-file! target file out)
      (ok "Encrypted:" out)
      out)))

(def ^:private max-arbitrary-plaintext-bytes
  "Plaintext bound for `decrypt!`, the general-purpose file command (1 GiB).

  Deliberately far above `secrets/default-limits`' 8 MiB, which bounds a
  secrets store rather than an arbitrary operator-named file. The output is
  streamed in fixed-size chunks, so this is a deliberate command policy and
  subprocess bound, not the size of a contiguous heap allocation."
  1073741824)

(defn decrypt!
  "Decrypt a <file>.age to stdout, byte-for-byte (binary-safe; plaintext is
  never written to disk). Returns the input path.

  Bounded by `max-arbitrary-plaintext-bytes`, not by the tighter secrets-store
  limit: this command decrypts whatever file it is given."
  [config env-arg file]
  (require-age!)
  (let [env (resolve-env config env-arg)]
    (require-identity! env)
    (when-not (and file (.exists (io/file file)))
      (fail! (str "No such file: " file) {:file file}))
    (age/decrypt-to-stream!
     (:identity-file env) file System/out
     (assoc (decrypt-opts env)
            :limits {:max-plaintext-bytes max-arbitrary-plaintext-bytes}))
    (.flush System/out)
    file))

(defn reencrypt!
  "Decrypt and immediately re-encrypt to the environment's current recipients —
  use after adding or removing a recipient (an `edit` with no change is a no-op
  and would not pick up recipient changes). The recipient list is snapshotted
  before the decryption, so it is exactly the list the command was started
  against. Rewrites the manifest too. Returns the secrets-file path."
  [config env-arg]
  (require-age!)
  (let [{:keys [secrets-file identity-file] environment-name :name :as env}
        (resolve-env config env-arg)]
    (require-identity! env)
    (when-not (.exists (io/file secrets-file))
      (fail! (str "No secrets file at " secrets-file "\n"
                  "    Create one with:  bb secrets new "
                  (shell-quote (clojure.core/name environment-name)))
             {:secrets-file secrets-file
              :environment environment-name}))
    (let [target (encrypt-target! env)
          tmp (temp-plaintext!)]
      (try
        (info "Decrypting" secrets-file "…")
        (age/decrypt-to-file! identity-file secrets-file tmp (decrypt-opts env))
        (info "Re-encrypting to current recipients…")
        (write-secrets! env target tmp)
        (ok "Re-encrypted:" secrets-file)
        (when (string? (:manifest env))
          (info "Manifest updated:" (:manifest env)))
        secrets-file
        (finally (secure-delete! tmp))))))

(defn add-recipient!
  "Add an age public key to an environment's recipients file. With no key given,
  adds the environment's own public key (from its key-file). Returns the
  recipient added (or already present)."
  [config env-arg pubkey]
  (require-age!)
  (let [{:keys [recipients-file key-file secrets-file limits]
         environment-name :name :as env}
        (resolve-env config env-arg)
        environment-label (clojure.core/name environment-name)]
    (when-not recipients-file
      (fail! (str environment-label
                  " has no :recipients-file configured (single-key mode).\n"
                  "    Add :recipients-file to its config to encrypt to multiple people.")
             {:environment environment-name}))
    (let [pub (or pubkey (age/public-key key-file))]
      (when-not pub
        (fail! (str "No public key given and no key at " key-file "\n"
                    "    Generate one with:  bb secrets keygen "
                    (shell-quote environment-label))
               {:key-file key-file
                :environment environment-name}))
      (let [pub (str/trim pub)
            pub-chars (count pub)]
        (when (> pub-chars (:max-recipient-chars limits))
          (fail! (str "Recipient argument is " pub-chars
                      " characters, exceeding the configured "
                      ":max-recipient-chars of " (:max-recipient-chars limits) ".")
                 {:reason :recipient-too-long
                  :environment environment-name
                  :observed pub-chars
                  :limit :max-recipient-chars
                  :configured (:max-recipient-chars limits)}))
        (when-not (age/valid-recipient? pub)
          (fail! "Not a valid age public key." {:reason :invalid-recipient}))
        (let [snapshot (recipient-file-snapshot env)
              existing (or (:recipients snapshot) [])]
          (if (some #{pub} existing)
            (do
              (info "Already a recipient of" (str environment-label ":") pub)
              pub)
            (let [f (io/file (str recipients-file))
                  observed (inc (count existing))
                  current (:content snapshot)
                  content (str current
                               (when (and (seq current)
                                          (not (str/ends-with? current "\n")))
                                 "\n")
                               pub "\n")
                  bytes (alength (.getBytes content
                                            java.nio.charset.StandardCharsets/UTF_8))]
              (when (> observed (:max-recipients limits))
                (fail! (str "Adding a recipient would exceed the configured "
                            ":max-recipients of " (:max-recipients limits) ".")
                       {:reason :too-many-recipients
                        :recipients-file (str recipients-file)
                        :environment environment-name
                        :count observed
                        :observed observed
                        :limit :max-recipients
                        :configured (:max-recipients limits)}))
              (when (> bytes (:max-recipients-bytes limits))
                (input-too-large!
                 "Updated recipients file" :max-recipients-bytes
                 (:max-recipients-bytes limits) bytes
                 {:recipients-file (str recipients-file)
                  :environment environment-name}))
              (append-recipient! f content)
              (ok "Added recipient to" recipients-file)
              (println "   " pub)
              (if (.exists (io/file secrets-file))
                (do
                  (warn "Re-encrypt so the new recipient can read existing secrets:")
                  (println
                   (paint :dim
                          (str "      bb secrets reencrypt "
                               (shell-quote environment-label)))))
                (do
                  (info "No ciphertext exists yet. Create the initial store with either:")
                  (println
                   (paint :dim
                          (str "      printf %s \"$VALUE\" | bb secrets set "
                               (shell-quote environment-label)
                               " :secret/key")))
                  (println
                   (paint :dim
                          (str "      bb secrets new "
                               (shell-quote environment-label))))))
              pub)))))))

(defn recipients!
  "List the recipients an environment encrypts to. Returns them as an eager seq
  (nil in single-key mode). Read-only and non-failing: a line encryption would
  reject is listed but marked, because listing it as a plain recipient would
  read as an assurance the write path does not give it."
  [config env-arg]
  (let [{:keys [recipients-file] environment-name :name :as env}
        (resolve-env config env-arg)
        environment-label (clojure.core/name environment-name)]
    (if-not recipients-file
      (do
        (info environment-label
              "is in single-key mode — it encrypts to its own key, not a recipients list.")
        nil)
      (let [recipients (read-recipients env)]
        (if (empty? recipients)
          (warn "No recipients yet in" recipients-file)
          (do
            (println
             (paint :bold
                    (str "Recipients for " environment-label " (" recipients-file "):")))
            (doseq [recipient recipients]
              (println "  " (if (age/valid-recipient? recipient)
                              recipient
                              (str recipient " "
                                   (paint :yellow
                                          "← invalid; encryption refuses this line")))))))
        recipients))))

(defn- enforce-manifest-entry-limit!
  [manifest-path value {:keys [max-manifest-entries]}]
  (let [observed (if (map? (:keys value)) (count (:keys value)) 0)]
    (when (> observed max-manifest-entries)
      (fail! (str "Manifest " manifest-path " contains " observed
                  " entries, exceeding the configured :max-manifest-entries of "
                  max-manifest-entries ".")
             {:reason :too-many-manifest-entries
              :manifest (str manifest-path)
              :count observed
              :observed observed
              :limit :max-manifest-entries
              :configured max-manifest-entries}))))

(defn- read-manifest-bounded!
  [manifest-path {:keys [max-manifest-bytes]}]
  (read-file-bounded! manifest-path max-manifest-bytes
                      "Manifest" :max-manifest-bytes
                      {:manifest (str manifest-path)}))

(defn- bounded-state
  [e]
  (let [data (ex-data e)]
    (when (contains? #{:input-too-large :too-many-recipients
                       :too-many-manifest-entries}
                     (:reason data))
      (merge {:state :bounded}
             (select-keys data
                          [:reason :limit :configured :observed :bytes :count])))))

(defn- read-supported-manifest
  "The committed manifest at `manifest-path`, or a `:status` when it cannot be
  compared at all.

  Two gates, both of which reject rather than diff. The `:version` gate keeps a
  v1 hash from ever being read as a v2 one. The `:app` gate is the wrong-app
  half of the authenticity contract: `:app` is the one field the manifest
  records about *which store it describes*, and without checking it a manifest
  written for another app whose key paths happen to agree is diffed as a shape.
  Single-key mode would usually still catch that on a `:vhash` derived from
  different key material, but a team manifest carries no `:vhash` at all, so a
  refreshed `:ciphertext-sha` would otherwise verify clean."
  [environment-label expected-app manifest-path limits]
  (let [parsed (safe-edn/parse (read-manifest-bounded! manifest-path limits) limits)
        value (:value parsed)
        _ (when (:ok? parsed)
            (enforce-manifest-entry-limit! manifest-path value limits))
        version (:version value)
        app (:app value)]
    (cond
      (not (:ok? parsed))
      (do
        (oops environment-label "— manifest is not valid EDN:"
              (edn-failure-message parsed))
        {:status :drift})

      (not= 2 version)
      (do
        (oops environment-label
              "— manifest version"
              (pr-str version)
              "is unsupported by this version of the library.")
        (println
         (str "    Regenerate it with `bb secrets reencrypt "
              (shell-quote environment-label)
              "`, or upgrade the library."))
        {:status :drift})

      (not= expected-app app)
      (do
        (oops environment-label
              "— manifest describes app"
              (pr-str app)
              (str "but this project is " (pr-str expected-app) "."))
        (println
         (str "    It belongs to a different store. Regenerate it with "
              "`bb secrets reencrypt " (shell-quote environment-label) "`."))
        {:status :drift})

      :else
      {:committed (:value parsed)})))

(defn- verify-keyless
  "Verify freshness without a key. `identity-location` is where a message may say
  the missing identity is — `at <path>` when the caller supplied that path, else
  `from <VARIABLE>`, never a path this library materialized."
  [environment-label secrets-file manifest-path identity-location committed]
  (let [ciphertext-sha (:ciphertext-sha committed)]
    (cond
      (nil? ciphertext-sha)
      (do
        (warn environment-label
              (str "— no identity " identity-location)
              "and the manifest records no :ciphertext-sha; cannot verify.")
        :missing)

      (= ciphertext-sha (sha256 secrets-file))
      (do
        (ok environment-label
            "— ciphertext agrees with the manifest"
            "(freshness only: no key, so values are not checked).")
        :ok-keyless)

      :else
      (do
        (oops environment-label
              "— ciphertext changed since the manifest was written"
              (str "(" manifest-path ")."))
        (println (str "    Regenerate with:  bb secrets reencrypt "
                      (shell-quote environment-label)))
        :drift))))

(defn- verify-keyed-diff
  [environment-label
   {:keys [secrets-file manifest identity-file] :as env}
   committed]
  (let [{:keys [ok? value] :as parsed}
        (safe-edn/parse
         (age/decrypt identity-file secrets-file (decrypt-opts env))
         (:limits env))]
    (if-not ok?
      (do
        (oops environment-label "— encrypted secrets are not valid EDN:"
              (edn-failure-message parsed))
        :drift)
      (let [fresh (manifest/entries value (manifest-hmac-key env))
            manifest-diff (manifest/diff (:keys committed) fresh)
            stale-entries? (not (every? empty? (vals manifest-diff)))
            ciphertext-sha (:ciphertext-sha committed)
            stale-sha? (and ciphertext-sha
                            (not= ciphertext-sha (sha256 secrets-file)))]
        (when stale-entries?
          (oops environment-label "— manifest is STALE" (str "(" manifest "):"))
          (doseq [path (:added manifest-diff)]
            (println "    +" (pr-str path) "— in secrets, missing from manifest"))
          (doseq [path (:removed manifest-diff)]
            (println "    -" (pr-str path) "— in manifest, gone from secrets"))
          (doseq [path (:changed manifest-diff)]
            (println "    ~" (pr-str path) "— value or type changed")))
        (when stale-sha?
          (oops environment-label
                "— ciphertext was re-encrypted out-of-band since the manifest was written."))
        (if (or stale-entries? stale-sha?)
          (do
            (println "    Regenerate with:"
                     (str "bb secrets reencrypt " (shell-quote environment-label)))
            :drift)
          (do
            (ok environment-label "— manifest matches" (str "(" manifest ")"))
            :ok))))))

(defn- verify-one
  "Verify one environment's committed manifest against its encrypted secrets.
  Prints a human-readable result and returns :ok, :ok-keyless, :drift, or
  :missing. Without an identity, falls back to comparing the manifest's
  recorded :ciphertext-sha against the actual ciphertext (freshness only).

  This establishes *agreement* between the two committed artifacts — drift
  detection — and never who authored either of them; see [[verify!]]."
  [{:keys [app secrets-file manifest identity-file] environment-name :name :as env}]
  (let [environment-label (clojure.core/name environment-name)]
    (cond
      (not (string? manifest))
      (do
        (info environment-label "— manifest disabled; skipping.")
        :ok)

      (not (.exists (io/file secrets-file)))
      (do
        (warn environment-label "— no secrets file at" secrets-file)
        :missing)

      (not (.exists (io/file (str manifest))))
      (do
        (warn environment-label
              "— no manifest at"
              manifest
              (str "(run `bb secrets edit " (shell-quote environment-label)
                   "` to create it)"))
        :missing)

      :else
      (let [{:keys [committed status]}
            (read-supported-manifest environment-label app manifest (:limits env))]
        (if status
          status
          (if-not (.exists (io/file identity-file))
            (verify-keyless
             environment-label secrets-file manifest (identity-location env) committed)
            (verify-keyed-diff environment-label env committed)))))))

(defn verify!
  "Check that each environment's committed manifest matches its encrypted
  secrets. With no env, verifies all of them. Never exits — returns
  {:results {env-name status} :exit code}, where each status is :ok,
  :ok-keyless, :drift, or :missing. The exit code is 1 on drift, 2 on a
  missing artifact or an unverifiable legacy manifest, and 0 otherwise.
  Keyless verification compares the ciphertext hash and does not require age;
  full verification decrypts and compares manifest entries.

  A pass means the ciphertext and the manifest agree, not that either is
  authentic: age does not sign, so no run of this can identify who wrote them.
  In single-key mode the `:vhash`es do make a changed value fail a keyed run,
  because they are keyed by the private identity; team manifests carry no
  `:vhash`, so a same-shape value change there is invisible to `verify` by
  design. Sender authenticity rests on the repository and deployment channel —
  see the README's authenticity contract and threat model."
  [config env-arg]
  (let [envs (if env-arg
               [(resolve-env config env-arg)]
               (vals (:environments config)))
        results (into {} (map (juxt :name verify-one)) envs)
        statuses (set (vals results))]
    {:results results
     :exit (cond (statuses :drift) 1
                 (statuses :missing) 2
                 :else 0)}))

;;;; Doctor

;;; Doctor results intentionally retain nil-valued fields. A fixed schema lets
;;; callers distinguish unavailable diagnostics from omitted diagnostics without
;;; inspecting the selected environment or exception path.

(defn- artifact-state
  "Describe a configured artifact without reading it. Disabled and unconfigured
  artifacts have no path; every configured path is canonical."
  [path absent-state]
  (if (string? path)
    (let [f (io/file path)]
      {:state :configured
       :path (canonical-path path)
       :exists? (boolean (.exists f))})
    {:state absent-state
     :path nil
     :exists? false}))

(defn- usable-file?
  "True only for a readable regular file. Never returns or reports its path."
  [path]
  (try
    (let [f (io/file (str path))]
      (boolean (and path (.isFile f) (.canRead f))))
    (catch Exception _ false)))

(defn- recipient-state
  "Summarize recipients without retaining any recipient line."
  [env artifact]
  (cond
    (nil? (:recipients-file env))
    {:state :unconfigured :count 0 :valid? nil}

    (not (:exists? artifact))
    {:state :missing :count nil :valid? nil}

    :else
    (try
      (let [recipients (read-recipients env)
            count-all (count recipients)
            invalid-all (count (remove age/valid-recipient? recipients))]
        (cond
          (zero? count-all)
          {:state :empty :count 0 :valid? false}

          (pos? invalid-all)
          {:state :invalid
           :count count-all
           :valid? false
           :invalid-count invalid-all}

          :else
          {:state :valid :count count-all :valid? true}))
      (catch clojure.lang.ExceptionInfo e
        (or (bounded-state e)
            {:state :unreadable :count nil :valid? nil}))
      (catch Exception _
        {:state :unreadable :count nil :valid? nil}))))

(defn- manifest-state
  "Report whether a configured manifest supports a keyless freshness check.
  Manifest contents and parse errors are deliberately omitted."
  [manifest artifact limits]
  (cond
    (not (string? manifest)) {:state :disabled}
    (not (:exists? artifact)) {:state :missing}
    :else
    (try
      (let [{:keys [ok? value]}
            (safe-edn/parse (read-manifest-bounded! manifest limits) limits)]
        (if-not ok?
          {:state :invalid}
          (do
            (enforce-manifest-entry-limit! manifest value limits)
            (cond
              (not (map? value)) {:state :invalid}
              (not= 2 (:version value)) {:state :unsupported}
              (not (and (string? (:ciphertext-sha value))
                        (not (str/blank? (:ciphertext-sha value)))))
              {:state :missing-ciphertext-sha}
              :else {:state :ready}))))
      (catch clojure.lang.ExceptionInfo e
        (or (bounded-state e) {:state :invalid}))
      (catch Exception _ {:state :invalid}))))

(defn- age-state []
  (let [version (try (age/version) (catch Exception _ nil))]
    {:available? (some? version)
     :version version}))

(defn- doctor-verification-capability
  [age identity artifacts manifest-capability]
  (let [ciphertext? (get-in artifacts [:ciphertext :exists?])
        manifest? (get-in artifacts [:manifest :exists?])]
    {:state (if (= :disabled (:state manifest-capability))
              :skipped
              (:state manifest-capability))
     :keyless? (boolean (and ciphertext?
                             (= :ready (:state manifest-capability))))
     :full? (boolean (and (:available? age)
                          (:usable? identity)
                          ciphertext?
                          manifest?))}))

(defn- doctor-status
  [age identity artifacts recipients manifest-capability verify]
  (let [manifest? (get-in artifacts [:manifest :exists?])
        invalid? (contains? #{:empty :invalid} (:state recipients))
        missing-artifact?
        (or (some (fn [kind]
                    (not (get-in artifacts [kind :exists?])))
                  [:ciphertext :template :key])
            (and (not= :disabled (:state manifest-capability))
                 (not manifest?))
            (= :missing (:state recipients)))
        warning? (or (not (:available? age))
                     missing-artifact?
                     (not (:usable? identity))
                     (contains? #{:unreadable :bounded} (:state recipients))
                     (and (not= :disabled (:state manifest-capability))
                          (not= :ready (:state manifest-capability)))
                     (and (not= :skipped (:state verify))
                          (not (or (:keyless? verify) (:full? verify)))))]
    (cond
      invalid? :invalid
      warning? :warning
      :else :healthy)))

(defn- doctor-data
  [config env-arg]
  (let [config (normalize-config config)
        {:keys [secrets-file manifest template key-file recipients-file
                identity-file identity-source]
         environment-name :name :as env} (resolve-env config env-arg)
        artifacts {:ciphertext (artifact-state secrets-file :unconfigured)
                   :manifest (artifact-state manifest :disabled)
                   :template (artifact-state template :unconfigured)
                   :key (artifact-state key-file :unconfigured)
                   :recipients (artifact-state recipients-file :unconfigured)}
        identity {:source identity-source
                  :usable? (usable-file? identity-file)}
        age (age-state)
        recipients (recipient-state env (:recipients artifacts))
        mode (if recipients-file :multi-recipient :single-key)
        manifest-capability (manifest-state manifest (:manifest artifacts) (:limits env))
        verify (doctor-verification-capability
                age identity artifacts manifest-capability)
        status (doctor-status
                age
                identity
                artifacts
                recipients
                manifest-capability
                verify)]
    {:configuration {:valid? true}
     :age age
     :environment environment-name
     :artifacts artifacts
     :identity identity
     :encryption {:mode mode :recipients recipients}
     :verify verify
     :status status
     :exit (case status :healthy 0 :warning 1 :invalid 2)}))

(defn- print-artifact-state!
  [label {:keys [state path exists?]}]
  (println (str label ": "
                (case state
                  :disabled "disabled"
                  :unconfigured "unconfigured"
                  (str (if exists? "present" "missing") " — " path)))))

(defn- print-doctor!
  [{:keys [configuration age environment artifacts identity encryption verify status]}]
  (if-not (:valid? configuration)
    (println "Configuration: invalid")
    (do
      (println "Age:" (if (:available? age)
                        (str "available — " (:version age))
                        "unavailable"))
      (println "Environment:" (clojure.core/name environment))
      (doseq [[kind label] [[:ciphertext "Ciphertext"]
                            [:manifest "Manifest"]
                            [:template "Template"]
                            [:key "Key"]
                            [:recipients "Recipients file"]]]
        (print-artifact-state! label (artifacts kind)))
      (println "Identity:"
               (str (identity-source-display-label (:source identity))
                    " — " (if (:usable? identity) "usable" "unusable")))
      (println "Encryption mode:" (clojure.core/name (:mode encryption)))
      (let [{:keys [state valid? invalid-count] recipient-count :count}
            (:recipients encryption)]
        (println "Recipients:"
                 (str (clojure.core/name state)
                      " — count " (if (nil? recipient-count)
                                    "unknown"
                                    recipient-count)
                      " — valid " (if (nil? valid?) "unknown" valid?)
                      (when invalid-count
                        (str " — invalid count " invalid-count)))))
      (println "Verify keyless:" (if (= :skipped (:state verify))
                                   "skipped"
                                   (if (:keyless? verify) "available" "unavailable")))
      (println "Verify full:" (if (= :skipped (:state verify))
                                "skipped"
                                (if (:full? verify) "available" "unavailable")))))
  (println "Status:" (clojure.core/name status)))

(defn doctor!
  "Safely diagnose one selected/default environment. Accepts raw config,
  normalizes and validates it, prints stable value-free labels, and returns a
  structured result containing :exit (0 healthy, 1 warning/action-needed, or 2
  invalid configuration). It never exits and never returns an identity path,
  recipient line, environment value, or secret."
  [config env-arg]
  (let [result (try
                 (doctor-data config env-arg)
                 (catch Exception _
                   {:configuration {:valid? false}
                    :age nil
                    :environment nil
                    :artifacts nil
                    :identity nil
                    :encryption nil
                    :verify nil
                    :status :invalid
                    :exit 2}))]
    (print-doctor! result)
    result))

;;;; Dispatch

(def ^:private command-specs
  [{:name "keygen" :usage "[env]" :description "Generate an age key for an environment"
    :min-positionals 0 :max-positionals 1}
   {:name "new" :usage "[env]"
    :description "Create a new encrypted secrets file (opens your editor)"
    :min-positionals 0 :max-positionals 1}
   {:name "edit" :usage "[env]"
    :description "Edit an existing secrets file (decrypt → edit → re-encrypt)"
    :min-positionals 0 :max-positionals 1}
   {:name "set" :usage "[env] <key> [--edn]"
    :description "Set a key from stdin; --edn parses the value as EDN instead of a string"
    :min-positionals 1 :max-positionals 2}
   {:name "rm" :usage "[env] <key>"
    :description "Remove a key (fails if the key or file is absent)"
    :min-positionals 1 :max-positionals 2}
   {:name "verify" :usage "[env]"
    :description "Check the committed manifest matches the secrets"
    :min-positionals 0 :max-positionals 1}
   {:name "doctor" :usage "[env]"
    :description "Safely diagnose configuration and verification capability"
    :min-positionals 0 :max-positionals 1}
   {:name "show-key" :usage "[env]" :description "Print public key(s) for sharing"
    :min-positionals 0 :max-positionals 1}
   {:name "add-recipient" :usage "[env] [key]"
    :description "Add a public key to the env's recipients file"
    :min-positionals 0 :max-positionals 2}
   {:name "recipients" :usage "[env]" :description "List configured recipient public keys"
    :min-positionals 0 :max-positionals 1}
   {:name "reencrypt" :usage "[env]"
    :description "Re-encrypt to current recipients (after a change)"
    :min-positionals 0 :max-positionals 1}
   {:name "encrypt" :usage "[env] <file>"
    :description "Encrypt an arbitrary file to <file>.age"
    :min-positionals 1 :max-positionals 2}
   {:name "decrypt" :usage "[env] <file>" :description "Decrypt a <file>.age to stdout"
    :min-positionals 1 :max-positionals 2}
   {:name "help" :usage "[command]" :description "Show global or command-specific help"
    :min-positionals 0 :max-positionals 1}])

(defn- split-operands
  "Split `args` at the first `--` operand terminator into `[options operands]`,
  consuming the terminator itself. Everything in `operands` is positional data
  however it is spelled, which is how an operand that looks like an option — a
  file named `--edn` — is named on the command line. Same boundary every `age`
  invocation gets; a second `--` is data, not another terminator."
  [args]
  (let [[options operands] (split-with #(not= "--" %) args)]
    [(vec options) (vec (rest operands))]))

(defn- without-terminator
  "`args` with the `--` operand terminator consumed and nothing else touched —
  what a command that defines no flag of its own needs."
  [args]
  (let [[options operands] (split-operands args)]
    (into options operands)))

(defn- extract-flag
  "Pull a boolean `flag` out of `args`, returning `[present? remaining-args]`.
  Called only for the command that defines `flag`, so no other command's
  operand can be consumed as a flag it does not accept. Within that command the
  flag still leaves the sequence before positional dispatch reads it: `set` is
  `[env] <key> [--edn]`, and `(second args)` deciding whether the first
  argument is the environment or the key is what the extraction protects. A
  flag is only recognized before the operand terminator."
  [flag args]
  (let [[options operands] (split-operands args)]
    [(boolean (some #{flag} options))
     (into (vec (remove #{flag} options)) operands)]))

(def ^:private help-flags #{"--help" "-h"})

(defn- command-spec [command]
  (some #(when (= command (:name %)) %) command-specs))

(defn- usage-line [{command :name :keys [usage]}]
  (str "Usage: bb secrets " command (when (seq usage) (str " " usage))))

(defn- print-global-help! [{:keys [environments default-environment]}]
  (println (paint :bold "Manage encrypted secrets (age).") "\n")
  (println "Usage: bb secrets <command> [args]\n")
  (doseq [{command :name :keys [usage description]} command-specs]
    (println (format "  %-14s %-23s %s" command usage description)))
  (println)
  (println "Global help: bb secrets -h (or: bb secrets --help)")
  (println "Command help: bb secrets help <command> (or: bb secrets <command> --help)")
  (println)
  (println "Environments:" (str/join ", " (map name (keys environments)))
           (if default-environment
             (str "(default: " (name default-environment) ")")
             ""))
  (println (paint :dim "\n  An omitted [env] uses the default environment."))
  (println
   (paint :dim
          "  -- ends the options: everything after it is an operand, even -h, --help, or --edn."))
  (println
   (paint :dim
          "  Commands printed as suggestions are POSIX sh, single-quoted per argument."))
  (println (paint :dim "  verify exits 0 (ok) · 1 (drift) · 2 (missing or unverifiable)."))
  (println
   (paint :dim
          "  doctor exits 0 (healthy) · 1 (warning/action needed) · 2 (invalid configuration).")))

(defn- print-command-help! [{:keys [description] :as spec}]
  (println (usage-line spec))
  (println)
  (println description))

(defn- validate-positionals! [{command :name
                               :keys [min-positionals max-positionals]
                               :as spec}
                              positionals]
  (let [n (count positionals)]
    (cond
      (< n min-positionals)
      (fail! (str "Missing positional argument for " command ".")
             {:command command :hint (usage-line spec)})

      (> n max-positionals)
      (fail! (str "Too many positional arguments for " command ".")
             {:command command :hint (usage-line spec)}))))

(defn- print-error!
  "Print an ex-info the way `run!` reports failures: the message via `oops`,
  then any :hint / :install / :error (captured stderr) / :docs from the
  ex-data as indented follow-up lines on stderr."
  [e]
  (oops (ex-message e))
  (binding [*out* *err*]
    (doseq [k [:hint :install :error :docs]
            :let [v (get (ex-data e) k)]
            :when (and (some? v) (not (str/blank? (str v))))
            line (str/split-lines (str/trim-newline (str v)))]
      (println "   " line))))

(defn- help-requested? [args]
  (let [[options _] (split-operands args)]
    (boolean (some help-flags options))))

(defn- command-positionals [command args]
  (if (= "set" command)
    (extract-flag "--edn" args)
    [false (without-terminator args)]))

(defn- print-help-invocation! [config positionals]
  (if-let [target (first positionals)]
    (if-let [spec (command-spec (str/lower-case target))]
      (print-command-help! spec)
      (fail! (str "Unknown command: " target)
             {:command target :hint (usage-line (command-spec "help"))}))
    (print-global-help! config)))

(defn- execute-command! [config command positionals edn?]
  (if (= "doctor" command)
    (let [{:keys [exit]} (doctor! config (first positionals))]
      (when (pos? exit) (System/exit exit)))
    (let [config (normalize-config config)]
      (case command
        "keygen" (keygen! config (first positionals))
        "new" (new! config (first positionals))
        "edit" (edit! config (first positionals))
        "set" (if (second positionals)
                (set-secret! config (first positionals) (second positionals) edn?)
                (set-secret! config nil (first positionals) edn?))
        "rm" (if (second positionals)
               (remove-secret! config (first positionals) (second positionals))
               (remove-secret! config nil (first positionals)))
        "verify" (let [{:keys [exit]} (verify! config (first positionals))]
                   (when (pos? exit) (System/exit exit)))
        "show-key" (show-key! config (first positionals))
        "add-recipient" (add-recipient! config (first positionals) (second positionals))
        "recipients" (recipients! config (first positionals))
        "reencrypt" (reencrypt! config (first positionals))
        "encrypt" (if (second positionals)
                    (encrypt! config (first positionals) (second positionals))
                    (encrypt! config nil (first positionals)))
        "decrypt" (if (second positionals)
                    (decrypt! config (first positionals) (second positionals))
                    (decrypt! config nil (first positionals)))))))

(defn- dispatch! [config args]
  (let [[cmd & more] args
        command (some-> cmd str/lower-case)]
    (cond
      (or (nil? command) (help-flags command))
      (print-global-help! config)

      :else
      (if-let [spec (command-spec command)]
        (if (help-requested? more)
          (print-command-help! spec)
          (let [[edn? positionals] (command-positionals command more)]
            (validate-positionals! spec positionals)
            (if (= "help" command)
              (print-help-invocation! config positionals)
              (execute-command! config command positionals edn?))))
        (let [config (normalize-config config)]
          (print-global-help! config)
          (fail! (str "Unknown command: " cmd) {:command cmd}))))))

(defn run!
  "Public entry point for dispatching `args` against `config`.
  Reports ex-info details and exits with :secrets/exit (default 1); commands
  with documented status codes may exit directly."
  [config args]
  (try
    (dispatch! config args)
    (catch clojure.lang.ExceptionInfo e
      (print-error! e)
      (System/exit (:secrets/exit (ex-data e) 1)))))
