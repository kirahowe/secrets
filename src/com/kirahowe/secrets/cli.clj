(ns com.kirahowe.secrets.cli
  "The `bb secrets` management task.

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
    :key-file      the durable configured/default path above. `keygen` writes
                     here; `show-key` and `add-recipient` read the public key
                     from it.
    :identity-file what decrypt-side operations (edit, set, rm, reencrypt,
                     verify) and single-key encryption use. Resolved in order:
                       1. an explicit :identity-file
                       2. $SECRETS_AGE_IDENTITY_FILE, a path to the key file
                       3. $SECRETS_AGE_IDENTITY, raw key contents (written to a 0600 temp file)
                       4. $SECRETS_AGE_IDENTITY_B64, base64-encoded key contents
                       5. the environment's :key-file
                     So CI holding only an SECRETS_AGE_IDENTITY* variable can encrypt,
                     decrypt, and verify, while `keygen` still writes to the
                     configured key path.

  Optional per-environment keys:
    :recipients-file  path to a committed file of age public keys (one per
                      line). When set, the environment encrypts to all of them,
                      so each teammate can decrypt with their own key.
                      Absent ⇒ single-key mode (encrypt to own key).
    :manifest false   disable the manifest for this environment.

  Commands: keygen · new · edit · set · rm · verify · doctor · show-key ·
  add-recipient · recipients · reencrypt · help.

  By default, each environment commits `secrets.edn.age` (ciphertext) and
  `secrets.edn.manifest` (key paths, types, counts, and a keyed hash per value).
  The hashes are keyed by a random manifest key the store holds inside its
  encrypted EDN; `manifest-key-for` states when that key is generated, kept,
  and renewed. A store's plaintext is one EDN map. Editing uses an owner-only
  plaintext temp file and deletes it afterward; a failed delete is an error
  that names the remaining path.

  The command functions are the API for a REPL or a program: they return data
  (a path, a results map, or :aborted), throw `ex-info` with a `:reason` on
  failure, and never exit. `verify!` and `doctor!` report most failures in
  their result, with the exit code under `:exit`. `run!` is the entry point of
  a process. It alone prints a failure and exits: 1 on failure, and for
  `verify` and `doctor` 1 on drift or a warning and 2 on any failure."
  (:refer-clojure :exclude [run!])
  (:require [clojure.java.io :as io]
            [clojure.pprint :as pprint]
            [clojure.string :as str]
            [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.fs :as fs]
            [com.kirahowe.secrets.manifest :as manifest]
            [com.kirahowe.secrets.safe-edn :as safe-edn]
            [com.kirahowe.secrets.source :as source]))

;;;; Generated shell commands

;;; Every command this namespace prints for an operator to paste is POSIX `sh`,
;;; and every value interpolated into one goes through `shell-quote`. The CLI
;;; never executes these strings itself; the hazard is the instruction handed
;;; to the operator, so the rendering is where it has to be fixed.

(defn- shell-quote
  "Render `s` as a single POSIX `sh` word: wrapped in `'`, with each embedded
  `'` written as `'\\''`. The empty string renders as `''`. Inside single
  quotes every other character is literal, so no escaping rule is needed."
  [s]
  (str "'" (str/replace (str s) "'" "'\\''") "'"))

;;;; Output

;;; Everything a command reports is a *line*: a vector whose first element is
;;; its level and whose remaining elements are segments, joined with one space
;;; the way `println` joins its arguments. A segment is a string or a
;;; `[style string]` pair to paint. Commands build lines as plain data (the
;;; `*-lines` functions below are pure) and `say!` is the one place a line is
;;; painted and written out.
;;;
;;;   :line    stdout, no marker          :stderr  stderr, no marker
;;;   :info •  :ok ✓  :warn ⚠  stdout     :oops ✗  stderr

(def ^:private ansi
  {:reset "\033[0m" :bold "\033[1m" :dim "\033[2m"
   :red "\033[31m" :green "\033[32m" :yellow "\033[33m" :blue "\033[34m"})

(def ^:private level-markers
  {:info [:blue "•"] :ok [:green "✓"] :warn [:yellow "⚠"] :oops [:red "✗"]})

(def ^:private stderr-levels #{:oops :stderr})

(defn- tty? [] (some? (System/console)))

(defn- paint
  "`s` wrapped in the ANSI codes for `style` when `color?`, else `s` itself."
  [color? style s]
  (if color? (str (ansi style) s (ansi :reset)) s))

(defn- render-segment [color? segment]
  (if (vector? segment)
    (let [[style s] segment] (paint color? style s))
    (str segment)))

(defn- render-line
  "The text of one line: its marker and styled segments, painted when `color?`."
  [color? [level & segments]]
  (let [text (str/join " " (map #(render-segment color? %) segments))]
    (if-let [[style marker] (level-markers level)]
      (str (paint color? style marker) " " text)
      text)))

(defn- say!
  "Write `lines`, each to the stream its level names. Color is decided once per
  call, and this is the only place a report reaches `*out*` or `*err*`."
  [lines]
  (let [color? (tty?)]
    (doseq [[level :as line] lines]
      (if (stderr-levels level)
        (binding [*out* *err*] (println (render-line color? line)))
        (println (render-line color? line))))))

(defn- info [& xs] (say! [(into [:info] xs)]))
(defn- ok [& xs] (say! [(into [:ok] xs)]))
(defn- warn [& xs] (say! [(into [:warn] xs)]))

(defn- question-marker [] (paint (tty?) :yellow "?"))

(defn- fail!
  "Throw an `ex-info` for a user-facing failure, with `reason` as its
  `:reason`. `run!` prints the message plus any :hint, :install, :error, or
  :docs in the data."
  ([reason msg] (fail! reason msg nil))
  ([reason msg data] (throw (ex-info msg (assoc data :reason reason)))))

(defn- failure-message
  "One line saying what failure `e` was, holding no file contents. An
  `ex-info` gives its own message. Any other exception gives its class, plus
  its message when it is an `IOException`, whose message names a path."
  [e]
  (cond
    (instance? clojure.lang.ExceptionInfo e) (ex-message e)
    (instance? java.io.IOException e) (str (.getName (class e)) ": " (ex-message e))
    :else (str "Unexpected failure: " (.getName (class e)))))

(defn- confirm!
  "Prompt y/N; true on \"y\", false otherwise. Never exits: callers decide
  what a declined prompt means."
  [prompt]
  (print (str (question-marker) " " prompt " [y/N] "))
  (flush)
  (= "y" (some-> (read-line) str/trim str/lower-case)))

(defn- prompt-hidden!
  "Prompt on the terminal with echo turned off and return the typed line
  without its newline, or nil at end of input. Only valid when `tty?` is true."
  [prompt]
  (let [console (System/console)
        chars (.readPassword console "%s" (object-array [prompt]))]
    (some-> chars String.)))

;;;; Config

(defn- canonical-path
  "Canonicalize `path`, so aliases like `./key.txt` and `key.txt` compare
  equal."
  [path]
  (.getCanonicalPath (io/file (str path))))

(def ^:private identity-source-display-label
  "How a `doctor` report names where an identity came from."
  {:secrets-age-identity-file "SECRETS_AGE_IDENTITY_FILE"
   :secrets-age-identity "SECRETS_AGE_IDENTITY"
   :secrets-age-identity-b64 "SECRETS_AGE_IDENTITY_B64"
   :identity-file ":identity-file"
   :configured-key-file "key file"
   :default-key-file "key file"})

(defn- require-path!
  "Reject a blank path, a URI-shaped path, and key contents in a path field,
  returning `path` otherwise.

  CLI artifacts are local filesystem paths. The failure names the environment
  and field and never the value. `:key-file` and `:identity-file` fail with
  `:reason :disallowed-identity`, as the runtime's identity paths do, and
  every other field with `:disallowed-source`. Non-string values such as
  `:manifest false` keep their meaning."
  [env kind path]
  (when (and (string? path) (str/blank? path))
    (fail! :invalid-config
           (str "Environment " (name env) " has a blank " kind
                " (a path string must not be empty).\n"
                "    An empty path resolves to the working directory, not a file.")
           {:environment env :field kind :path path}))
  (when-let [problem (and (string? path) (source/path-problem path))]
    (fail! (if (#{:key-file :identity-file} kind)
             :disallowed-identity
             :disallowed-source)
           (source/path-problem-message (str "Environment " (name env) " " kind)
                                        "a local filesystem path"
                                        problem)
           (cond-> {:environment env :field kind}
             (:scheme problem) (assoc :scheme (:scheme problem)))))
  path)

(def ^:private path-purposes
  "What each path setting of an environment is for. `:key-file` and
  `:identity-file` both name an identity, so one file may be both."
  {:secrets-file :secrets-file
   :manifest :manifest
   :template :template
   :key-file :identity
   :identity-file :identity
   :recipients-file :recipients-file})

(defn- reject-shared-paths!
  "Fail when two settings name one file that cannot serve both, comparing
  canonical paths across every environment, so `./key.txt` and `key.txt` are
  one file and one environment's ciphertext cannot be another's key.

  A file has one purpose: it is a secrets file, a manifest, a template, an
  identity, or a recipients file. Environments may share a template, an
  identity, or a recipients file, which commands only read. Two environments
  may name the same secrets file only when they name the same manifest too,
  and the reverse: then they are one store under two names. The failure names
  the two settings.

  This reads the configuration as it is now. It is a check against a
  configuration mistake, not against the filesystem changing afterwards."
  [environments]
  (let [uses (for [env (sort-by (comp name :name) (vals environments))
                   [setting purpose] path-purposes
                   :let [path (get env setting)]
                   :when (string? path)]
               {:label (str (name (:name env)) " " setting)
                :purpose purpose
                :path path
                :canonical (canonical-path path)
                :store (mapv #(some-> (get env %) str canonical-path) [:secrets-file :manifest])})
        clash (first (for [[_ group] (sort-by key (group-by :canonical uses))
                           a group
                           b group
                           :when (and (neg? (compare (:label a) (:label b)))
                                      (or (not= (:purpose a) (:purpose b))
                                          (and (#{:secrets-file :manifest} (:purpose a))
                                               (not= (:store a) (:store b)))))]
                       [a b]))]
    (when-let [[a b] clash]
      (fail! :invalid-config
             (str (:label a) " and " (:label b) " name the same file: " (:path a)
                  (when (not= (:path a) (:path b)) (str " and " (:path b)))
                  "\n    A file is a secrets file, a manifest, a template, an identity, or a"
                  " recipients file, and only one of them. Two environments\n    share a"
                  " secrets file or a manifest only when they share both.")
             {:settings [(:label a) (:label b)]}))))

(def ^:private max-recipients-bytes
  "The most bytes a recipients file may hold (256 KiB). It catches an
  accidental huge input, such as a path that names the wrong file."
  262144)

(def ^:private max-plaintext-bytes
  "The most plaintext bytes a store the CLI writes may hold (8 MiB). It catches
  an accidental huge input, such as a path that names the wrong file. A store
  this size encrypts to well under the 16 MiB of ciphertext a read accepts, so
  every store the CLI writes can be read back."
  8388608)

(def ^:private max-manifest-bytes
  "The most bytes a manifest may hold (1 MiB). It catches an accidental huge
  input, such as a path that names the wrong file."
  1048576)

(def ^:private config-keys
  "Every key a secrets config may hold at its top level."
  #{:app :default-environment :environments})

(def ^:private environment-keys
  "Every key an environment's config may hold. Each names a path."
  #{:secrets-file :key-file :identity-file :template :manifest :recipients-file})

(defn- reject-unknown-keys!
  "Fail when map `m` holds a key outside `known`, naming the key and the known
  ones. A misspelled key would otherwise configure nothing and say nothing.
  `what` names the map in the message."
  [what known m]
  (when-let [unknown (seq (remove known (keys m)))]
    (fail! :unknown-config-key
           (str what " has an unknown key: " (str/join ", " (map pr-str unknown)) ".\n"
                "    Known keys: " (str/join ", " (sort (map pr-str known))) ".")
           {:unknown-keys (vec unknown)})))

(defn- normalize-environment
  [app environment-name
   {:keys [secrets-file key-file identity-file template manifest recipients-file]
    :as env-config}]
  (let [label (name environment-name)]
    (reject-unknown-keys! (str "Environment " label) environment-keys env-config)
    (doseq [[k v] env-config]
      (when-not (or (string? v) (and (= :manifest k) (false? v)))
        (fail! :invalid-config
               (str "Environment " label " " k " must be a path string"
                    (when (= :manifest k) ", or false to keep no manifest")
                    ", not a value of type " (name (manifest/value-type v)) ".")
               {:environment environment-name :field k})))
    (when-not secrets-file
      (fail! :invalid-config
             (str "Environment " label " has no :secrets-file (a path string is required).")
             {:environment environment-name}))
    (require-path! environment-name :secrets-file secrets-file)
    (when (and (not (str/ends-with? secrets-file ".age"))
               (not (and (contains? env-config :template)
                         (contains? env-config :manifest))))
      (fail! :invalid-config
             (str "Environment " label " :secrets-file (" secrets-file
                  ") does not end in .age, so the\n"
                  "    derived :template/:manifest names would collide with — and overwrite — "
                  "the\n"
                  "    ciphertext itself. Use a .age extension, or set :template and :manifest\n"
                  "    explicitly.")
             {:environment environment-name
              :secrets-file secrets-file})))
  (let [key-file (if key-file
                   (secrets/expand-home key-file)
                   (secrets/default-key-file app))
        explicit-identity (some-> identity-file secrets/expand-home)
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
           :secrets-file secrets-file
           :key-file key-file
           :identity-file explicit-identity
           ;; An explicit :manifest false is kept. Absent values are derived
           ;; from the secrets file.
           :template template
           :manifest manifest
           :recipients-file recipients-file)))

(defn normalize-config
  "Validate a secrets config as it is written in `bb.edn` and return it with
  per-environment defaults (:key-file, :template, :manifest) applied. The
  command functions take the result. A config this function returned comes
  back unchanged.

  Requires a non-blank :app and at least one environment, each a map with a
  :secrets-file. Every environment setting is a path string, and :manifest
  may also be false. A secrets path not ending in `.age` requires explicit
  :template and :manifest values. No file may serve two purposes across the
  environments (see `reject-shared-paths!`). A key the config or an environment
  does not define is rejected by name, so a misspelled key cannot be silently
  ignored. Does not select an environment identity or create private files.
  Throws ex-info on invalid input."
  [{:keys [app environments] :as config}]
  (if (::normalized (meta config))
    config
    (do
      (when-not (map? config)
        (fail! :invalid-config "secrets config must be a map with :app and :environments"))
      (reject-unknown-keys! "secrets config" config-keys config)
      (when-not (and (map? environments) (seq environments))
        (fail! :invalid-config
               (str "secrets config needs :environments, a map from each environment's name to"
                    " a map of its settings, with at least one environment")))
      (doseq [[environment-name env-config] environments]
        (when-not (and (keyword? environment-name) (map? env-config))
          (fail! :invalid-config
                 (str "secrets config :environments must map each environment's name, a"
                      " keyword, to a map of its settings such as"
                      " {:secrets-file \"secrets.edn.age\"}"))))
      (when-not (and (string? app) (not (str/blank? app)))
        (fail! :invalid-config
               (str "secrets config has no :app (a name string is required). It names the\n"
                    "    default key path ~/.config/<app>/key.txt and is recorded in the "
                    "manifest,\n"
                    "    so there is deliberately no default — projects must not share a key "
                    "path\n"
                    "    by accident.")))
      (when (and (contains? config :default-environment)
                 (not (contains? environments (:default-environment config))))
        (fail! :invalid-config
               (str "secrets config :default-environment must name one of its environments: "
                    (str/join ", " (map name (keys environments))))))
      (let [normalized (reduce-kv (fn [normalized environment-name env-config]
                                    (assoc normalized
                                           environment-name
                                           (normalize-environment app environment-name env-config)))
                                  {}
                                  environments)]
        (reject-shared-paths! normalized)
        (vary-meta (assoc config :environments normalized) assoc ::normalized true)))))

(defn- resolve-env
  "Resolve an environment argument string to its (defaulted) config map.
  Throws (via `fail!`) on a missing or unknown environment. An unknown name is
  not repeated: it may be a value typed where the environment goes."
  [{:keys [environments default-environment]} env-arg]
  (let [env-key (if (nil? env-arg) default-environment (keyword env-arg))]
    (or (get environments env-key)
        (fail! :usage
               (str (if (nil? env-arg) "Missing environment." "Unknown environment.")
                    " One of: " (str/join ", " (map name (keys environments))))))))

(defn- with-environment-identity
  "Hold one resolved identity through the command's decryption and hashing.
  An identity path that came from SECRETS_AGE_IDENTITY_FILE was not in the
  config when its paths were checked, so it is checked against them here."
  [config env f]
  (secrets/with-identity env
    (fn [identity]
      (let [resolved (merge env identity)]
        (when (= :secrets-age-identity-file (:identity-source identity))
          (reject-shared-paths! (assoc (:environments config) (:name env) resolved)))
        (f resolved)))))

;;;; Utilities

(defn- input-too-large!
  "Fail because `what`, a short description that names the file where there is
  one, holds `observed` bytes against a bound of `limit`."
  [what limit observed context]
  (fail! :input-too-large
         (str what " is larger than the " limit " byte limit.")
         (merge context {:limit limit :observed observed})))

(defn- utf8-length [^String s]
  (alength (.getBytes s java.nio.charset.StandardCharsets/UTF_8)))

(defn- read-file-bounded!
  "Read the file at `path` as UTF-8 text, failing when it holds more than
  `limit` bytes. `kind` and `context` describe it in the failure."
  [path limit kind context]
  (let [f (io/file (str path))]
    (when (> (.length f) limit)
      (input-too-large! (str kind " " path) limit (.length f) context))
    (try
      (slurp f :encoding "UTF-8")
      (catch java.io.IOException e
        (fail! :unreadable-file
               (str kind " " path " could not be read (" (.getSimpleName (class e)) ").")
               context)))))

(defn- read-reader-bounded!
  "Read all of character `reader`, failing when its UTF-8 form passes `limit`
  bytes. A character is at least one byte, so reading stops one chunk past the
  bound and never accumulates an unbounded value."
  [^java.io.Reader reader limit what context]
  (let [captured (StringBuilder.)
        chunk (char-array 8192)]
    (loop []
      (let [n (.read reader chunk 0 (alength chunk))]
        (when-not (neg? n)
          (.append captured chunk 0 n)
          (when (<= (.length captured) limit)
            (recur)))))
    (let [text (.toString captured)
          observed (utf8-length text)]
      (when (> observed limit)
        (input-too-large! what limit observed context))
      text)))

(defn- editor-value
  "The editor command to run: the `VISUAL` value `visual`, else the `EDITOR`
  value `editor`, else `vim`. A blank value counts as unset, so an empty
  `VISUAL` cannot hide a working `EDITOR`. A value is returned whole, with
  any arguments it carries."
  [visual editor]
  (or (first (remove str/blank? [visual editor])) "vim"))

(defn- editor
  "`editor-value` applied to the live environment."
  []
  (editor-value (System/getenv "VISUAL") (System/getenv "EDITOR")))

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
  editor command, because a misconfigured one is otherwise indistinguishable from an
  editor that genuinely failed. The command is configuration, not a secret; the
  plaintext path stays out of the message."
  [path]
  (let [command (editor)
        path (.getAbsolutePath (io/file (str path)))
        proc (-> (ProcessBuilder. (into-array String (editor-argv command path)))
                 (.inheritIO)
                 (.start))]
    (when-not (zero? (.waitFor proc))
      (fail! :editor-failed
             (str "Editor exited with an error; leaving secrets unchanged."
                  " Editor: " command)))))

(defn- with-plaintext-temp
  "Call `f` with a private temporary file for plaintext secrets, deleted when
  `f` returns or throws. A failed delete is reported with the remaining path."
  [f]
  (fs/with-private-temp-file "secrets-" ".edn" f))

(defn- distinct-by [f coll]
  (->> coll (group-by f) vals (map first)))

(defn- sha256
  "The SHA-256 hex of the file at `path`. A file that cannot be read fails
  naming the path."
  [path]
  (let [md (java.security.MessageDigest/getInstance "SHA-256")]
    (try
      (with-open [in (io/input-stream (io/file (str path)))]
        (let [buf (byte-array 8192)]
          (loop []
            (let [n (.read in buf)]
              (when (pos? n) (.update md buf 0 n) (recur))))))
      (catch java.io.IOException e
        (fail! :unreadable-file
               (str "File " path " could not be read (" (.getSimpleName (class e)) ")."))))
    (apply str (map #(format "%02x" %) (.digest md)))))

(def ^:private default-template
  (str ";; Encrypted secrets (age). Edit with `bb secrets edit`; never commit the\n"
       ";; decrypted form. Values are plain EDN — strings, sets, nested maps, etc.\n"
       "{:example/api-key \"replace-me\"\n"
       " :example/allowed #{}}\n"))

(defn- template-content [{:keys [template]}]
  (let [f (io/file (str template))]
    (if (.exists f)
      (read-file-bounded! f max-plaintext-bytes "Template" {:template (str template)})
      default-template)))

(defn- require-age! []
  (when-not (age/installed?)
    (fail! :age-not-installed
           (str "The `age` tool is not installed.\n"
                "    macOS:  brew install age\n"
                "    Ubuntu: apt install age\n"
                "    Docs:   https://age-encryption.org"))))

(defn- require-identity!
  "Require the resolved identity file, naming its path when it is missing."
  [{environment-name :name :keys [identity-file]}]
  (when-not (and identity-file (.exists (io/file identity-file)))
    (fail! :no-identity
           (str "No age identity for " (name environment-name)
                " at " identity-file "\n"
                "    Create one with:  bb secrets keygen "
                (shell-quote (name environment-name)) "\n"
                "    Or point at an existing key via SECRETS_AGE_IDENTITY_FILE (a path),\n"
                "    SECRETS_AGE_IDENTITY (raw key contents), or "
                "SECRETS_AGE_IDENTITY_B64 (base64 contents).")
           {:environment environment-name :identity-file identity-file})))

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
  "Read one recipients file under the same byte bound for every command.
  Returns its exact text plus numbered entries and recipient values, or nil
  when the file is absent."
  [{:keys [recipients-file] environment-name :name}]
  (let [f (io/file (str recipients-file))]
    (when (.exists f)
      (let [content (read-file-bounded!
                     f max-recipients-bytes "Recipients file"
                     {:recipients-file (str recipients-file)
                      :environment environment-name})
            entries (vec (recipient-entries content))]
        {:content content
         :entries entries
         :recipients (mapv second entries)}))))

(defn- read-recipients [env]
  (:recipients (recipient-file-snapshot env)))

(defn- validate-recipient-entries!
  "Reject any entry `age/valid-recipient?` refuses, naming the 1-based line
  number and quoting only a truncated prefix. A hand-edited line may hold
  anything, and a diagnostic is not the place to echo it."
  [{:keys [recipients-file] environment-name :name} entries]
  (let [label (clojure.core/name environment-name)]
    (doseq [[n line] entries]
      (when-not (age/valid-recipient? line)
        (fail! :invalid-recipient
               (str "Not a valid age recipient on line " n " of " recipients-file
                    " (" label "): " (pr-str (line-prefix line)) "\n"
                    "    Every line must be an age1… public key, an ssh-ed25519/ssh-rsa\n"
                    "    key, or a # comment.")
               {:recipients-file (str recipients-file) :line n
                :environment environment-name})))))

(defn- recipient-snapshot
  "Read the environment's recipients file exactly once and return the immutable
  vector of validated recipients to encrypt to, deduplicated in first-seen
  order.

  The file is read once so one operation uses one consistent set. A pathname
  handed to age would be read again inside age, after an editor session that can
  run for minutes and during which the file may have been edited. Everything the
  file says is decided here, before the sensitive work starts, and the resulting
  values are what gets encrypted to.

  Fails on a file larger than `max-recipients-bytes`, an entry
  `age/valid-recipient?` rejects, or an empty result."
  [{:keys [recipients-file] environment-name :name :as env}]
  (let [label (clojure.core/name environment-name)
        entries (or (:entries (recipient-file-snapshot env)) [])]
    (when (empty? entries)
      (fail! :no-recipients
             (str "No recipients yet for " label " in " recipients-file "\n"
                  "    Add one with:  bb secrets add-recipient "
                  (shell-quote label))
             {:recipients-file (str recipients-file)
              :environment environment-name}))
    (validate-recipient-entries! env entries)
    (vec (distinct (map second entries)))))

(defn- encrypt-target!
  "The immutable age recipient spec to encrypt with, resolved once before any
  sensitive work begins (before an editor opens, before stdin is read, before
  anything is decrypted) and threaded down to `age/encrypt-file!` from there.

  Multi-recipient mode returns the validated `{:recipients [\"age1…\" …]}`
  snapshot, so age receives repeated `-r` values and no pathname to re-read.
  Single-key mode returns the environment's resolved `{:identity-file …}` (so
  SECRETS_AGE_IDENTITY* works in CI too)."
  [{:keys [recipients-file identity-file] :as env}]
  (if recipients-file
    {:recipients (recipient-snapshot env)}
    (do (require-identity! env)
        {:identity-file identity-file})))

;;;; Manifest

(defn- require-store-metadata!
  "Return the metadata map held by decrypted store value `store`, or fail
  saying what is wrong with it and which command writes a usable store. The
  failure never carries the value found."
  [{:keys [secrets-file] environment-name :name} store]
  (if-let [problem (manifest/store-problem store)]
    (let [label (shell-quote (name environment-name))
          reserved (pr-str manifest/store-key)
          reencrypt (str "\n    Write a current one with:  bb secrets reencrypt " label)]
      (fail! :invalid-store
             (str "The store " secrets-file
                  (case problem
                    :not-a-map
                    (str " holds a value of type " (name (manifest/value-type store))
                         " where one EDN map is required, so no command can read or"
                         " change it.\n    Replace it with:  bb secrets new " label)
                    :missing
                    (str " has no store metadata (" reserved "), so its manifest cannot"
                         " be written or checked." reencrypt)
                    :malformed
                    (str " holds malformed store metadata (" reserved "), so its"
                         " manifest cannot be written or checked." reencrypt)
                    :unsupported-version
                    (str " is in store format version "
                         (:version (get store manifest/store-key))
                         ", which this version of the library does not support.\n"
                         "    Upgrade the library, or write a current one with:"
                         "  bb secrets reencrypt " label)))
             {:problem problem
              :secrets-file (str secrets-file)
              :environment environment-name}))
    (get store manifest/store-key)))

(defn- manifest-key-for
  "Return the manifest key a write of this store carries. This is the one rule
  for the key's lifetime (`doc/threat-model.md`, A5 and the chosen manifest
  contract):

  - `:create` (`new`, and `set` when no store exists) generates a key.
  - `:reencrypt` always generates a key, so every `:vhash` changes once. It
    does not read the existing metadata, which is how it repairs a store whose
    metadata is missing, malformed, or of another version.
  - `:update` (`edit`, `set`, `rm`) keeps the key of `store`, the decrypted
    value, and fails when its metadata is not usable. These commands encrypt
    to the recipients as they read now, so when `target` is not the recipient
    set the store records, they generate a key instead. A removed recipient's
    retained key then says nothing about values published by this write or
    any later one."
  [operation env store target]
  (if (= :update operation)
    (let [{:keys [manifest-key recipients]} (require-store-metadata! env store)]
      (if (= (manifest/recipients-id (:recipients target)) recipients)
        manifest-key
        (do (info "Recipients changed since the last write:"
                  "generating a new manifest key, so every value hash changes once.")
            (manifest/generate-key))))
    (manifest/generate-key)))

(defn- parse-secrets!
  "Parse all of `text`, the plaintext of the store at `secrets-file`, and
  return its EDN value. Fail when it is empty, malformed, holds more than one
  value, or nests too deeply, with `note` after the message."
  [secrets-file text note]
  (let [{:keys [ok? value] :as parsed} (safe-edn/parse text)]
    (if ok?
      value
      (fail! (:reason parsed)
             (str "Secrets are not valid EDN (" (safe-edn/failure-message parsed) ")." note)
             (merge {:secrets-file (str secrets-file)}
                    (safe-edn/failure-data parsed))))))

(defn- decrypt-text!
  "The environment's decrypted store as text, library metadata included. A
  ciphertext past `source/max-source-bytes` is refused before it is decrypted,
  which bounds the plaintext too: age does not compress."
  [{:keys [secrets-file identity-file]}]
  (let [size (.length (io/file (str secrets-file)))]
    (when (> size source/max-source-bytes)
      (input-too-large! (str "The secrets file " secrets-file) source/max-source-bytes size
                        {:secrets-file (str secrets-file)})))
  (age/decrypt identity-file secrets-file))

(def ^:private set-usage
  (str "`set` takes [env] <key>; the value is read from the prompt or stdin, "
       "never from the command line."))

(defn- with-set-usage
  "Call `f`, adding `set-usage` as the hint of a failure. An argument `set`
  cannot place may be the value itself, typed on the command line."
  [f]
  (try (f)
       (catch clojure.lang.ExceptionInfo e
         (throw (ex-info (ex-message e) (assoc (ex-data e) :hint set-usage) e)))))

(defn- parse-key-path
  "Parse a `set`/`rm` CLI key argument as EDN into the vector `assoc-in` /
  `get-in` / `update-in` expect: a bare keyword becomes a one-element path,
  a vector of keywords/strings is a nested path. Rejects anything else,
  including a missing argument, with a `fail!` naming both accepted forms, so
  a typo'd path is caught before any file is touched. A path at or under the
  store's reserved metadata key is rejected too. The failure names the
  rejected value's type and never the value: `set` receives the key where a
  mistyped command line may have put the secret."
  [s]
  (when (str/blank? (str s))
    (fail! :usage
           (str "Missing key. Accepted forms: a keyword (:some/key) or a vector path "
                "([:a :b]).")))
  (let [{:keys [ok? value] :as parsed} (safe-edn/parse (str s))
        problem (cond
                  (not ok?) (safe-edn/failure-message parsed)
                  (keyword? value) nil
                  (and (vector? value) (empty? value)) "got an empty vector"
                  (vector? value) (when-not (every? #(or (keyword? %) (string? %)) value)
                                    "got a vector containing a non-keyword, non-string element")
                  :else (str "got a value of type " (name (manifest/value-type value))))]
    (when problem
      (fail! (if ok? :usage (:reason parsed))
             (str "Invalid key: " problem ".\n"
                  "    Accepted forms: a keyword (:some/key) or a vector path "
                  "([:a :b]).")
             (when-not ok? (safe-edn/failure-data parsed))))
    (let [path (if (keyword? value) [value] value)]
      (when (= manifest/store-key (first path))
        (fail! :reserved-key
               (str "The key " (pr-str (first path)) " is reserved for the library's own"
                    " metadata. `set` and `rm` do not read, change, or remove it.")
               {:key path}))
      path)))

(defn- require-map-parents!
  "Fail when `path` passes through a value of `secrets` that is not a map,
  where `assoc-in` and `update-in` cannot go. The failure names the path up to
  that value and its type, never the value."
  [secrets path]
  (loop [value secrets
         walked []
         [k & more] path]
    (when (and (seq more) (contains? value k))
      (let [child (get value k)
            walked (conj walked k)]
        (when-not (map? child)
          (fail! :path-not-a-map
                 (str "Cannot reach " (pr-str path) ": " (pr-str walked) " holds a value of type "
                      (name (manifest/value-type child)) ", not a map, so there is nothing"
                      " under it to set or remove.")
                 {:key path}))
        (recur child walked more)))))

(defn- render-secrets
  "Render a secrets map as the plaintext `set`/`rm` re-encrypt. Pretty-printed
  so the file stays readable to the next `bb secrets edit`, and printed with
  the length/level limits unbound: a REPL that has set `*print-length*` would
  otherwise write `...` into the store and silently truncate secrets.

  Note the whole file is regenerated, so comments a human wrote in an edited
  store do not survive a `set`. The values do."
  [value]
  (binding [*print-length* nil *print-level* nil]
    (with-out-str (pprint/pprint value))))

(defn- strip-trailing-newline
  "Strip exactly one trailing newline (\\n or \\r\\n) from `s`, so
  `echo secret | bb secrets set …` stores the obvious value; anything else,
  including a value that itself ends with a blank line, passes through
  verbatim."
  [s]
  (cond
    (str/ends-with? s "\r\n") (subs s 0 (- (count s) 2))
    (str/ends-with? s "\n") (subs s 0 (- (count s) 1))
    :else s))

(defn- replace-file!
  "Atomically replace public artifact `target` with the text `content`,
  staged beside it. The staging file is deleted on any failure."
  [target content]
  (let [staging (fs/staging-file target)]
    (try
      (spit staging content)
      (fs/atomic-move! staging target)
      (finally (.delete staging)))))

;;; A store's plaintext is the user's text with the library's metadata written
;;; as the first line of its map. `with-metadata` puts that line in and
;;; `user-plaintext` takes it out, so the user's text, comments included,
;;; round-trips byte for byte and never shows the metadata.

(defn- map-opening
  "The index just past the `{` that opens the first form of `text`, when only
  whitespace, commas, and `;` comments come before it. The map may carry a
  namespace prefix (`#:db{`), which is how the pretty printer writes a map
  whose keys share a namespace. Otherwise nil."
  [^String text]
  (loop [i 0]
    (when (< i (count text))
      (let [c (.charAt text i)]
        (cond
          (or (Character/isWhitespace c) (= \, c)) (recur (inc i))
          (= \; c) (let [end (.indexOf text "\n" (int i))]
                     (when-not (neg? end) (recur (inc end))))
          (= \{ c) (inc i)
          (= \# c) (some->> (re-find #"\A#:[^\s{}\[\]()\";,]+\s*\{" (subs text i))
                            count
                            (+ i)))))))

(defn- metadata-line
  "The map entry that carries the store's metadata, as one line of text."
  [manifest-key recipients-id]
  (str (pr-str manifest/store-key)
       " {:version " manifest/store-version
       " :manifest-key " (pr-str manifest-key)
       " :recipients " (pr-str recipients-id) "}\n "))

(def ^:private metadata-line-re
  "Matches the library's metadata line at the start of a string, whatever flat
  map it holds, so the line of another store version is taken out too."
  (re-pattern (str "\\A" (java.util.regex.Pattern/quote (pr-str manifest/store-key))
                   " \\{[^{}\\n]*\\}\\n ")))

(defn- with-metadata
  "Return `user-text`, the text of a map, with `line` (from `metadata-line`)
  written as its first entry. Nil when the text does not open with its map."
  [user-text line]
  (when-let [opening (map-opening user-text)]
    (str (subs user-text 0 opening) line (subs user-text opening))))

(defn- user-plaintext
  "Return store or template text without the library's metadata line, exactly
  as the user wrote it. Text without that line comes back unchanged."
  [text]
  (let [opening (map-opening text)
        line (when opening (re-find metadata-line-re (subs text opening)))]
    (if line
      (str (subs text 0 opening) (subs text (+ opening (count line))))
      text)))

(defn- read-edited!
  "The text an editor left in private temp file `tmp`, bounded as every
  plaintext the CLI writes is."
  [{:keys [secrets-file]} tmp]
  (read-file-bounded! tmp max-plaintext-bytes "The edited plaintext"
                      {:secrets-file (str secrets-file)}))

(defn- store-plaintext!
  "Validate `user-text` and return `[value plaintext]`: the user's map, and
  the text to encrypt, which is `user-text` with the store's metadata written
  in. Fails, before anything is encrypted, on a plaintext past
  `max-plaintext-bytes`, which is checked before it is parsed, and on text
  that is not one EDN map or that holds the reserved key."
  [secrets-file target user-text manifest-key]
  (let [unchanged "\n    Ciphertext and manifest were left unchanged."
        line (metadata-line manifest-key (manifest/recipients-id (:recipients target)))
        size (+ (utf8-length user-text) (utf8-length line))
        _ (when (> size max-plaintext-bytes)
            (input-too-large! (str "The plaintext for " secrets-file)
                              max-plaintext-bytes size
                              {:secrets-file (str secrets-file)}))
        value (parse-secrets! secrets-file user-text unchanged)
        _ (when-not (map? value)
            (fail! :secrets-not-a-map
                   (str "Secrets must be one EDN map, but the plaintext is a value of type "
                        (name (manifest/value-type value)) "." unchanged)
                   {:secrets-file (str secrets-file)}))
        _ (when (contains? value manifest/store-key)
            (fail! :reserved-key
                   (str "The plaintext holds " (pr-str manifest/store-key)
                        ", which the library reserves for its own metadata.\n"
                        "    Remove it; the store keeps its own." unchanged)
                   {:secrets-file (str secrets-file) :key [manifest/store-key]}))
        plaintext (or (with-metadata user-text line)
                      (fail! :secrets-map-not-first
                             (str "The secrets map must be the first form in the plaintext."
                                  " Only whitespace and ; comments may come before its {."
                                  unchanged)
                             {:secrets-file (str secrets-file)}))]
    [value plaintext]))

(defn- write-secrets!
  "Validate `user-text`, the store's plaintext without library metadata, write
  it with `manifest-key` into private temp file `tmp`, encrypt that to the
  already-resolved `target` recipient spec, and replace the ciphertext and
  then the manifest, each atomically.

  `tmp` is the caller's own private temp file, so the keyed plaintext is on
  disk only inside the scope that deletes it. Validation, encryption, and
  manifest rendering all finish before anything is replaced, so a failure
  there leaves both files as they were. The pair is not one transaction: the
  ciphertext is authoritative and the manifest is derived from it. If the
  manifest cannot be replaced after the ciphertext was, the failure has
  `:reason :manifest-stale` and says how to regenerate it."
  [{:keys [manifest app secrets-file] environment-name :name} target tmp user-text manifest-key]
  (let [[value plaintext] (store-plaintext! secrets-file target user-text manifest-key)
        staging (fs/staging-file secrets-file)]
    (try
      (spit tmp plaintext :encoding "UTF-8")
      (age/encrypt-file! target tmp staging)
      (let [manifest-text (when (string? manifest)
                            (manifest/render {:app app :ciphertext-sha (sha256 staging)}
                                             (manifest/entries value manifest-key)))]
        (fs/atomic-move! staging secrets-file)
        (when manifest-text
          (try
            (replace-file! manifest manifest-text)
            (catch Exception e
              (throw (ex-info
                      (str "The ciphertext " secrets-file " was updated, but its manifest "
                           manifest " could not be replaced (" (.getName (class e))
                           "), so the manifest is stale.\n"
                           "    `bb secrets verify` will report it. Regenerate it with:"
                           "  bb secrets reencrypt "
                           (shell-quote (name environment-name)))
                      {:reason :manifest-stale
                       :secrets-file (str secrets-file)
                       :manifest manifest
                       :environment environment-name}
                      e))))))
      (finally
        (.delete staging)))))

(defn- report-written!
  "Report `outcome` for the ciphertext and, when the environment keeps a
  manifest, that it was rewritten beside it."
  [{:keys [manifest]} & outcome]
  (apply ok outcome)
  (when (string? manifest)
    (info "Manifest updated:" manifest)))

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

(defn- keygen-lines
  "The report after a key is written: who shares it, the public key, and how to
  back it up and deploy it. `sharing` is every environment name resolving to
  `key-file`; `app-default?` says that is the app-wide default path."
  [environment-name key-file recipients-file sharing app-default? pub]
  (cond-> [[:ok "Key written:" key-file]
           [:line (str "    Used by: " (str/join ", " (map name sharing))
                       (when app-default?
                         " — every environment without its own :key-file"))]
           [:line]
           [:line [:bold "  Public key:"] pub]
           [:line]
           [:warn "Back this key up (e.g. a password manager). It is NOT in git and"]
           [:line (str "    cannot be recovered. To deploy, set it as the "
                       "SECRETS_AGE_IDENTITY secret:")]
           ;; `cat --` because a key file named `-n` or `--help` has to reach
           ;; cat as a pathname.
           ;; The surrounding "$(…)" is the shell's own construct, not
           ;; interpolated data, and is what makes the file contents one
           ;; argument to flyctl.
           [:line [:dim (str "      flyctl secrets set SECRETS_AGE_IDENTITY=\"$(cat -- "
                             (shell-quote key-file) ")\"")]]]
    recipients-file
    (into [[:line]
           [:info "This project encrypts to a shared recipients file. Add your public"]
           [:line "    key so teammates encrypt secrets you can read:"]
           [:line [:dim (str "      bb secrets add-recipient "
                             (shell-quote (name environment-name)))]]])))

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
        (info "Generating age key for" (name environment-name) "…")
        (let [pub (age/keygen! key-file)
              sharing (sharing-environments (:environments config) key-file)
              app-default? (= (canonical-path key-file)
                              (canonical-path (secrets/default-key-file (:app config))))]
          (say! (keygen-lines environment-name key-file recipients-file
                              sharing app-default? pub))
          key-file)))))

(defn new!
  "Create an encrypted secrets file from its template using $VISUAL, $EDITOR,
  or vim. Returns the secrets-file path, or :aborted when an existing file is
  kept. Plaintext is held in an owner-only temp file during editing. The new
  store gets its own manifest key. The library's metadata line in a template is
  dropped, never copied."
  [config env-arg]
  (with-environment-identity config (resolve-env config env-arg)
    (fn [env]
      (require-age!)
      (let [{:keys [secrets-file] environment-name :name} env
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
          (with-plaintext-temp
            (fn [tmp]
              (spit tmp (user-plaintext (template-content env)))
              (info "Opening" (editor) "…")
              (run-editor! tmp)
              (info "Encrypting…")
              (write-secrets! env target tmp (read-edited! env tmp)
                              (manifest-key-for :create env nil target))
              (report-written! env "Encrypted secrets written:" secrets-file)
              secrets-file)))))))

(defn edit!
  "Edit an existing secrets file through an owner-only plaintext temp file.
  Re-encrypts only when the plaintext changes. Returns the secrets-file path.
  The editor shows the plaintext without the store's metadata, which is put
  back on save. A plaintext that comes back holding the reserved key is
  refused."
  [config env-arg]
  (with-environment-identity config (resolve-env config env-arg)
    (fn [env]
      (require-age!)
      (let [{:keys [secrets-file] environment-name :name} env]
        (require-identity! env)
        (when-not (.exists (io/file secrets-file))
          (fail! :no-file
                 (str "No secrets file at " secrets-file "\n"
                      "    Create one with:  bb secrets new "
                      (shell-quote (clojure.core/name environment-name)))
                 {:secrets-file secrets-file
                  :environment environment-name}))
        (let [target (encrypt-target! env)]
          (with-plaintext-temp
            (fn [tmp]
              (info "Decrypting" secrets-file "…")
              (let [text (decrypt-text! env)
                    store (parse-secrets! secrets-file text nil)
                    ;; A store without usable metadata fails before the editor opens.
                    _ (require-store-metadata! env store)
                    before (user-plaintext text)]
                (spit tmp before :encoding "UTF-8")
                (run-editor! tmp)
                (let [after (read-edited! env tmp)]
                  (if (= before after)
                    (warn "No changes — leaving" secrets-file "untouched.")
                    (do
                      (info "Re-encrypting…")
                      (write-secrets! env target tmp after
                                      (manifest-key-for :update env store target))
                      (report-written! env "Secrets updated:" secrets-file)))))
              secrets-file)))))))

(defn- read-set-value!
  "The value for `set`: one line typed at a hidden terminal prompt when
  `interactive?`, otherwise everything on stdin minus one trailing newline.
  Both are bounded by `max-plaintext-bytes`."
  [env path interactive?]
  (let [limit max-plaintext-bytes
        context {:environment (:name env) :key path}]
    (if interactive?
      (let [value (or (prompt-hidden! (str (question-marker) " Value for " (pr-str path)
                                           " (input hidden): "))
                      "")]
        (when (> (utf8-length value) limit)
          (input-too-large! "The typed value" limit (utf8-length value) context))
        value)
      (strip-trailing-newline
       (read-reader-bounded! *in* limit "Standard input" context)))))

(defn set-secret!
  "Set a value typed at a hidden terminal prompt, or read from stdin when
  stdin is not a terminal. `key-arg` is a keyword or a non-empty vector of
  keyword/string path elements. Piped input loses one trailing newline. The
  value is stored verbatim as a string unless `edn?` is true, in which case
  the input must be one EDN value. Blank input is rejected. Creates a missing
  secrets file from an empty map, then re-encrypts and updates the manifest.
  Returns the secrets-file path. Re-rendering removes plaintext comments."
  [config env-arg key-arg edn?]
  (with-environment-identity config (with-set-usage #(resolve-env config env-arg))
    (fn [env]
      (require-age!)
      (let [path (with-set-usage #(parse-key-path key-arg))
            {:keys [secrets-file]} env
            exists? (.exists (io/file secrets-file))]
        (when exists? (require-identity! env))
        (let [target (encrypt-target! env)
              interactive? (tty?)
              raw (read-set-value! env path interactive?)
              _ (when (str/blank? raw)
                  ;; The same rule the library applies to a set-but-empty
                  ;; SECRETS_AGE_IDENTITY: blank almost always means an unset
                  ;; variable expanded to nothing (`echo "$KEY" | bb secrets
                  ;; set …` in CI), and storing it produces a secret that
                  ;; fails much later, far from the cause.
                  (fail! :blank-value
                         (str (if interactive? "Nothing entered" "Nothing on stdin")
                              " — refusing to store a blank value for " (pr-str path) ".\n"
                              (when-not interactive?
                                "    Pipe the value in:  printf %s \"$VALUE\" | bb secrets set …\n")
                              "    To store an empty value deliberately, use --edn with \"\".")
                         {:key path}))
              value (if edn?
                      (let [{:keys [ok? value] :as parsed}
                            (safe-edn/parse raw)]
                        (if ok?
                          value
                          (fail! (:reason parsed)
                                 (str "Value is not valid EDN ("
                                      (safe-edn/failure-message parsed) ").")
                                 (merge {:key path} (safe-edn/failure-data parsed)))))
                      raw)]
          (with-plaintext-temp
            (fn [tmp]
              (let [store (if exists?
                            (do (info "Decrypting" secrets-file "…")
                                (parse-secrets! secrets-file (decrypt-text! env) nil))
                            (info "No secrets file at" secrets-file "— creating it."))
                    manifest-key (manifest-key-for (if exists? :update :create)
                                                   env store target)
                    current (or (manifest/user-data store) {})]
                (require-map-parents! current path)
                (info (if exists? "Re-encrypting…" "Encrypting…"))
                (write-secrets! env target tmp
                                (render-secrets (assoc-in current path value))
                                manifest-key)
                (report-written! env "Set" (pr-str path) "in" secrets-file)
                secrets-file))))))))

(defn remove-secret!
  "Remove a keyword or vector key path, then re-encrypt and update the
  manifest. Throws when the file or path is absent. Empty parent maps are not
  pruned. Returns the secrets-file path. Re-rendering removes plaintext
  comments."
  [config env-arg key-arg]
  (with-environment-identity config (resolve-env config env-arg)
    (fn [env]
      (require-age!)
      (let [path (parse-key-path key-arg)
            {:keys [secrets-file] environment-name :name} env]
        (require-identity! env)
        (when-not (.exists (io/file secrets-file))
          (fail! :no-file
                 (str "No secrets file at " secrets-file "\n"
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
        (let [target (encrypt-target! env)]
          (info "Decrypting" secrets-file "…")
          (let [store (parse-secrets! secrets-file (decrypt-text! env) nil)
                manifest-key (manifest-key-for :update env store target)
                current (manifest/user-data store)]
            (require-map-parents! current path)
            (when (= ::missing (get-in current path ::missing))
              (fail! :no-such-key
                     (str "No such key: " (pr-str path) " in " secrets-file)
                     {:secrets-file secrets-file :key path}))
            (let [parent (butlast path)
                  k (last path)
                  updated (if (seq parent)
                            (update-in current (vec parent) dissoc k)
                            (dissoc current k))]
              (with-plaintext-temp
                (fn [tmp]
                  (info "Re-encrypting…")
                  (write-secrets! env target tmp (render-secrets updated) manifest-key)
                  (report-written! env "Removed" (pr-str path) "from" secrets-file)
                  secrets-file)))))))))

(defn- show-key-line
  "One line per environment: its public key, or a warning that the key file
  is absent."
  [environment-name key-file pub]
  (if pub
    [:line (format "  %-6s %s" (str (name environment-name) ":") pub)]
    [:warn (format "%s: no key at %s" (name environment-name) key-file)]))

(defn show-key!
  "Print the public key(s). Share these so teammates can encrypt to you.
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
                   (say! [(show-key-line environment-name key-file pub)])
                   [environment-name pub])))
          (distinct-by :key-file envs))))

(defn reencrypt!
  "Decrypt and immediately re-encrypt to the environment's current recipients.
  Use after adding or removing a recipient (an `edit` with no change is a no-op
  and would not pick up recipient changes). The recipient list is snapshotted
  before the decryption, so it is exactly the list the command was started
  against. Returns the secrets-file path.

  Every run generates a new manifest key and rewrites the manifest, so every
  `:vhash` changes once and a removed recipient's copy of the old key says
  nothing about values published afterwards. The existing metadata is not
  read, which makes this the repair for a store whose metadata is missing,
  malformed, or of another version."
  [config env-arg]
  (with-environment-identity config (resolve-env config env-arg)
    (fn [env]
      (require-age!)
      (let [{:keys [secrets-file] environment-name :name} env]
        (require-identity! env)
        (when-not (.exists (io/file secrets-file))
          (fail! :no-file
                 (str "No secrets file at " secrets-file "\n"
                      "    Create one with:  bb secrets new "
                      (shell-quote (clojure.core/name environment-name)))
                 {:secrets-file secrets-file
                  :environment environment-name}))
        (let [target (encrypt-target! env)]
          (with-plaintext-temp
            (fn [tmp]
              (info "Decrypting" secrets-file "…")
              (let [user-text (user-plaintext (decrypt-text! env))]
                (info "Re-encrypting to current recipients…")
                (write-secrets! env target tmp user-text
                                (manifest-key-for :reencrypt env nil target)))
              (report-written! env "Re-encrypted:" secrets-file)
              secrets-file)))))))

(defn- recipient-added-lines
  "The report after a recipient is appended: what to run next, which turns on
  whether a ciphertext already exists to re-encrypt."
  [environment-label recipients-file pub ciphertext?]
  (into [[:ok "Added recipient to" recipients-file]
         [:line "   " pub]]
        (if ciphertext?
          [[:warn "Re-encrypt so the new recipient can read existing secrets:"]
           [:line [:dim (str "      bb secrets reencrypt " (shell-quote environment-label))]]]
          [[:info "No ciphertext exists yet. Create the initial store with either:"]
           [:line [:dim (str "      printf %s \"$VALUE\" | bb secrets set "
                             (shell-quote environment-label) " :secret/key")]]
           [:line [:dim (str "      bb secrets new " (shell-quote environment-label))]]])))

(defn add-recipient!
  "Add an age public key to an environment's recipients file. With no key given,
  adds the environment's own public key (from its key-file). Returns the
  recipient added (or already present)."
  [config env-arg pubkey]
  (require-age!)
  (let [{:keys [recipients-file key-file secrets-file]
         environment-name :name :as env}
        (resolve-env config env-arg)
        environment-label (clojure.core/name environment-name)]
    (when-not recipients-file
      (fail! :no-recipients
             (str environment-label
                  " has no :recipients-file configured (single-key mode).\n"
                  "    Add :recipients-file to its config to encrypt to multiple people.")
             {:environment environment-name}))
    (let [pub (or pubkey (age/public-key key-file))]
      (when-not pub
        (fail! :no-identity
               (str "No public key given and no key at " key-file "\n"
                    "    Generate one with:  bb secrets keygen "
                    (shell-quote environment-label))
               {:key-file key-file
                :environment environment-name}))
      (let [pub (str/trim pub)]
        (when-not (age/valid-recipient? pub)
          (fail! :invalid-recipient "Not a valid age public key."))
        (let [snapshot (recipient-file-snapshot env)
              existing (or (:recipients snapshot) [])]
          (if (some #{pub} existing)
            (do
              (info "Already a recipient of" (str environment-label ":") pub)
              pub)
            (let [current (:content snapshot)
                  content (str current
                               (when (and (seq current)
                                          (not (str/ends-with? current "\n")))
                                 "\n")
                               pub "\n")]
              (when (> (utf8-length content) max-recipients-bytes)
                (input-too-large!
                 (str "The updated recipients file " recipients-file)
                 max-recipients-bytes (utf8-length content)
                 {:recipients-file (str recipients-file)
                  :environment environment-name}))
              (replace-file! recipients-file content)
              (say! (recipient-added-lines environment-label recipients-file pub
                                           (.exists (io/file secrets-file))))
              pub)))))))

(defn- recipients-lines
  "The listing for `recipients`, marking any line encryption would refuse."
  [environment-label recipients-file recipients]
  (if (empty? recipients)
    [[:warn "No recipients yet in" recipients-file]]
    (into [[:line [:bold (str "Recipients for " environment-label
                              " (" recipients-file "):")]]]
          (map (fn [recipient]
                 (if (age/valid-recipient? recipient)
                   [:line "  " recipient]
                   [:line "  " (pr-str (line-prefix recipient))
                    [:yellow "← invalid; encryption refuses this line"]])))
          recipients)))

(defn recipients!
  "List the recipients an environment encrypts to. Returns them as an eager seq
  (nil in single-key mode). Read-only. A line that encryption would reject is
  listed and marked as invalid instead of failing the listing. Throws for an
  unknown environment and for a recipients file that is too large or cannot
  be read."
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
        (say! (recipients-lines environment-label recipients-file recipients))
        recipients))))

(defn- read-manifest-bounded!
  [manifest-path]
  (read-file-bounded! manifest-path max-manifest-bytes "Manifest"
                      {:manifest (str manifest-path)}))

(defn- read-supported-manifest
  "The committed manifest at `manifest-path` as `{:committed value}`, or a
  `{:problem …}` naming why it cannot be compared at all: it is not EDN, or
  `manifest/problem` finds it incomplete. Both the keyless and the keyed check
  start here, so neither compares anything against an incomplete manifest."
  [expected-app manifest-path]
  (let [parsed (safe-edn/parse (read-manifest-bounded! manifest-path))]
    (if-not (:ok? parsed)
      {:problem {:reason :manifest-invalid-edn :failure (safe-edn/failure-data parsed)}}
      (if-let [problem (manifest/problem expected-app (:value parsed))]
        {:problem problem}
        {:committed (:value parsed)}))))

;;; A verification is computed as a *finding*: `:status` (:ok, :ok-keyless,
;;; :drift, :missing, or :error), a `:reason`, and whatever the report needs.
;;; It is rendered by `finding-lines`. `verify-one!` does the reading, hashing,
;;; and decrypting; the two functions between it and the report are pure.

(defn- keyless-finding
  "Freshness without a key: the manifest's recorded `:ciphertext-sha` against
  `actual-sha`, the digest of the ciphertext on disk."
  [committed actual-sha]
  (if (= (:ciphertext-sha committed) actual-sha)
    {:status :ok-keyless :reason :ciphertext-agrees}
    {:status :drift :reason :ciphertext-changed}))

(defn- keyed-finding
  "Full agreement: the committed entries against `fresh`, the entries of the
  decrypted store, plus the recorded `:ciphertext-sha` against `actual-sha`.
  Either disagreement is drift; both are reported. So is
  `recipients-changed?`: the store records a recipient set other than the one
  the environment encrypts to now."
  [committed fresh actual-sha recipients-changed?]
  (let [diff (manifest/diff (:keys committed) fresh)
        stale-entries? (not (every? empty? (vals diff)))
        stale-sha? (not= (:ciphertext-sha committed) actual-sha)]
    (cond
      (or stale-entries? stale-sha?)
      {:status :drift
       :reason :stale
       :diff (when stale-entries? diff)
       :ciphertext-changed? stale-sha?
       :recipients-changed? recipients-changed?}

      recipients-changed?
      {:status :drift :reason :recipients-changed}

      :else
      {:status :ok :reason :manifest-matches})))

(defn- verify-one!
  "Verify one environment's committed manifest against its encrypted secrets,
  returning its finding. When the environment's identity file does not exist,
  which can only be an absent key file, it compares the manifest's recorded
  :ciphertext-sha against the actual ciphertext (freshness only). With an
  identity it decrypts the store and compares its entries, hashed under the
  store's manifest key. A store without usable metadata is drift, reported
  with the message `require-store-metadata!` gives.

  This establishes *agreement* between the two committed artifacts, which is drift
  detection, and never who authored either of them; see [[verify!]]."
  [{:keys [app secrets-file manifest identity-file] :as env}]
  (cond
    (not (string? manifest))
    {:status :ok :reason :manifest-disabled}

    (not (.exists (io/file secrets-file)))
    {:status :missing :reason :no-secrets-file}

    (not (.exists (io/file manifest)))
    {:status :missing :reason :no-manifest}

    :else
    (try
      (let [{:keys [committed problem]} (read-supported-manifest app manifest)]
        (cond
          problem
          (assoc problem :status :drift)

          (not (.exists (io/file identity-file)))
          (keyless-finding committed (sha256 secrets-file))

          :else
          (let [{:keys [ok? value] :as parsed} (safe-edn/parse (decrypt-text! env))]
            (if ok?
              (let [{:keys [manifest-key recipients]} (require-store-metadata! env value)
                    current (manifest/recipients-id
                             (when (:recipients-file env) (recipient-snapshot env)))]
                (keyed-finding committed
                               (manifest/entries value manifest-key)
                               (sha256 secrets-file)
                               (not= recipients current)))
              {:status :drift
               :reason :secrets-invalid-edn
               :failure (safe-edn/failure-data parsed)}))))
      (catch clojure.lang.ExceptionInfo e
        ;; A manifest or store past its size bound, and a store without
        ;; usable metadata, cannot agree with any manifest.
        (if (#{:input-too-large :invalid-store} (:reason (ex-data e)))
          {:status :drift :reason :store-problem :message (ex-message e)}
          (throw e))))))

(defn- diff-lines
  "One line per key path that moved between the manifest and the store."
  [{:keys [added removed changed]}]
  (concat
   (for [path added] [:line "    +" (pr-str path) "— in secrets, missing from manifest"])
   (for [path removed] [:line "    -" (pr-str path) "— in manifest, gone from secrets"])
   (for [path changed] [:line "    ~" (pr-str path) "— value or type changed"])))

(defn- finding-lines
  "The report for one environment's finding."
  [{:keys [app secrets-file manifest] environment-name :name}
   {:keys [reason] :as finding}]
  (let [label (name environment-name)
        regenerate [:line (str "    Regenerate it with:  bb secrets reencrypt "
                               (shell-quote label))]
        recipients-changed [:oops label
                            "— recipients changed since the last encryption; run reencrypt."]]
    (case reason
      :manifest-disabled
      [[:info label "— manifest disabled; skipping."]]

      :no-secrets-file
      [[:warn label "— no secrets file at" secrets-file]]

      :no-manifest
      [[:warn label "— no manifest at" manifest
        (str "(run `bb secrets edit " (shell-quote label) "` to create it)")]]

      :manifest-invalid-edn
      [[:oops label "— manifest is not valid EDN:" (safe-edn/failure-message (:failure finding))]]

      :manifest-malformed
      [[:oops label "— manifest is incomplete: expected a map with a :ciphertext-sha"
        "and a :keys map whose every entry has a :type and a :vhash."]
       regenerate]

      :unsupported-version
      [[:oops label "— manifest version" (pr-str (:version finding))
        "is unsupported by this version of the library."]
       regenerate
       [:line "    Or upgrade the library."]]

      :wrong-app
      [[:oops label "— manifest describes app" (pr-str (:app finding))
        (str "but this project is " (pr-str app) ".")]
       [:line "    It belongs to a different store."]
       regenerate]

      :error
      (into [[:oops label "—" (:message finding)]]
            (when-let [hint (:hint finding)] [[:line "   " hint]]))

      :ciphertext-agrees
      [[:ok label "— ciphertext agrees with the manifest"
        "(freshness only: no key, so values are not checked)."]]

      :ciphertext-changed
      [[:oops label "— ciphertext changed since the manifest was written"
        (str "(" manifest ").")]
       regenerate]

      :store-problem
      [[:oops label "—" (:message finding)]]

      :secrets-invalid-edn
      [[:oops label "— encrypted secrets are not valid EDN:"
        (safe-edn/failure-message (:failure finding))]]

      :stale
      (-> []
          (into (when-let [diff (:diff finding)]
                  (cons [:oops label "— manifest is STALE" (str "(" manifest "):")]
                        (diff-lines diff))))
          (into (when (:ciphertext-changed? finding)
                  [[:oops label
                    "— ciphertext digest differs from the one the manifest records."]]))
          (into (when (:recipients-changed? finding) [recipients-changed]))
          (conj regenerate))

      :recipients-changed
      [recipients-changed
       [:line (str "    The store is still encrypted to the earlier recipients:"
                   "  bb secrets reencrypt " (shell-quote label))]]

      :manifest-matches
      [[:ok label "— manifest matches" (str "(" manifest ")")]])))

(defn verify!
  "Check that each environment's committed manifest matches its encrypted
  secrets. With no env, verifies all of them. Returns
  {:results {env-name status} :exit code}, where each status is :ok,
  :ok-keyless, :drift, :missing, or :error.

  The exit code is 0 when everything agrees and 1 when the only problem is
  drift. It is 2 when anything else stopped an environment from being
  verified: a missing secrets file or manifest, an identity that does not
  resolve, a store the identity cannot decrypt, or a file that cannot be read.
  Such a failure is reported as that environment's :error and the other
  environments are still verified. The one failure that throws is an unknown
  or missing environment argument.

  Every manifest has to be complete before anything is compared: the supported
  `:version`, this project's `:app`, a `:ciphertext-sha`, and a `:keys` map
  whose every entry has a `:type` and a `:vhash`. Anything else is drift, with
  or without an identity. Keyless verification then compares the ciphertext
  hash and does not require age. It applies when no identity was designated
  and the environment's key file is absent. Full verification decrypts and
  also compares the store's entries, hashed under the store's manifest key, so
  a changed value fails it in solo and team stores alike.

  A store whose metadata is missing, malformed, or of another version is
  drift: it cannot agree with any manifest, and the report says that
  `reencrypt` writes a current one. So is a store that records a recipient
  set other than the one its environment encrypts to now, which is what a
  recipients file edited without a `reencrypt` looks like.

  A pass means the ciphertext and the manifest agree, which detects drift and
  a manifest from the wrong store. It does not establish authorship, even when
  run with an identity: age does not sign, and everyone who can decrypt the
  store holds its manifest key, so no run of this can say who wrote either
  artifact. Authenticity rests on the repository and deployment channel; see
  `doc/threat-model.md`."
  [config env-arg]
  (let [envs (if env-arg
               [(resolve-env config env-arg)]
               (vals (:environments config)))
        verify-env (fn [env]
                     (try
                       (with-environment-identity config env
                         (fn [env] [env (verify-one! env)]))
                       (catch Exception e
                         [env {:status :error
                               :reason :error
                               :message (failure-message e)
                               :hint (:hint (ex-data e))}])))
        results (into {}
                      (map (fn [env]
                             (let [[env finding] (verify-env env)]
                               (say! (finding-lines env finding))
                               [(:name env) (:status finding)])))
                      envs)
        statuses (set (vals results))]
    {:results results
     :exit (cond (some statuses [:missing :error]) 2
                 (statuses :drift) 1
                 :else 0)}))

;;;; Doctor

(def ^:private identity-failure-reasons
  "The reasons a failed identity resolution carries: a blank or undecodable
  variable, a path that is not a local path, and a designated file that does
  not exist."
  #{:invalid-identity :disallowed-identity :no-identity})

(defn- doctor-report
  "Diagnose normalized environment `env`. `identity-problem` is the message of
  a failed identity resolution, or nil when `env` carries a resolved identity.
  A warning is something an operator would act on that stops no command from
  being tried: a file that is not there yet, or `age` not being installed. A
  problem is an identity that does not resolve, or a recipients file that
  lists nobody or holds a line age would refuse."
  [{:keys [secrets-file manifest recipients-file identity-file identity-source]
    environment-name :name :as env}
   identity-problem]
  (let [exists? #(boolean (and % (.exists (io/file (str %)))))
        label (shell-quote (name environment-name))
        version (age/version)
        recipients (when (exists? recipients-file) (read-recipients env))
        invalid (count (remove age/valid-recipient? recipients))
        injected? (#{:secrets-age-identity :secrets-age-identity-b64} identity-source)
        warnings
        (cond-> []
          (nil? version)
          (conj "age is not installed, so nothing can be encrypted or decrypted.")
          (not (exists? secrets-file))
          (conj (str "No secrets file yet. Create it with:  bb secrets new " label))
          (and (string? manifest) (exists? secrets-file) (not (exists? manifest)))
          (conj (str "No manifest. Write it with:  bb secrets reencrypt " label))
          (and recipients-file (not (exists? recipients-file)))
          (conj (str "No recipients file yet. Start it with:  bb secrets add-recipient " label))
          (not (or identity-problem (exists? identity-file)))
          (conj (str "No identity, so only keyless verification works here."
                     " Create a key with:  bb secrets keygen " label)))
        problems
        (cond-> []
          identity-problem (conj identity-problem)
          (and recipients (empty? recipients))
          (conj (str "The recipients file lists nobody. Add a key with:"
                     "  bb secrets add-recipient " label))
          (pos? invalid)
          (conj (str invalid " recipients file line(s) are not age recipients."
                     " `bb secrets recipients " label "` marks them.")))]
    (cond-> {:environment environment-name
             :age version
             :secrets-file {:path secrets-file :exists? (exists? secrets-file)}
             :manifest (when (string? manifest)
                         {:path manifest :exists? (exists? manifest)})
             :identity {:source identity-source
                        :path (when-not injected? identity-file)
                        :exists? (exists? identity-file)}
             :warnings warnings
             :problems problems
             :exit (cond (seq problems) 2 (seq warnings) 1 :else 0)}
      recipients-file
      (assoc :recipients-file {:path recipients-file
                               :exists? (exists? recipients-file)
                               :count (count recipients)}))))

(defn- doctor-lines
  "The `doctor` report. It prints paths and counts, and never file contents,
  recipient lines, or environment values."
  [{:keys [environment age secrets-file manifest recipients-file identity warnings problems
           exit]}]
  (let [artifact (fn [{:keys [path exists?]}]
                   (str path (if exists? " (present)" " (missing)")))]
    (concat
     (when environment
       (cond-> [[:line "Environment:" (name environment)]
                [:line "age:" (or age "not installed")]
                [:line "Secrets file:" (artifact secrets-file)]
                [:line "Manifest:" (if manifest (artifact manifest) "disabled")]]
         recipients-file
         (conj [:line "Recipients file:" (artifact recipients-file)]
               [:line "Recipients:" (:count recipients-file)])
         true
         (conj [:line "Identity:"
                (str (identity-source-display-label (:source identity))
                     (when (:path identity) (str " " (:path identity)))
                     (if (:exists? identity) " (present)" " (missing)"))])))
     (for [warning warnings] [:line "Warning:" warning])
     (for [problem problems] [:line "Problem:" problem])
     [[:line "Status:" (case (int exit) 0 "healthy" 1 "warning" 2 "invalid")]]
     (when (zero? exit)
       [[:line "Run `bb secrets verify` to check the store against its manifest."]]))))

(defn doctor!
  "Diagnose the setup of one selected or default environment. Accepts raw
  config, prints a short report, and returns it as a map. It never exits.

  The map holds `:environment`, `:age` (the installed version, or nil),
  `:secrets-file` and `:manifest` (each `{:path :exists?}`, and `:manifest`
  nil when disabled), `:recipients-file` in team mode (`{:path :exists?
  :count}`), `:identity` (`{:source :path :exists?}`, with no path for an
  identity injected as contents), `:warnings` and `:problems` (vectors of
  messages), and `:exit`.

  `:exit` is 0 when healthy. It is 1 on a warning: `age` is not installed, or
  the secrets file, the manifest, the recipients file, or the key is not
  there yet. It is 2 on a problem: an identity that does not resolve, a
  recipients file that lists nobody or holds an invalid line, or anything
  that stopped the diagnosis, such as an invalid configuration or an unknown
  environment, in which case the map holds only `:problems` and `:exit`. A
  missing template is not reported. `doctor` does not open the store or the
  manifest: `verify` does that."
  [config env-arg]
  (let [result (try
                 (let [config (normalize-config config)
                       env (resolve-env config env-arg)]
                   (try
                     (with-environment-identity config env #(doctor-report % nil))
                     (catch clojure.lang.ExceptionInfo e
                       (if (identity-failure-reasons (:reason (ex-data e)))
                         (doctor-report (merge env (select-keys (ex-data e)
                                                                [:identity-file :identity-source]))
                                        (ex-message e))
                         (throw e)))))
                 (catch clojure.lang.ExceptionInfo e
                   (when (= :private-file-remains (:reason (ex-data e)))
                     (throw e))
                   {:problems [(ex-message e)] :exit 2}))]
    (say! (doctor-lines result))
    result))

;;;; Dispatch

(defn- error-lines
  "Render the error and its remediation on stderr."
  [e]
  (let [data (ex-data e)]
    (into [[:oops (failure-message e)]]
          (for [k [:hint :install :error :docs]
                :let [v (get data k)]
                :when (and (some? v) (not (str/blank? (str v))))
                line (str/split-lines (str/trim-newline (str v)))]
            [:stderr "   " line]))))

(defn- env-command
  "The `:run` of a command whose one optional argument is an environment."
  [f]
  (fn [config [env] _flags] (f config env)))

(defn- env-and-key
  "The `[env key]` of a command that takes `[env] <key>`: one argument is the
  key in the default environment."
  [args]
  (if (next args) args [nil (first args)]))

(def ^:private commands
  "Every command. `:args` is its positional arguments as usage text, `<x>`
  required and `[x]` optional, and it is also what bounds how many are
  accepted. `:flags` maps each flag the command takes to its help line. `:run`
  is called with the normalized config (the config as given when `:raw-config?`),
  the positional arguments, and the set of flags present. `help` has no `:run`:
  the dispatcher answers it from this table."
  [{:name "keygen" :args "[env]"
    :doc "Generate an age key for an environment."
    :run (env-command #'keygen!)}
   {:name "new" :args "[env]"
    :doc "Create a new encrypted secrets file (opens your editor)."
    :run (env-command #'new!)}
   {:name "edit" :args "[env]"
    :doc "Edit an existing secrets file (decrypt, edit, then re-encrypt)."
    :run (env-command #'edit!)}
   {:name "set" :args "[env] <key>"
    :flags {"--edn" "Parse the value as EDN instead of storing it verbatim as a string."}
    :doc (str "Set a key from a hidden prompt, or from stdin when it is not a terminal.\n"
              "The value is never read from the command line.")
    :run (fn [config args flags]
           (let [[env k] (env-and-key args)]
             (set-secret! config env k (contains? flags "--edn"))))}
   {:name "rm" :args "[env] <key>"
    :doc "Remove a key."
    :run (fn [config args _flags]
           (let [[env k] (env-and-key args)]
             (remove-secret! config env k)))}
   {:name "verify" :args "[env]"
    :doc "Check that the committed manifest matches the secrets."
    :run (env-command #'verify!)}
   {:name "doctor" :args "[env]" :raw-config? true
    :doc "Report on the setup: age, files, identity, and recipients."
    :run (env-command #'doctor!)}
   {:name "show-key" :args "[env]"
    :doc "Print public keys for sharing."
    :run (env-command #'show-key!)}
   {:name "add-recipient" :args "[env] [public-key]"
    :doc (str "Add a public key to an environment's recipients file.\n"
              "Without a key it adds the environment's own.")
    :run (fn [config [env public-key] _flags] (add-recipient! config env public-key))}
   {:name "recipients" :args "[env]"
    :doc "List configured recipient public keys."
    :run (env-command #'recipients!)}
   {:name "reencrypt" :args "[env]"
    :doc "Re-encrypt to the current recipients after a change."
    :run (env-command #'reencrypt!)}
   {:name "help" :args "[command]"
    :doc "Show this help, or the help of one command."}])

(defn- usage
  "The usage line of command table entry `command`."
  [{:keys [args flags] command-name :name}]
  (str/join " " (concat ["bb secrets" command-name args]
                        (map #(str "[" % "]") (keys flags)))))

(defn- command-help-lines
  [{:keys [doc flags] :as command}]
  (concat [[:line "Usage:" (usage command)]
           [:line]
           [:line doc]
           [:line]
           [:line "Options:"]]
          (for [[flag text] (assoc flags "-h, --help" "Show this help.")]
            [:line (format "  %-12s %s" flag text)])))

(defn- help-lines
  "The global help. It is built before the config is validated, so it lists
  environments only when they have the valid shape."
  [{:keys [environments default-environment]}]
  (concat
   [[:line "Manage encrypted secrets (age)."]
    [:line]
    [:line "Usage: bb secrets <command> [arguments]"]
    [:line]
    [:line "Commands:"]]
   (for [{:keys [args doc] command-name :name} commands]
     [:line (format "  %-34s %s" (str command-name " " args) (first (str/split-lines doc)))])
   [[:line]
    [:line (str "Environments: "
                (when (and (map? environments) (every? keyword? (keys environments)))
                  (str/join ", " (map name (keys environments))))
                (when (keyword? default-environment)
                  (str " (default: " (name default-environment) ")")))]
    [:line]
    [:line "An omitted [env] uses the default environment."]
    [:line "-- ends the options: everything after it is an argument, even -h or --edn."]
    [:line "Run `bb secrets <command> --help` for one command's usage."]
    [:line "Commands printed as suggestions are POSIX sh, single-quoted per argument."]
    [:line "verify exits 0 when every manifest agrees, 1 when the only problem is drift,"]
    [:line "  and 2 when anything else stopped it: a missing file, an identity or"]
    [:line "  decryption failure, an unknown environment, or an invalid configuration."]
    [:line "doctor exits 0 when healthy, 1 on a warning, and 2 on an invalid configuration,"]
    [:line "  identity, or recipients file, or when it could not run."]
    [:line "Every other command exits 0, or 1 on any failure."]]))

(defn- find-command
  "The table entry named `command-name`, in any letter case. An unknown name
  fails without being repeated: it may be a value typed in the wrong place."
  [command-name]
  (or (some #(when (= (str/lower-case command-name) (:name %)) %) commands)
      (fail! :usage "Unknown command. Run `bb secrets help` for the list.")))

(defn- dispatch!
  "Run the command `args` names against `config` and return its result.

  Before a `--`, an argument that starts with `-` is a flag and every other
  argument is positional. Everything after the `--` is positional. A flag the
  command does not define, and a positional argument it has no place for, are
  usage errors. Those errors print the command's usage and never the
  argument: it is not a known command, flag, or environment name, and may be
  a secret typed in the wrong place."
  [config [command-name & more]]
  (let [[before after] (split-with #(not= "--" %) more)
        flag? #(str/starts-with? % "-")
        flags (set (filter flag? before))
        positionals (into (vec (remove flag? before)) (rest after))
        help? (or (nil? command-name) (some #{"-h" "--help"} (cons command-name flags)))
        command (when-not (contains? #{nil "-h" "--help"} command-name)
                  (find-command command-name))
        problem (when command
                  (cond
                    (seq (remove (set (keys (:flags command))) (disj flags "-h" "--help")))
                    "Unknown option."
                    (< (count positionals) (count (re-seq #"<" (:args command))))
                    "Missing argument."
                    (> (count positionals) (count (str/split (:args command) #" ")))
                    "Too many arguments."))]
    (cond
      (nil? command) (say! (help-lines config))
      help? (say! (command-help-lines command))
      problem (fail! :usage (str problem " Usage: " (usage command)))
      (= "help" (:name command)) (say! (if-let [target (first positionals)]
                                         (command-help-lines (find-command target))
                                         (help-lines config)))
      :else ((:run command)
             (if (:raw-config? command) config (normalize-config config))
             positionals
             flags))))

(def ^:private status-commands
  "The commands whose exit code is a status: 1 is drift or a warning, so a
  failure to run them at all is 2."
  #{"verify" "doctor"})

(defn- exit!
  "Leave the process boundary with exit `code`, returning only when it is 0.
  On the JVM the agent threads that `future` and `clojure.java.shell` start
  keep a finished process alive for a minute, so they are shut down here.
  Babashka exits without that, and a task may go on to use them."
  [code]
  (when-not (System/getProperty "babashka.version")
    (shutdown-agents))
  (when (pos? code)
    (System/exit code)))

(defn run!
  "Dispatch `args` against `config` as the whole of a process: the entry point
  for a `bb` task or a JVM `-main`, not a function to call at a REPL, where
  the command functions are the API. This is the one place an exit code is
  decided.

  A failure prints one line, and any hint the failure carries, on stderr, and
  never a stack trace. It exits 1, or 2 from `verify` and `doctor`, which
  keep 1 for drift and for a warning and otherwise exit with the `:exit` of
  their result. On the JVM a successful run shuts down the agent thread
  pools, so the process ends as soon as the command does."
  [config args]
  (let [status-command? (contains? status-commands (some-> (first args) str str/lower-case))
        exit (try
               (let [result (dispatch! config args)]
                 (if status-command? (:exit result 0) 0))
               (catch Exception e
                 (say! (error-lines e))
                 (if status-command? 2 1)))]
    (exit! exit)))
