(ns com.kirahowe.secrets.store
  "Implementation namespace; not part of the public API and may change without notice.

  The store beneath the `bb secrets` commands: config normalization and
  validation, recipients, the store's metadata and manifest key, encrypting and
  decrypting the store, writing it with its manifest, and verifying the two
  against each other. Nothing here prompts, opens an editor, or prints.
  `com.kirahowe.secrets.cli` does that and calls into this namespace."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.fs :as fs]
            [com.kirahowe.secrets.identity :as identity]
            [com.kirahowe.secrets.keychain :as keychain]
            [com.kirahowe.secrets.manifest :as manifest]
            [com.kirahowe.secrets.safe-edn :as safe-edn]
            [com.kirahowe.secrets.source :as source]))

;;;; Failures and shell words

(defn shell-quote
  "Render `s` as a single POSIX `sh` word: wrapped in `'`, with each embedded
  `'` written as `'\\''`. The empty string renders as `''`. Inside single
  quotes every other character is literal, so no escaping rule is needed."
  [s]
  (str "'" (str/replace (str s) "'" "'\\''") "'"))

(defn fail!
  "Throw an `ex-info` for a user-facing failure, with `reason` as its
  `:reason`. `run!` prints the message plus any :hint, :install, :error, or
  :docs in the data."
  ([reason msg] (fail! reason msg nil))
  ([reason msg data] (throw (ex-info msg (assoc data :reason reason)))))

(defn failure-message
  "One line saying what failure `e` was, holding no file contents. An
  `ex-info` gives its own message. Any other exception gives its class, plus
  its message when it is an `IOException`, whose message names a path."
  [e]
  (cond
    (instance? clojure.lang.ExceptionInfo e) (ex-message e)
    (instance? java.io.IOException e) (str (.getName (class e)) ": " (ex-message e))
    :else (str "Unexpected failure: " (.getName (class e)))))

(defn exit!
  "End the process with exit `code`, returning only when it is 0. The CLI and
  the initializer leave through here, and it is the seam their tests replace."
  [code]
  (when (pos? code)
    (System/exit code)))

;;;; Config

(defn- canonical-path
  "Canonicalize `path`, so aliases like `./key.txt` and `key.txt` compare
  equal."
  [path]
  (.getCanonicalPath (io/file (str path))))

(defn- require-path!
  "Reject a blank path, a URI-shaped path, and key contents in a path field,
  returning `path` otherwise.

  CLI artifacts are local filesystem paths. The failure names the environment
  and field and never the value. `:key-file` fails with `:reason
  :disallowed-identity`, as the runtime's identity paths do, and every other
  field with `:invalid-config`. Non-string values such as `:manifest false`
  keep their meaning."
  [env kind path]
  (when (and (string? path) (str/blank? path))
    (fail! :invalid-config
           (str "Environment " (name env) " has a blank " kind
                " (a path string must not be empty).\n"
                "    An empty path resolves to the working directory, not a file.")
           {:environment env :field kind :path path}))
  (when-let [problem (and (string? path) (source/path-problem path))]
    (fail! (if (= :key-file kind) :disallowed-identity :invalid-config)
           (source/path-problem-message (str "Environment " (name env) " " kind)
                                        "a local filesystem path"
                                        problem)
           (cond-> {:environment env :field kind}
             (:scheme problem) (assoc :scheme (:scheme problem)))))
  path)

(def ^:private path-purposes
  "What each path setting of an environment is for. `:identity-file` is not
  a setting: it is the path SECRETS_AGE_IDENTITY_FILE gave a running command.
  It and `:key-file` both name an identity, so one file may be both."
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
               {:label (if (= :identity-file setting)
                         "SECRETS_AGE_IDENTITY_FILE"
                         (str (name (:name env)) " " setting))
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
                  "\n    A file is a secrets file, a manifest, a template, an identity, or"
                  " a recipients file,\n    and only one of them. Two environments share a"
                  " secrets file or a manifest only\n    when they share both.")
             {:settings [(:label a) (:label b)]}))))

(def max-recipients-bytes
  "The most bytes a recipients file may hold (256 KiB). It catches an
  accidental huge input, such as a path that names the wrong file."
  262144)

(def max-plaintext-bytes
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
  "Every key an environment's config may hold. Each names a path, except
  `:key-command`, a program and its arguments."
  #{:secrets-file :key-file :key-command :template :manifest :recipients-file})

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
  [app environment-name env-config]
  (let [label (name environment-name)]
    (reject-unknown-keys! (str "Environment " label) environment-keys env-config)
    (when-let [command (:key-command env-config)]
      (when-not (identity/valid-key-command? command)
        (fail! :invalid-config
               (str "Environment " label " :key-command must be a vector of non-blank strings,"
                    " a program and its arguments.")
               {:environment environment-name :field :key-command}))
      (when (contains? env-config :key-file)
        (fail! :invalid-config
               (str "Environment " label " has both :key-file and :key-command. Its key"
                    " lives in one place: keep one of them.")
               {:environment environment-name})))
    (doseq [[k v] (dissoc env-config :key-command)]
      (when-not (or (string? v) (and (= :manifest k) (false? v)))
        (fail! :invalid-config
               (str "Environment " label " " k " must be a path string"
                    (when (= :manifest k) ", or false to keep no manifest")
                    ", not a value of type " (name (manifest/value-type v)) ".")
               {:environment environment-name :field k})))
    (when-not (:secrets-file env-config)
      (fail! :invalid-config
             (str "Environment " label " has no :secrets-file (a path string is required).")
             {:environment environment-name}))
    ;; One rule for every path setting: a leading `~` is the home directory.
    (let [{:keys [secrets-file] :as paths}
          (update-vals env-config #(if (string? %) (fs/expand-home %) %))
          derived #(str/replace secrets-file #"\.age$" %)
          ;; An explicit :manifest false is kept. Absent values are derived
          ;; from the secrets file.
          env (merge {:template (derived ".example")
                      :manifest (derived ".manifest")
                      :recipients-file nil}
                     paths
                     {:name environment-name :app app})]
      (require-path! environment-name :secrets-file secrets-file)
      (when (and (not (str/ends-with? secrets-file ".age"))
                 (not (and (contains? env-config :template)
                           (contains? env-config :manifest))))
        (fail! :invalid-config
               (str "Environment " label " :secrets-file (" secrets-file
                    ") does not end in .age, so the\n"
                    "    derived :template/:manifest names would collide with, and overwrite, "
                    "the\n"
                    "    ciphertext itself. Use a .age extension, or set :template and :manifest\n"
                    "    explicitly.")
               {:environment environment-name
                :secrets-file secrets-file}))
      (doseq [kind [:key-file :template :manifest :recipients-file]
              :when (contains? env kind)]
        (require-path! environment-name kind (get env kind)))
      env)))

(defn normalize-config
  "Validate a secrets config as it is written in `bb.edn` and return it with
  per-environment defaults (:template, :manifest) applied. The
  command functions take the result. A config this function returned comes
  back unchanged.

  Requires a non-blank :app and at least one environment, each a map with a
  :secrets-file. Every environment setting except :key-command is a path
  string with a leading `~` expanded, and :manifest may also be false.
  :key-command is a vector of strings, and an environment names at most one
  of :key-file and :key-command. A secrets path not ending in
  `.age` requires explicit :template and :manifest values. No file may serve two purposes across the
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
                    "    app's macOS Keychain item and is recorded in the manifest, so there\n"
                    "    is deliberately no default: projects must not share a key by accident.")))
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

(defn resolve-env
  "Resolve an environment argument string to its (defaulted) config map.
  Throws (via `fail!`) on a missing or unknown environment. An unknown name is
  not repeated: it may be a value typed where the environment goes."
  [{:keys [environments default-environment]} env-arg]
  (let [env-key (if (nil? env-arg) default-environment (keyword env-arg))]
    (or (get environments env-key)
        (fail! :usage
               (str (if (nil? env-arg) "Missing environment." "Unknown environment.")
                    " One of: " (str/join ", " (map name (keys environments))))))))

(defn with-environment-identity
  "Resolve the environment's identity once and call `f` with the environment
  and that identity merged, so one key serves the command's decryption and
  hashing. An identity path that came from SECRETS_AGE_IDENTITY_FILE was not
  in the config when its paths were checked, so it is checked against them
  here."
  [config env f]
  (let [identity (secrets/resolve-identity env)
        resolved (merge env identity)]
    (when (= :secrets-age-identity-file (:identity-source identity))
      (reject-shared-paths! (assoc (:environments config) (:name env) resolved)))
    (f resolved)))

(defn identity-of
  "The identity in a resolved environment, as `age` takes it."
  [env]
  (select-keys env [:identity-file :identity-contents]))

(defn own-public-key
  "The public key of the key the environment keeps for itself (see
  [[com.kirahowe.secrets.identity/key-identity]]), ignoring the SECRETS_AGE_IDENTITY*
  variables, or nil when there is no such key."
  [env]
  (let [own (identity/key-identity env)]
    (when (secrets/identity-available? own)
      (age/public-key own))))

(defn key-location
  "Describe where the environment's own key lives, for messages: its
  `:key-file`, its `:key-command`, or the macOS Keychain item for its app."
  [{:keys [app key-file key-command]}]
  (cond
    key-file key-file
    key-command (str ":key-command " (first key-command))
    (keychain/available?) (str "the macOS Keychain (" keychain/service ", account " app ")")
    :else "nowhere: set :key-file or :key-command"))

;;;; Bounded reads

(defn input-too-large!
  "Fail because `what`, a short description that names the file where there is
  one, holds `observed` bytes against a bound of `limit`."
  [what limit observed context]
  (fail! :input-too-large
         (str what " is larger than the " limit " byte limit.")
         (merge context {:limit limit :observed observed})))

(defn utf8-length [^String s]
  (alength (.getBytes s java.nio.charset.StandardCharsets/UTF_8)))

(defn read-file-bounded!
  "Read the file at `path` as UTF-8 text, failing when it holds more than
  `limit` bytes. `kind` and `context` describe it in the failure."
  [path limit kind context]
  (let [f (io/file (str path))]
    (when (> (.length f) limit)
      (input-too-large! (str kind " " path) limit (.length f) context))
    (try
      (slurp f :encoding "UTF-8")
      (catch java.io.IOException e
        (fail! :no-file
               (str kind " " path " could not be read (" (.getSimpleName (class e)) ").")
               context)))))

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
        (fail! :no-file
               (str "File " path " could not be read (" (.getSimpleName (class e)) ")."))))
    (apply str (map #(format "%02x" %) (.digest md)))))

(defn require-identity!
  "Require the resolved identity, naming where it looked when there is none."
  [{environment-name :name :keys [identity-file] :as env}]
  (when-not (secrets/identity-available? env)
    (fail! :no-identity
           (str "No age identity for " (name environment-name)
                (if identity-file (str " at " identity-file) (str " in " (key-location env)))
                "\n"
                (when (or identity-file (keychain/available?))
                  (str "    Create one with:  bb secrets keygen "
                       (shell-quote (name environment-name)) "\n"))
                "    Or point at an existing key via SECRETS_AGE_IDENTITY_FILE (a path),\n"
                "    SECRETS_AGE_IDENTITY (raw key contents), or "
                "SECRETS_AGE_IDENTITY_B64 (base64 contents).")
           (cond-> {:environment environment-name}
             identity-file (assoc :identity-file identity-file)))))

;;;; Recipients (multi-recipient mode)

(defn line-prefix
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

(defn recipient-file-snapshot
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

(defn read-recipients [env]
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

(defn encrypt-target!
  "The immutable age recipient spec to encrypt with, resolved once before any
  sensitive work begins (before an editor opens, before stdin is read, before
  anything is decrypted) and threaded down to `age/encrypt-file!` from there.

  Multi-recipient mode returns the validated `{:recipients [\"age1…\" …]}`
  snapshot, so age receives repeated `-r` values and no pathname to re-read.
  Single-key mode returns the environment's resolved identity (so
  SECRETS_AGE_IDENTITY* works in CI too)."
  [{:keys [recipients-file] :as env}]
  (if recipients-file
    {:recipients (recipient-snapshot env)}
    (do (require-identity! env)
        (identity-of env))))

;;;; Store metadata

(defn require-store-metadata!
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

(defn manifest-key-for
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
        (manifest/generate-key)))
    (manifest/generate-key)))

(defn parse-secrets!
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

(defn decrypt-text!
  "The environment's decrypted store as text, library metadata included. A
  ciphertext past `source/max-source-bytes` is refused with `:source-too-large`
  before it is decrypted, as `load-secrets` refuses it, which bounds the
  plaintext too: age does not compress."
  [{:keys [secrets-file] :as env}]
  (let [size (.length (io/file (str secrets-file)))
        limit source/max-source-bytes]
    (when (> size limit)
      (fail! :source-too-large
             (str "The secrets file " secrets-file " is larger than the " limit " byte limit.")
             {:secrets-file (str secrets-file) :limit limit :observed size})))
  (age/decrypt (identity-of env) secrets-file))

;;;; Plaintext and writing

(defn replace-file!
  "Atomically replace public artifact `target` with the text `content`,
  staged beside it. The staging file is deleted on any failure."
  [target content]
  (let [staging (fs/staging-file target)]
    (try
      (spit staging content)
      (fs/atomic-move! staging target)
      (finally (.delete staging)))))

(defn append-recipient!
  "Write the environment's recipients file with `pub` added as its last line.
  `current` is the file's text as `recipient-file-snapshot` read it, or nil."
  [{:keys [recipients-file] environment-name :name} current pub]
  (let [content (str current
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
    (replace-file! recipients-file content)))

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

(defn user-plaintext
  "Return store or template text without the library's metadata line, exactly
  as the user wrote it. Text without that line comes back unchanged."
  [text]
  (let [opening (map-opening text)
        line (when opening (re-find metadata-line-re (subs text opening)))]
    (if line
      (str (subs text 0 opening) (subs text (+ opening (count line))))
      text)))

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

(defn write-secrets!
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

;;;; Verifying

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

(defn verify-one!
  "Verify one environment's committed manifest against its encrypted secrets,
  returning its finding. When the environment has no identity, which can
  only be an absent key file or Keychain item, it compares the manifest's recorded
  :ciphertext-sha against the actual ciphertext (freshness only). With an
  identity it decrypts the store and compares its entries, hashed under the
  store's manifest key. A store without usable metadata is drift, reported
  with the message `require-store-metadata!` gives.

  This establishes *agreement* between the two committed artifacts, which is drift
  detection, and never who authored either of them; see [[verify!]]."
  [{:keys [app secrets-file manifest] :as env}]
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

          (not (secrets/identity-available? env))
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
        ;; usable metadata, cannot agree with any manifest. A recipients
        ;; file past its bound is not drift, and propagates as an error.
        (if (or (#{:source-too-large :invalid-store} (:reason (ex-data e)))
                (and (= :input-too-large (:reason (ex-data e))) (:manifest (ex-data e))))
          {:status :drift :reason :store-problem :message (ex-message e)}
          (throw e))))))
