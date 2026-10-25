(ns com.kirahowe.secrets.cli
  "The `bb secrets` management task: the prompts, the editor, the reports, and
  command dispatch over `com.kirahowe.secrets.store`.

      ;; bb.edn
      {:tasks {secrets {:requires ([com.kirahowe.secrets.cli :as cli])
                        :task (cli/run! my-config *command-line-args*)}}}

  `run!` is the process entry point and the only place that prints a failure
  and exits: 1 on failure, except `verify` and `doctor`, which use 1 for drift
  or a warning and 2 for any failure. `normalize-config` validates a config
  map. The README describes the config keys and how a command resolves its
  identity.

  The command functions (`keygen!`, `new!`, `edit!`, `set-secret!`,
  `remove-secret!`, `verify!`, `doctor!`, `show-key!`, `add-recipient!`,
  `recipients!`, `reencrypt!`) are the API for a REPL or a program. They
  return data (a path, a results map, or :aborted), throw `ex-info` with a
  `:reason` on failure, and never exit. `verify!` and `doctor!` report most
  failures in their result, with the exit code under `:exit`."
  (:refer-clojure :exclude [run!])
  (:require [clojure.java.io :as io]
            [clojure.pprint :as pprint]
            [clojure.string :as str]
            [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.fs :as fs]
            [com.kirahowe.secrets.keychain :as keychain]
            [com.kirahowe.secrets.manifest :as manifest]
            [com.kirahowe.secrets.safe-edn :as safe-edn]
            [com.kirahowe.secrets.store :as store :refer [fail! shell-quote]]))

;;;; Output

;;; A report is a vector of *lines*: `[level & segments]`, segments joined with
;;; a space as `println` does. A segment is a string or a `[style string]` pair.
;;; The `*-lines` functions are pure; `say!` is the one place lines are painted
;;; and written.
;;;
;;;   :line    stdout, no marker          :stderr  stderr, no marker
;;;   :info •  :ok ✓  :warn ⚠  stdout     :oops ✗  stderr

(def ^:private ansi
  {:reset "\033[0m" :bold "\033[1m" :dim "\033[2m"
   :red "\033[31m" :green "\033[32m" :yellow "\033[33m" :blue "\033[34m"})

(def ^:private level-markers
  {:info [:blue "•"] :ok [:green "✓"] :warn [:yellow "⚠"] :oops [:red "✗"]})

(def ^:private stderr-levels #{:oops :stderr})

(defn- tty?
  "True when stdin and stdout are both terminals. With `:stdin`, true when
  stdin alone is one; `System/console` is nil whenever stdout is redirected,
  so `test -t 0` answers that."
  ([] (some? (System/console)))
  ([_stdin]
   (-> (ProcessBuilder. ^java.util.List ["sh" "-c" "test -t 0"])
       (.redirectInput java.lang.ProcessBuilder$Redirect/INHERIT)
       .start .waitFor zero?)))

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
  "Write `lines`, each to the stream its level names, with color decided once
  per call."
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

(defn normalize-config
  "Validate a secrets config as written in `bb.edn` and return it with
  per-environment defaults (:key-file, :template, :manifest) applied. The
  command functions take the result, and normalizing a result again returns
  it unchanged.

  Requires a non-blank :app and at least one environment, each a map with a
  :secrets-file. Environment settings are path strings with a leading `~`
  expanded; :manifest may also be false. A secrets path not ending in `.age`
  requires explicit :template and :manifest. No file may serve two purposes
  across the environments. An unknown key is rejected by name, so a misspelling
  cannot be silently ignored. Selects no identity and creates no files. Throws
  ex-info on invalid input."
  [config]
  (store/normalize-config config))

(def ^:private identity-source-display-label
  "How a `doctor` report names where an identity came from."
  {:secrets-age-identity-file "SECRETS_AGE_IDENTITY_FILE"
   :secrets-age-identity "SECRETS_AGE_IDENTITY"
   :secrets-age-identity-b64 "SECRETS_AGE_IDENTITY_B64"
   :configured-key-file "key file"
   :key-command ":key-command"
   :keychain "macOS Keychain"})

;;;; Utilities

(defn- read-reader-bounded!
  "Read all of `reader`, failing when its UTF-8 form passes `limit` bytes. A
  character is at least one byte, so reading can stop one chunk past the bound."
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
          observed (store/utf8-length text)]
      (when (> observed limit)
        (store/input-too-large! what limit observed context))
      text)))

(defn- editor-value
  "The editor command: `visual`, else `editor`, else `vim`. A blank value
  counts as unset, so an empty `VISUAL` cannot hide a working `EDITOR`."
  [visual editor]
  (or (first (remove str/blank? [visual editor])) "vim"))

(defn- editor
  "`editor-value` applied to the live environment."
  []
  (editor-value (System/getenv "VISUAL") (System/getenv "EDITOR")))

(defn- editor-argv
  "The argv that runs editor `command` on `path` through the shell. `path` is
  a positional argument, never interpolated, so it stays data."
  [command path]
  ["sh" "-c" (str command " \"$1\"") "editor" path])

(defn- run-editor!
  "Open `$VISUAL`/`$EDITOR` on `path`, inheriting the terminal. The value goes
  through the shell because it may carry arguments (\"code --wait\"). `path` is
  made absolute because an editor would read a dash-leading path as an option
  and `--` is not portable across editors. Throws `:editor-failed` on a
  non-zero exit, naming the editor command (configuration, not a secret) so a
  misconfigured editor is recognizable. The plaintext path stays out of the
  message."
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
  "Call `f` with a private temp file for plaintext, deleted when `f` returns
  or throws."
  [f]
  (fs/with-private-temp-file "secrets-" ".edn" f))

(defn- distinct-by [f coll]
  (->> coll (group-by f) vals (map first)))

(def ^:private default-template
  (str ";; Encrypted secrets (age). Edit with `bb secrets edit`; never commit the\n"
       ";; decrypted form. Values are plain EDN: strings, sets, nested maps, etc.\n"
       "{:example/api-key \"replace-me\"\n"
       " :example/allowed #{}}\n"))

(defn- template-content [{:keys [template]}]
  (let [f (io/file (str template))]
    (if (.exists f)
      (store/read-file-bounded! f store/max-plaintext-bytes "Template" {:template (str template)})
      default-template)))

;;;; Key paths and plaintext

(def ^:private set-usage
  (str "`set` takes [env] <key>; the value is read from the prompt or stdin, "
       "never from the command line."))

(defn- with-set-usage
  "Call `f`, adding `set-usage` as the hint of a failure: an argument `set`
  cannot place may be the value itself, typed on the command line."
  [f]
  (try (f)
       (catch clojure.lang.ExceptionInfo e
         (throw (ex-info (ex-message e) (assoc (ex-data e) :hint set-usage) e)))))

(defn- parse-key-path
  "Parse a `set`/`rm` key argument as EDN into a path vector: a keyword
  becomes a one-element path, a vector of keywords/strings is a nested path.
  Anything else, including a missing argument, fails before any file is
  touched, as does a path at or under the reserved metadata key. A failure
  names the rejected value's type, never the value: a mistyped command line
  may have put the secret in the key position."
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
  "Fail with `:path-not-a-map` when `path` passes through a non-map value of
  `secrets`. The failure names the path up to it and its type, never the value."
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
  "Render a secrets map as the plaintext `set`/`rm` re-encrypt. The print
  limits are unbound, because a REPL with `*print-length*` set would otherwise
  write `...` into the store and truncate secrets. Namespace-map shorthand is
  off, so keys print as `{:db/host …}`, as the next `edit` shows. The whole
  file is regenerated, so plaintext comments do not survive."
  [value]
  (manifest/print-whole #(with-out-str (pprint/pprint value))))

(defn- strip-trailing-newline
  "Strip exactly one trailing newline (\\n or \\r\\n) from `s`, so
  `echo secret | bb secrets set …` stores the obvious value."
  [s]
  (cond
    (str/ends-with? s "\r\n") (subs s 0 (- (count s) 2))
    (str/ends-with? s "\n") (subs s 0 (- (count s) 1))
    :else s))

(defn- read-edited!
  "The text an editor left in temp file `tmp`, size-bounded."
  [{:keys [secrets-file]} tmp]
  (store/read-file-bounded! tmp store/max-plaintext-bytes "The edited plaintext"
                            {:secrets-file (str secrets-file)}))

(defn- report-written!
  "Report `outcome`, and the manifest rewrite when the environment keeps one."
  [{:keys [manifest]} & outcome]
  (apply ok outcome)
  (when (string? manifest)
    (info "Manifest updated:" manifest)))

;;;; Commands

(defn- manifest-key-for
  "`store/manifest-key-for`, saying so when the recipients changed and the key
  is renewed."
  [operation env store target]
  (let [manifest-key (store/manifest-key-for operation env store target)]
    (when (and (= :update operation)
               (not= manifest-key (:manifest-key (get store manifest/store-key))))
      (info "Recipients changed since the last write:"
            "generating a new manifest key, so every value hash changes once."))
    manifest-key))

(defn- keychain-read-command
  "The shell command that prints `app`'s key from the macOS Keychain."
  [app]
  (str "security find-generic-password -s " keychain/service " -a " (shell-quote app) " -w"))

(defn- keygen-lines
  "The report after a key is stored."
  [{:keys [app key-file recipients-file] environment-name :name :as env} pub]
  (cond-> [[:ok "Key written:" (store/key-location env)]
           [:line]
           [:line [:bold "  Public key:"] pub]
           [:line]
           [:warn "Back this key up (e.g. a password manager). It is NOT in git and"]
           [:line (str "    cannot be recovered. A deployment takes its contents in"
                       " SECRETS_AGE_IDENTITY.")]]
    (not key-file)
    (into [[:line "    This prints it, for a backup or a deployment secret:"]
           [:line [:dim (str "      " (keychain-read-command app))]]])

    recipients-file
    (into [[:line]
           [:info "This project encrypts to a shared recipients file. Add your public"]
           [:line "    key so teammates encrypt secrets you can read:"]
           [:line [:dim (str "      bb secrets add-recipient "
                             (shell-quote (name environment-name)))]]])))

(defn keygen!
  "Generate an age identity where an environment keeps its key (its :key-file
  or, on macOS, the Keychain item for the app) and print the location and
  public key. Returns the location, or :aborted when the user declines to
  replace an existing key. Fails with `:usage` for an environment whose key
  comes from :key-command, since that command only reads; store the key with
  the password manager's own tools."
  [config env-arg]
  (let [{:keys [app key-file key-command] environment-name :name :as env}
        (store/resolve-env config env-arg)
        label (name environment-name)]
    (cond
      key-command
      (fail! :usage
             (str "Environment " label " reads its key with :key-command " (first key-command)
                  ", which\n    keygen cannot write to. Generate a key with `age-keygen`"
                  " and store it\n    with that password manager's own tools.")
             {:environment environment-name})

      (not (or key-file (keychain/available?)))
      (fail! :usage
             (str "Environment " label " has nowhere to keep a key. Without the macOS"
                  " Keychain,\n    set :key-command (a password manager that prints the"
                  " key) or :key-file.")
             {:environment environment-name}))
    (age/ensure-installed!)
    (let [location (store/key-location env)
          proceed? (or (not (if key-file
                              (.exists (io/file key-file))
                              (keychain/has-key? app)))
                       (do
                         (warn "Key already exists:" location)
                         (confirm!
                          "Overwrite? Existing secrets encrypted to it become UNREADABLE.")))]
      (if-not proceed?
        (do (info "Aborted.") :aborted)
        (do
          (info "Generating age key for" label "…")
          (say! (keygen-lines env (if key-file
                                    (age/keygen! key-file)
                                    (let [{:keys [identity-contents public-key]} (age/generate)]
                                      (keychain/store-key! app identity-contents)
                                      public-key))))
          location)))))

(defn- require-secrets-file!
  "Fail with `:no-file` unless the secrets file exists. `more` is appended to
  the message."
  [{:keys [secrets-file] environment-name :name} & more]
  (when-not (.exists (io/file secrets-file))
    (fail! :no-file
           (apply str "No secrets file at " secrets-file "\n"
                  "    Create one with:  bb secrets new "
                  (shell-quote (name environment-name)) more)
           {:secrets-file secrets-file
            :environment environment-name})))

(defn new!
  "Create an encrypted secrets file from its template, edited in $VISUAL,
  $EDITOR, or vim. Returns the secrets-file path, or :aborted when the user
  declines to overwrite an existing file. The plaintext sits in an owner-only
  temp file. The store gets a new manifest key, and a metadata line in the
  template is dropped."
  [config env-arg]
  (store/with-environment-identity config (store/resolve-env config env-arg)
    (fn [env]
      (age/ensure-installed!)
      (let [{:keys [secrets-file] environment-name :name} env
            target (store/encrypt-target! env)
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
              (spit tmp (store/user-plaintext (template-content env)))
              (info "Opening" (editor) "…")
              (run-editor! tmp)
              (store/write-secrets! env target tmp (read-edited! env tmp)
                                    (manifest-key-for :create env nil target)
                                    #(info "Encrypting…"))
              (report-written! env "Encrypted secrets written:" secrets-file)
              secrets-file)))))))

(defn edit!
  "Edit an existing secrets file through an owner-only plaintext temp file,
  re-encrypting only when the plaintext changes. Returns the secrets-file
  path. The editor shows the plaintext without the store's metadata, which is
  restored on save; a result that holds the reserved key is refused."
  [config env-arg]
  (store/with-environment-identity config (store/resolve-env config env-arg)
    (fn [env]
      (age/ensure-installed!)
      (let [{:keys [secrets-file]} env]
        (store/require-identity! env)
        (require-secrets-file! env)
        (let [target (store/encrypt-target! env)]
          (with-plaintext-temp
            (fn [tmp]
              (info "Decrypting" secrets-file "…")
              (let [text (store/decrypt-text! env)
                    store (store/parse-secrets! secrets-file text nil)
                    ;; A store without usable metadata fails before the editor opens.
                    _ (store/require-store-metadata! env store)
                    before (store/user-plaintext text)]
                (spit tmp before :encoding "UTF-8")
                (run-editor! tmp)
                (let [after (read-edited! env tmp)]
                  (if (= before after)
                    (warn "No changes: leaving" secrets-file "untouched.")
                    (do
                      (store/write-secrets! env target tmp after
                                            (manifest-key-for :update env store target)
                                            #(info "Re-encrypting…"))
                      (report-written! env "Secrets updated:" secrets-file)))))
              secrets-file)))))))

(defn- read-set-value!
  "The value for `set`: a hidden-prompt line when `interactive?`, otherwise
  stdin minus one trailing newline. Both are bounded by
  `store/max-plaintext-bytes`."
  [env path interactive?]
  (let [limit store/max-plaintext-bytes
        context {:environment (:name env) :key path}]
    (if interactive?
      (let [value (or (prompt-hidden! (str (question-marker) " Value for " (pr-str path)
                                           " (input hidden): "))
                      "")]
        (when (> (store/utf8-length value) limit)
          (store/input-too-large! "The typed value" limit (store/utf8-length value) context))
        value)
      (strip-trailing-newline
       (read-reader-bounded! *in* limit "Standard input" context)))))

(defn set-secret!
  "Set a value at `key-arg`, a keyword or a non-empty vector of keyword/string
  path elements. The value comes from a hidden prompt when stdin and stdout are
  both terminals, otherwise from stdin minus one trailing newline. With stdin a
  terminal and stdout redirected it refuses, since it could not hide the
  typing. The value is stored as a string unless `opts` holds `:edn? true`,
  which parses the input as one EDN value. Blank input is rejected with
  `:blank-value`. Creates a missing secrets file from an empty map, then
  re-encrypts and updates the manifest; plaintext comments are lost. Returns
  the secrets-file path."
  [config env-arg key-arg & [{:keys [edn?]}]]
  (store/with-environment-identity config (with-set-usage #(store/resolve-env config env-arg))
    (fn [env]
      (age/ensure-installed!)
      (let [path (with-set-usage #(parse-key-path key-arg))
            {:keys [secrets-file]} env
            exists? (.exists (io/file secrets-file))]
        (when exists? (store/require-identity! env))
        (let [target (store/encrypt-target! env)
              interactive? (tty?)
              _ (when (and (not interactive?) (tty? :stdin))
                  (fail! :usage
                         (str "stdout is redirected; run `set` without redirecting it,"
                              " or pipe the value in.")))
              raw (read-set-value! env path interactive?)
              _ (when (str/blank? raw)
                  ;; Blank almost always means an unset variable expanded to
                  ;; nothing (`echo "$KEY" | bb secrets set …` in CI), and
                  ;; storing it fails much later, far from the cause. The
                  ;; library applies the same rule to SECRETS_AGE_IDENTITY.
                  (fail! :blank-value
                         (str (if interactive? "Nothing entered" "Nothing on stdin")
                              ": refusing to store a blank value for " (pr-str path) ".\n"
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
                                (store/parse-secrets! secrets-file (store/decrypt-text! env) nil))
                            (info "No secrets file at" (str secrets-file ":") "creating it."))
                    manifest-key (manifest-key-for (if exists? :update :create)
                                                   env store target)
                    current (or (manifest/user-data store) {})]
                (require-map-parents! current path)
                (store/write-secrets! env target tmp
                                      (render-secrets (assoc-in current path value))
                                      manifest-key
                                      #(info (if exists? "Re-encrypting…" "Encrypting…")))
                (report-written! env "Set" (pr-str path) "in" secrets-file)
                secrets-file))))))))

(defn remove-secret!
  "Remove the keyword or vector key path, then re-encrypt and update the
  manifest. Throws when the file or path is absent. Empty parent maps stay.
  Returns the secrets-file path. Plaintext comments are lost."
  [config env-arg key-arg]
  (store/with-environment-identity config (store/resolve-env config env-arg)
    (fn [env]
      (age/ensure-installed!)
      (let [path (parse-key-path key-arg)
            {:keys [secrets-file] environment-name :name} env]
        (store/require-identity! env)
        ;; A string `key-arg` already is the EDN text argv carried; any other
        ;; accepted value is printed to get that text back.
        (require-secrets-file! env "\n    or:               bb secrets set "
                               (shell-quote (name environment-name)) " "
                               (shell-quote (if (string? key-arg) key-arg (pr-str key-arg))))
        (let [target (store/encrypt-target! env)]
          (info "Decrypting" secrets-file "…")
          (let [store (store/parse-secrets! secrets-file (store/decrypt-text! env) nil)
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
                  (store/write-secrets! env target tmp (render-secrets updated) manifest-key
                                        #(info "Re-encrypting…"))
                  (report-written! env "Removed" (pr-str path) "from" secrets-file)
                  secrets-file)))))))))

(defn- show-key-line
  "A public-key line, or a warning when the key is absent."
  [environment-name location pub]
  (if pub
    [:line (format "  %-6s %s" (str (name environment-name) ":") pub)]
    [:warn (format "%s: no key in %s" (name environment-name) location)]))

(defn show-key!
  "Print the public keys, for teammates to encrypt to. Reads the key each
  environment keeps (its :key-command, :key-file, or Keychain item), not an
  identity variable. Returns a map of env name to public key (nil when the key
  is missing). Environments sharing a key are reported once, under the first
  seen."
  [config env-arg]
  (let [envs (if env-arg
               [(store/resolve-env config env-arg)]
               (vals (:environments config)))]
    (into {}
          (map (fn [{environment-name :name :as env}]
                 (let [pub (store/own-public-key env)]
                   (say! [(show-key-line environment-name (store/key-location env) pub)])
                   [environment-name pub])))
          (distinct-by store/key-location envs))))

(defn reencrypt!
  "Decrypt and re-encrypt to the environment's current recipients. Use after
  adding or removing a recipient; an `edit` with no change would not pick the
  change up. The recipient list is snapshotted before decryption. Returns the
  secrets-file path.

  Every run generates a new manifest key and rewrites the manifest, so every
  `:vhash` changes once and a removed recipient's copy of the old key says
  nothing about later values. The existing metadata is not read, so this
  repairs a store whose metadata is missing, malformed, or of another version.
  Metadata that is not on the library's own line was written by hand; the
  store is then rendered again without it, which drops plaintext comments."
  [config env-arg]
  (store/with-environment-identity config (store/resolve-env config env-arg)
    (fn [env]
      (age/ensure-installed!)
      (let [{:keys [secrets-file]} env]
        (store/require-identity! env)
        (require-secrets-file! env)
        (let [target (store/encrypt-target! env)]
          (with-plaintext-temp
            (fn [tmp]
              (info "Decrypting" secrets-file "…")
              (let [text (store/user-plaintext (store/decrypt-text! env))
                    value (:value (safe-edn/parse text))
                    user-text (if (and (map? value) (contains? value manifest/store-key))
                                (render-secrets (manifest/user-data value))
                                text)]
                (store/write-secrets! env target tmp user-text
                                      (manifest-key-for :reencrypt env nil target)
                                      #(info "Re-encrypting to current recipients…")))
              (report-written! env "Re-encrypted:" secrets-file)
              secrets-file)))))))

(defn- recipient-added-lines
  "The report after a recipient is appended, with the next step depending on
  whether a ciphertext already exists."
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
  "Add an age public key to an environment's recipients file; with no key,
  the environment's own. Returns the recipient added or already present."
  [config env-arg pubkey]
  (let [{:keys [recipients-file secrets-file]
         environment-name :name :as env}
        (store/resolve-env config env-arg)
        environment-label (clojure.core/name environment-name)]
    (when-not recipients-file
      (fail! :no-recipients-file
             (str environment-label
                  " has no :recipients-file configured (single-key mode).\n"
                  "    Add :recipients-file to its config to encrypt to multiple people.")
             {:environment environment-name}))
    (let [pub (or pubkey (store/own-public-key env))]
      (when-not pub
        (fail! :no-identity
               (str "No public key given and no key in " (store/key-location env) "\n"
                    "    Generate one with:  bb secrets keygen "
                    (shell-quote environment-label))
               {:environment environment-name}))
      (let [pub (str/trim pub)]
        (when-not (age/valid-recipient? pub)
          (fail! :invalid-recipient "Not a valid age public key."))
        (let [snapshot (store/recipient-file-snapshot env)
              existing (or (:recipients snapshot) [])]
          (if (some #{pub} existing)
            (do
              (info "Already a recipient of" (str environment-label ":") pub)
              pub)
            (do
              (store/append-recipient! env (:content snapshot) pub)
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
                   [:line "  " (pr-str (store/line-prefix recipient))
                    [:yellow "← invalid; encryption refuses this line"]])))
          recipients)))

(defn recipients!
  "List the recipients an environment encrypts to. Returns them as an eager
  seq, or nil in single-key mode. Read-only. A line encryption would reject is
  listed and marked. Throws for an unknown environment and for a recipients
  file that is too large or unreadable."
  [config env-arg]
  (let [{:keys [recipients-file] environment-name :name :as env}
        (store/resolve-env config env-arg)
        environment-label (clojure.core/name environment-name)]
    (if-not recipients-file
      (do
        (info environment-label
              "is in single-key mode: it encrypts to its own key, not a recipients list.")
        nil)
      (let [recipients (store/read-recipients env)]
        (say! (recipients-lines environment-label recipients-file recipients))
        recipients))))

(defn- diff-lines
  "One line per key path that moved between the manifest and the store."
  [{:keys [added removed changed]}]
  (concat
   (for [path added]
     [:line "    +" (pr-str path) "is in the secrets and missing from the manifest"])
   (for [path removed]
     [:line "    -" (pr-str path) "is in the manifest and gone from the secrets"])
   (for [path changed] [:line "    ~" (pr-str path) "changed its value or type"])))

(defn- finding-lines
  "The report for one environment's finding."
  [{:keys [app secrets-file manifest] environment-name :name}
   {:keys [reason] :as finding}]
  (let [quoted (shell-quote (name environment-name))
        label (str (name environment-name) ":")
        regenerate [:line (str "    Regenerate it with:  bb secrets reencrypt " quoted)]
        recipients-changed [:oops label
                            "recipients changed since the last encryption; run reencrypt."]]
    (case reason
      :manifest-disabled
      [[:info label "manifest disabled; skipping."]]

      :no-secrets-file
      [[:warn label "no secrets file at" secrets-file]]

      :no-manifest
      [[:warn label "no manifest at" manifest]
       [:line (str "    Write it with:  bb secrets reencrypt " quoted)]]

      :manifest-invalid-edn
      [[:oops label "manifest is not valid EDN:" (safe-edn/failure-message (:failure finding))]
       regenerate]

      :manifest-malformed
      [[:oops label "manifest is incomplete: expected a map with a :ciphertext-sha"
        "and a :keys map whose every entry has a :type and a :vhash."]
       regenerate]

      :unsupported-version
      [[:oops label "manifest version" (pr-str (:version finding))
        "is unsupported by this version of the library."]
       regenerate
       [:line "    Or upgrade the library."]]

      :wrong-app
      [[:oops label "manifest describes app" (pr-str (:app finding))
        (str "but this project is " (pr-str app) ".")]
       [:line "    It belongs to a different store."]
       regenerate]

      :error
      (into [[:oops label (:message finding)]]
            (when-let [hint (:hint finding)] [[:line "   " hint]]))

      :ciphertext-agrees
      [[:ok label "ciphertext agrees with the manifest"
        "(freshness only: no key, so values are not checked)."]]

      :ciphertext-changed
      [[:oops label "ciphertext changed since the manifest was written"
        (str "(" manifest ").")]
       regenerate]

      :store-problem
      [[:oops label (:message finding)]]

      :secrets-invalid-edn
      [[:oops label "encrypted secrets are not valid EDN:"
        (safe-edn/failure-message (:failure finding))]]

      :stale
      (-> []
          (into (when-let [diff (:diff finding)]
                  (cons [:oops label "manifest is STALE" (str "(" manifest "):")]
                        (diff-lines diff))))
          (into (when (:ciphertext-changed? finding)
                  [[:oops label
                    "ciphertext digest differs from the one the manifest records."]]))
          (into (when (:recipients-changed? finding) [recipients-changed]))
          (conj regenerate))

      :recipients-changed
      [recipients-changed
       [:line (str "    The store is still encrypted to the earlier recipients:"
                   "  bb secrets reencrypt " quoted)]]

      :manifest-matches
      [[:ok label "manifest matches" (str "(" manifest ")")]])))

(defn verify!
  "Check that each environment's committed manifest matches its encrypted
  secrets; with no env, check all of them. Returns
  {:results {env-name status} :exit code}, where each status is :ok,
  :ok-keyless, :drift, :missing, or :error.

  `:exit` is 0 when everything agrees, 1 when the only problem is drift, and 2
  when anything else stopped an environment from being verified: a missing
  secrets file or manifest, an identity that does not resolve, a store the
  identity cannot decrypt, an invalid recipients file, or an unreadable file.
  Such a failure is that environment's :error and the others are still
  verified. Only an unknown or missing environment argument throws.

  A manifest must be complete before anything is compared: the supported
  `:version`, this project's `:app`, a `:ciphertext-sha`, and a `:keys` map
  whose every entry has a `:type` and a `:vhash`. Anything else is drift.
  Keyless verification compares only the ciphertext hash and does not need
  age; it applies when no identity was designated and the environment's own
  key (its key file or Keychain item) is absent.
  Full verification decrypts and also compares the entries, hashed under the
  store's manifest key, so a changed value fails in solo and team stores alike.

  Drift also covers a store whose metadata is missing, malformed, or of another
  version (the report says `reencrypt` writes a current one), and a store that
  records a recipient set other than the one its environment encrypts to now,
  as after a recipients file edited without a `reencrypt`.

  A pass shows the ciphertext and manifest agree. It does not establish
  authorship; see `doc/threat-model.md`."
  [config env-arg]
  (let [envs (if env-arg
               [(store/resolve-env config env-arg)]
               (vals (:environments config)))
        verify-env (fn [env]
                     (try
                       (store/with-environment-identity config env
                         (fn [env] [env (store/verify-one! env)]))
                       (catch Exception e
                         [env {:status :error
                               :reason :error
                               :message (store/failure-message e)
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
  "The `:reason`s of a failed identity resolution."
  #{:invalid-identity :disallowed-identity :no-identity :key-command-failed :keychain-failed})

(defn- doctor-report
  "Diagnose normalized environment `env`. `identity-problem` is the message of
  a failed identity resolution, or nil when `env` carries a resolved identity.
  A warning is something to act on that stops no command from being tried (a
  file not there yet, `age` not installed). A problem is an identity that does
  not resolve, or a recipients file that lists nobody or holds a line age
  would refuse."
  [{:keys [secrets-file manifest recipients-file identity-file identity-source]
    environment-name :name :as env}
   identity-problem]
  (let [exists? #(boolean (and % (.exists (io/file (str %)))))
        label (shell-quote (name environment-name))
        version (age/version)
        recipients (when (exists? recipients-file) (store/read-recipients env))
        invalid (count (remove age/valid-recipient? recipients))
        has-identity? (secrets/identity-available? env)
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
          (not (or identity-problem has-identity?))
          (conj (str "No identity, so only keyless verification works here."
                     (if (or (:key-file env) (keychain/available?))
                       (str " Create a key with:  bb secrets keygen " label)
                       " Set :key-command or :key-file for this environment."))))
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
                        :path identity-file
                        :exists? has-identity?}
             :warnings warnings
             :problems problems
             :exit (cond (seq problems) 2 (seq warnings) 1 :else 0)}
      recipients-file
      (assoc :recipients-file {:path recipients-file
                               :exists? (exists? recipients-file)
                               :count (count (distinct (filter age/valid-recipient?
                                                               recipients)))}))))

(defn- doctor-lines
  "The `doctor` report: paths and counts, never file contents, recipient
  lines, or environment values."
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
                (if-let [source (identity-source-display-label (:source identity))]
                  (str source
                       (when (:path identity) (str " " (:path identity)))
                       (if (:exists? identity) " (present)" " (missing)"))
                  "not resolved")])))
     (for [warning warnings] [:line "Warning:" warning])
     (for [problem problems] [:line "Problem:" problem])
     [[:line "Status:" (case (int exit) 0 "healthy" 1 "warning" 2 "invalid")]]
     (when (zero? exit)
       [[:line "Run `bb secrets verify` to check the store against its manifest."]]))))

(defn doctor!
  "Diagnose one selected or default environment. Takes the raw config, prints
  a short report, returns it as a map, and never exits.

  The map holds `:environment`, `:age` (the installed version, or nil),
  `:secrets-file` and `:manifest` (each `{:path :exists?}`; `:manifest` is nil
  when disabled), `:recipients-file` in team mode (`{:path :exists? :count}`,
  where `:count` is the distinct valid recipients encryption would use),
  `:identity` (`{:source :path :exists?}`, a path only for a key file),
  `:warnings` and `:problems` (vectors of messages), and `:exit`.

  `:exit` is 0 when healthy. It is 1 on a warning: `age` is not installed, or
  the secrets file, manifest, recipients file, or key is not there yet. It is 2
  on a problem: an identity that does not resolve, a recipients file that
  lists nobody or holds an invalid line, or anything that stopped the
  diagnosis, such as an invalid configuration or an unknown environment, in
  which case the map holds only `:problems` and `:exit`. A missing template is
  not reported. It does not open the store or the manifest; `verify` does."
  [config env-arg]
  (let [result (try
                 (let [config (store/normalize-config config)
                       env (store/resolve-env config env-arg)]
                   (try
                     (store/with-environment-identity config env #(doctor-report % nil))
                     (catch clojure.lang.ExceptionInfo e
                       (if (identity-failure-reasons (:reason (ex-data e)))
                         (doctor-report (merge env (select-keys (ex-data e)
                                                                [:identity-file :identity-source]))
                                        (ex-message e))
                         (throw e)))))
                 (catch clojure.lang.ExceptionInfo e
                   {:problems [(ex-message e)] :exit 2}))]
    (say! (doctor-lines result))
    result))

;;;; Dispatch

(defn- error-lines
  "The error and its remediation, for stderr."
  [e]
  (let [data (ex-data e)]
    (into [[:oops (store/failure-message e)]]
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
  "The `[env key]` of a `[env] <key>` command; one argument is the key."
  [args]
  (if (next args) args [nil (first args)]))

(def ^:private commands
  "Every command. `:args` is the positional arguments as usage text, `<x>`
  required and `[x]` optional, and it bounds how many are accepted. `:flags`
  maps each flag to its help line. `:run` is called with the normalized config
  (as given when `:raw-config?`), the positional arguments, and the set of
  flags present. `help` has no `:run`; the dispatcher answers it."
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
              "The prompt needs stdin and stdout both to be terminals: with stdout\n"
              "redirected, pipe the value in. It is never read from the command line.")
    :run (fn [config args flags]
           (let [[env k] (env-and-key args)]
             (set-secret! config env k {:edn? (contains? flags "--edn")})))}
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
              "Without a key it adds the environment's own. A single argument that is\n"
              "a public key goes to the default environment; any other single\n"
              "argument is the environment.")
    :run (fn [config [env public-key :as args] _flags]
           (if (and (= 1 (count args)) (age/valid-recipient? env))
             (add-recipient! config nil env)
             (add-recipient! config env public-key)))}
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
  "The global help. Built before the config is validated, so it lists
  environments only when they have a valid shape."
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
    [:line "  decryption failure, an invalid recipients file, an unknown environment,"]
    [:line "  or an invalid configuration."]
    [:line "doctor exits 0 when healthy, 1 on a warning, and 2 on an invalid configuration,"]
    [:line "  identity, or recipients file, or when it could not run."]
    [:line "Every other command exits 0, or 1 on any failure."]]))

(defn- find-command
  "The table entry named `command-name`. An unknown name is not echoed, since
  it may be a value typed in the wrong place."
  [command-name]
  (or (some #(when (= command-name (:name %)) %) commands)
      (fail! :usage "Unknown command. Run `bb secrets help` for the list.")))

(defn- dispatch!
  "Run the command `args` names against `config` and return its result.

  Before a `--`, an argument starting with `-` is a flag and the rest are
  positional; everything after `--` is positional. An unknown flag or surplus
  positional is a usage error that prints the command's usage and never the
  argument, which may be a secret typed in the wrong place."
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
             (if (:raw-config? command) config (store/normalize-config config))
             positionals
             flags))))

(def ^:private status-commands
  "The commands whose exit 1 means drift or a warning, so failing to run at all
  is 2."
  #{"verify" "doctor"})

(defn run!
  "Dispatch `args` against `config` as the whole of a process: the entry point
  for a `bb` task or a JVM `-main`, not for a REPL, where the command
  functions are the API. It decides the exit code.

  A failure prints one line plus any hint on stderr, never a stack trace, and
  exits 1, or 2 from `verify` and `doctor`. Those two otherwise exit with the
  `:exit` of their result."
  [config args]
  (let [status-command? (contains? status-commands (first args))
        exit (try
               (let [result (dispatch! config args)]
                 (if status-command? (:exit result 0) 0))
               (catch Exception e
                 (say! (error-lines e))
                 (if status-command? 2 1)))]
    (store/exit! exit)))
