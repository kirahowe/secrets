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
                      them (`age -R`) so each teammate can decrypt with their
                      own key. Absent ⇒ single-key mode (encrypt to own key).
    :manifest false   disable the manifest for this environment.

  Commands: keygen · new · edit · verify · show-key · add-recipient ·
  recipients · reencrypt · encrypt · decrypt · help.

  Two committed artifacts per environment: `secrets.edn.age` (ciphertext) and
  `secrets.edn.manifest` (its safe, value-free shape — regenerated on every
  save so a diff shows which keys changed). The decrypt → edit → re-encrypt →
  secure-delete cycle never leaves plaintext on disk.

  The command fns are a REPL-safe API: they return data (a path, a results
  map, or :aborted) and signal failures by throwing `ex-info` (carrying
  :secrets/exit) instead of exiting. `run!` — the CLI entry point — is the
  only fn here that prints error data and calls System/exit."
  (:refer-clojure :exclude [run!])
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.java.shell :as shell]
            [clojure.string :as str]
            [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.manifest :as manifest]))

;; ---------- Output ----------

(def ^:private ansi
  {:reset "\033[0m" :bold "\033[1m" :dim "\033[2m"
   :red "\033[31m" :green "\033[32m" :yellow "\033[33m" :blue "\033[34m"})

(defn- tty? [] (some? (System/console)))
(defn- paint [color s] (if (tty?) (str (ansi color) s (ansi :reset)) s))

(defn- info [& xs] (println (paint :blue "•") (str/join " " xs)))
(defn- ok   [& xs] (println (paint :green "✓") (str/join " " xs)))
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

;; ---------- Config ----------

(defn normalize-config
  "Apply per-environment defaults (:key-file, :identity-file, :template,
  :manifest), validate the configuration, and stamp each env with its :name.
  Throws (ex-info, as `run!` expects) when there are no environments, when
  :app is missing (it names the default key path ~/.config/<app>/key.txt, so
  defaulting it would make unrelated projects share a key), when an
  environment lacks a :secrets-file string, or when a derived :template /
  :manifest name would collide with the ciphertext (a :secrets-file that does
  not end in `.age` derives template = manifest = the secrets file itself, and
  writing the manifest would then overwrite the encrypted file). Ciphertext,
  manifest, template, key, and recipients paths are compared by canonical path
  so aliases such as `./s.age` and `s.age` cannot refer to different artifacts
  in the configuration."
  [{:keys [app environments] :as config}]
  (when (empty? environments)
    (fail! "secrets config has no :environments" {:config config}))
  (when-not (and (string? app) (not (str/blank? app)))
    (fail! (str "secrets config has no :app (a name string is required). It names the\n"
                "    default key path ~/.config/<app>/key.txt and is recorded in the manifest,\n"
                "    so there is deliberately no default — projects must not share a key path\n"
                "    by accident.")
           {:config config}))
  (assoc config
         :environments
         (into {}
               (map (fn [[env {:keys [secrets-file key-file template manifest recipients-file] :as e}]]
                      (when-not (string? secrets-file)
                        (fail! (str "Environment " env " has no :secrets-file (a path string is required).")
                               {:environment env :env-config e}))
                      (when (and (not (str/ends-with? secrets-file ".age"))
                                 (not (and (contains? e :template) (contains? e :manifest))))
                        (fail! (str "Environment " env " :secrets-file (" secrets-file ") does not end in .age, so the\n"
                                    "    derived :template/:manifest names would collide with — and overwrite — the\n"
                                    "    ciphertext itself. Use a .age extension, or set :template and :manifest\n"
                                    "    explicitly.")
                               {:environment env :secrets-file secrets-file}))
                      (let [key-file        (secrets/expand-home
                                             (or key-file (str "~/.config/" app "/key.txt")))
                            template        (if (contains? e :template)
                                              template
                                              (str/replace secrets-file #"\.age$" ".example"))
                            manifest        (if (contains? e :manifest)
                                              manifest
                                              (str/replace secrets-file #"\.age$" ".manifest"))
                            recipients-file (some-> recipients-file secrets/expand-home)
                            collisions      (->> [[:secrets-file secrets-file]
                                                  [:manifest manifest]
                                                  [:template template]
                                                  [:key-file key-file]
                                                  [:recipients-file recipients-file]]
                                                 (filter (fn [[_ path]] (string? path)))
                                                 (map (fn [[kind path]]
                                                        [kind (.getCanonicalPath (io/file path))]))
                                                 (group-by second)
                                                 vals
                                                 (filter #(> (count %) 1)))]
                        (when-let [collision (first collisions)]
                          (fail! (str "Environment " env " has colliding artifact paths: "
                                      (str/join ", " (map (comp name first) collision))
                                      " (canonical path " (second (first collision)) ").")
                                 {:environment env
                                  :path-collision collision}))
                        [env (assoc e
                                    :name env
                                    :app app
                                    :secrets-file secrets-file
                                    :key-file key-file
                                    ;; Decrypt-side identity: SECRETS_AGE_IDENTITY* env vars win,
                                    ;; then the configured/default key path.
                                    :identity-file (or (secrets/identity-from-env) key-file)
                                    ;; Explicit values (incl. :manifest false) are always
                                    ;; kept; absent ⇒ derive from the secrets file.
                                    :template template
                                    :manifest manifest
                                    :recipients-file recipients-file)])))
               environments)))

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

;; ---------- Utilities ----------

(defn- editor [] (or (System/getenv "VISUAL") (System/getenv "EDITOR") "vim"))

(defn- run-editor!
  "Open `$EDITOR` on `path`, inheriting the terminal. The editor value goes
  through the shell because it may carry arguments (\"code --wait\",
  \"emacsclient -t\"); the path is passed as a positional argument, not
  interpolated. Throws if the editor exits non-zero."
  [path]
  (let [proc (-> (ProcessBuilder. (into-array String ["sh" "-c" (str (editor) " \"$1\"") "editor" (str path)]))
                 (.inheritIO)
                 (.start))]
    (when-not (zero? (.waitFor proc))
      (fail! "Editor exited with an error; leaving secrets unchanged."))))

(defn- secure-delete!
  "Best-effort secure delete of a plaintext temp file."
  [path]
  (let [f (io/file (str path))]
    (when (.exists f)
      (try
        (cond
          (str/starts-with? (System/getProperty "os.name") "Mac")
          (shell/sh "rm" "-P" (str path))
          (zero? (:exit (shell/sh "sh" "-c" "command -v shred")))
          (shell/sh "shred" "-u" (str path))
          :else (.delete f))
        (catch Exception _ (.delete f)))
      (when (.exists f) (.delete f)))))

(defn- temp-plaintext!
  "Create an owner-only (0600 from the moment it exists) temp file for
  plaintext secrets."
  []
  (secrets/owner-only-temp-file! "secrets-" ".edn"))

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
  ";; Encrypted secrets (age). Edit with `bb secrets edit`; never commit the\n;; decrypted form. Values are plain EDN — strings, sets, nested maps, etc.\n{:example/api-key \"replace-me\"\n :example/allowed #{}}\n")

(defn- template-content [{:keys [template]}]
  (let [f (io/file (str template))]
    (if (.exists f) (slurp f) default-template)))

(defn- require-age! []
  (when-not (age/installed?)
    (fail! (str "The `age` tool is not installed.\n"
                "    macOS:  brew install age\n"
                "    Ubuntu: apt install age\n"
                "    Docs:   https://age-encryption.org"))))

(defn- require-identity!
  "Ensure the environment's decrypt-side identity file exists."
  [{:keys [identity-file name]}]
  (when-not (.exists (io/file identity-file))
    (fail! (str "No age identity for " (clojure.core/name name) " at " identity-file "\n"
                "    Create one with:  bb secrets keygen " (clojure.core/name name) "\n"
                "    Or point at an existing key via SECRETS_AGE_IDENTITY_FILE (a path),\n"
                "    SECRETS_AGE_IDENTITY (raw key contents), or SECRETS_AGE_IDENTITY_B64 (base64 contents).")
           {:identity-file (str identity-file) :environment name})))

;; ---------- Recipients (multi-recipient mode) ----------

(defn- read-recipients
  "Read age public keys from a recipients file (one per line; blank lines and
  `#` comments ignored). Returns a seq of keys, or nil if the file is absent."
  [path]
  (let [f (io/file (str path))]
    (when (.exists f)
      (->> (slurp f) str/split-lines (map str/trim)
           (remove str/blank?) (remove #(str/starts-with? % "#"))))))

(defn- encrypt-recipients
  "The age recipient spec an environment encrypts to: its shared recipients file
  in multi-recipient mode, otherwise the environment's own identity (single-key
  mode — the resolved :identity-file, so SECRETS_AGE_IDENTITY* works in CI too)."
  [{:keys [recipients-file identity-file]}]
  (if recipients-file {:recipients-file recipients-file} {:identity-file identity-file}))

(defn- require-encrypt-target!
  "Ensure we can encrypt: a non-empty recipients file (multi-recipient mode), or
  the identity (single-key mode, where we encrypt to our own identity)."
  [{:keys [recipients-file name] :as env}]
  (if recipients-file
    (when (empty? (read-recipients recipients-file))
      (fail! (str "No recipients yet for " (clojure.core/name name) " in " recipients-file "\n"
                  "    Add one with:  bb secrets add-recipient " (clojure.core/name name))
             {:recipients-file (str recipients-file) :environment name}))
    (require-identity! env)))

;; ---------- Manifest ----------

(defn- manifest-hmac-key
  "The manifest HMAC key for an environment: derived from the shared identity
  in single-key mode, nil in multi-recipient mode (no single shared key), so the
  manifest is structure-only for teams."
  [{:keys [recipients-file identity-file]}]
  (when (and (not recipients-file) (.exists (io/file identity-file)))
    (manifest/hmac-key (slurp identity-file))))

(defn- parse-edn [s]
  (try
    (let [eof    (Object.)
          reader (java.io.PushbackReader. (java.io.StringReader. s))
          value  (edn/read {:eof eof} reader)
          extra  (edn/read {:eof eof} reader)]
      (cond
        (identical? eof value) {:ok? false :error "expected one EDN value"}
        (not (identical? eof extra)) {:ok? false :error "expected one EDN value, found another"}
        :else {:ok? true :value value}))
    (catch Exception e {:ok? false :error (ex-message e)})))

(defn- validate-plaintext!
  "Parse all of `plaintext`, returning its EDN value. Fail before encryption
  when it is empty, malformed, or contains more than one value."
  [secrets-file plaintext]
  (let [{:keys [ok? value error]} (parse-edn plaintext)]
    (if ok?
      value
      (fail! (str "Secrets are not valid EDN (" error ").\n"
                  "    Ciphertext and manifest were left unchanged.")
             {:secrets-file (str secrets-file) :error error}))))

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
      (if (= "java.nio.file.AtomicMoveNotSupportedException" (.getName (class e)))
        (throw (ex-info (str "The filesystem does not support an atomic secrets update for " target)
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
  (let [prepared  (atom [])
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
                              (java.nio.file.Files/deleteIfExists (.toPath (io/file target))))
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
  "Validate `plaintext-file`, then stage its ciphertext and optional manifest
  beside their destinations and commit both through atomic replacements."
  [{:keys [manifest app secrets-file] :as env} plaintext-file]
  (let [plaintext       (slurp plaintext-file)
        value           (validate-plaintext! secrets-file plaintext)
        ciphertext-temp (sibling-temp-file! secrets-file ".age.tmp")
        manifest-temp   (when (string? manifest)
                          (sibling-temp-file! manifest ".manifest.tmp"))]
    (try
      (age/encrypt-file! (encrypt-recipients env) plaintext-file ciphertext-temp)
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

;; ---------- Commands ----------

(defn keygen!
  "Generate an age identity at an environment's key-file. Returns the key-file
  path, or :aborted when an existing key is kept."
  [config env-arg]
  (require-age!)
  (let [{:keys [key-file name recipients-file]} (resolve-env config env-arg)
        proceed? (or (not (.exists (io/file key-file)))
                     (do (warn "Key already exists:" key-file)
                         (confirm! "Overwrite? Existing secrets encrypted to it become UNREADABLE.")))]
    (if-not proceed?
      (do (info "Aborted.") :aborted)
      (do
        (info "Generating age key for" (clojure.core/name name) "…")
        (let [pub (age/keygen! key-file)]
          (ok "Key written:" key-file)
          (println)
          (println (paint :bold "  Public key:") pub)
          (println)
          (warn "Back this key up (e.g. a password manager). It is NOT in git and")
          (println "    cannot be recovered. To deploy, set it as the SECRETS_AGE_IDENTITY secret:")
          (println (paint :dim (str "      flyctl secrets set SECRETS_AGE_IDENTITY=\"$(cat " key-file ")\"")))
          (when recipients-file
            (println)
            (info "This project encrypts to a shared recipients file. Add your public")
            (println "    key so teammates encrypt secrets you can read:")
            (println (paint :dim (str "      bb secrets add-recipient " (clojure.core/name name)))))
          key-file)))))

(defn new!
  "Create a new encrypted secrets file from a template via $EDITOR. Returns the
  secrets-file path, or :aborted when an existing file is kept."
  [config env-arg]
  (require-age!)
  (let [{:keys [secrets-file name] :as env} (resolve-env config env-arg)]
    (require-encrypt-target! env)
    (let [proceed? (or (not (.exists (io/file secrets-file)))
                       (do (warn "Secrets file already exists:" secrets-file)
                           (confirm! (str "Overwrite it? (To change values, use `bb secrets edit "
                                          (clojure.core/name name) "` instead.)"))))]
      (if-not proceed?
        (do (info "Aborted.") :aborted)
        (let [tmp (temp-plaintext!)]
          (try
            (spit tmp (template-content env))
            (info "Opening" (editor) "…")
            (run-editor! tmp)
            (info "Encrypting…")
            (write-secrets! env tmp)
            (ok "Encrypted secrets written:" secrets-file)
            (when (string? (:manifest env)) (info "Manifest updated:" (:manifest env)))
            secrets-file
            (finally (secure-delete! tmp))))))))

(defn edit!
  "Decrypt → edit → re-encrypt an existing secrets file (no plaintext left on
  disk). Returns the secrets-file path."
  [config env-arg]
  (require-age!)
  (let [{:keys [secrets-file identity-file name] :as env} (resolve-env config env-arg)]
    (require-identity! env)
    (require-encrypt-target! env)
    (when-not (.exists (io/file secrets-file))
      (fail! (str "No secrets file at " secrets-file "\n"
                  "    Create one with:  bb secrets new " (clojure.core/name name))
             {:secrets-file secrets-file :environment name}))
    (let [tmp (temp-plaintext!)]
      (try
        (info "Decrypting" secrets-file "…")
        (age/decrypt-to-file! identity-file secrets-file tmp)
        (let [before (sha256 tmp)]
          (run-editor! tmp)
          (if (= before (sha256 tmp))
            (warn "No changes — leaving" secrets-file "untouched.")
            (do (info "Re-encrypting…")
                (write-secrets! env tmp)
                (ok "Secrets updated:" secrets-file)
                (when (string? (:manifest env)) (info "Manifest updated:" (:manifest env))))))
        secrets-file
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
          (map (fn [{:keys [key-file name]}]
                 (let [pub (age/public-key key-file)]
                   (if pub
                     (println (format "  %-6s %s" (str (clojure.core/name name) ":") pub))
                     (warn (format "%s: no key at %s" (clojure.core/name name) key-file)))
                   [name pub])))
          (distinct-by :key-file envs))))

(defn encrypt!
  "Encrypt an arbitrary plaintext file to <file>.age using an environment's
  recipients (its recipients file, or its own identity in single-key mode).
  Returns the ciphertext path."
  [config env-arg file]
  (require-age!)
  (let [env (resolve-env config env-arg)]
    (require-encrypt-target! env)
    (when-not (and file (.exists (io/file file)))
      (fail! (str "No such file: " file) {:file file}))
    (let [out (str file ".age")]
      (age/encrypt-file! (encrypt-recipients env) file out)
      (ok "Encrypted:" out)
      out)))

(defn decrypt!
  "Decrypt a <file>.age to stdout, byte-for-byte (binary-safe; plaintext is
  never written to disk). Returns the input path."
  [config env-arg file]
  (require-age!)
  (let [env (resolve-env config env-arg)]
    (require-identity! env)
    (when-not (and file (.exists (io/file file)))
      (fail! (str "No such file: " file) {:file file}))
    (let [bs (age/decrypt-bytes (:identity-file env) file)]
      (.write System/out ^bytes bs)
      (.flush System/out))
    file))

(defn reencrypt!
  "Decrypt and immediately re-encrypt to the environment's current recipients —
  use after adding or removing a recipient (an `edit` with no change is a no-op
  and would not pick up recipient changes). Rewrites the manifest too. Returns
  the secrets-file path."
  [config env-arg]
  (require-age!)
  (let [{:keys [secrets-file identity-file name] :as env} (resolve-env config env-arg)]
    (require-identity! env)
    (require-encrypt-target! env)
    (when-not (.exists (io/file secrets-file))
      (fail! (str "No secrets file at " secrets-file "\n"
                  "    Create one with:  bb secrets new " (clojure.core/name name))
             {:secrets-file secrets-file :environment name}))
    (let [tmp (temp-plaintext!)]
      (try
        (info "Decrypting" secrets-file "…")
        (age/decrypt-to-file! identity-file secrets-file tmp)
        (info "Re-encrypting to current recipients…")
        (write-secrets! env tmp)
        (ok "Re-encrypted:" secrets-file)
        (when (string? (:manifest env)) (info "Manifest updated:" (:manifest env)))
        secrets-file
        (finally (secure-delete! tmp))))))

(defn add-recipient!
  "Add an age public key to an environment's recipients file. With no key given,
  adds the environment's own public key (from its key-file). Returns the
  recipient added (or already present)."
  [config env-arg pubkey]
  (require-age!)
  (let [{:keys [recipients-file key-file name]} (resolve-env config env-arg)
        nm (clojure.core/name name)]
    (when-not recipients-file
      (fail! (str nm " has no :recipients-file configured (single-key mode).\n"
                  "    Add :recipients-file to its config to encrypt to multiple people.")
             {:environment name}))
    (let [pub (or pubkey (age/public-key key-file))]
      (when-not pub
        (fail! (str "No public key given and no key at " key-file "\n"
                    "    Generate one with:  bb secrets keygen " nm)
               {:key-file key-file :environment name}))
      (when-not (age/valid-recipient? pub)
        (fail! (str "Not a valid age public key: " pub) {:recipient pub}))
      (let [pub      (str/trim pub)
            existing (or (read-recipients recipients-file) [])]
        (if (some #{pub} existing)
          (do (info "Already a recipient of" (str nm ":") pub)
              pub)
          (let [f (io/file (str recipients-file))]
            (when-let [p (.getParentFile f)] (.mkdirs p))
            (spit f (str (str/join "\n" (conj (vec existing) pub)) "\n"))
            (ok "Added recipient to" recipients-file)
            (println "   " pub)
            (warn "Re-encrypt so the new recipient can read existing secrets:")
            (println (paint :dim (str "      bb secrets reencrypt " nm)))
            pub))))))

(defn recipients!
  "List the recipients an environment encrypts to. Returns them as a seq (nil
  in single-key mode)."
  [config env-arg]
  (let [{:keys [recipients-file name]} (resolve-env config env-arg)
        nm (clojure.core/name name)]
    (if-not recipients-file
      (do (info nm "is in single-key mode — it encrypts to its own key, not a recipients list.")
          nil)
      (let [rs (read-recipients recipients-file)]
        (if (empty? rs)
          (warn "No recipients yet in" recipients-file)
          (do (println (paint :bold (str "Recipients for " nm " (" recipients-file "):")))
              (doseq [r rs] (println "  " r))))
        rs))))

(defn- verify-one
  "Verify one environment's committed manifest against its encrypted secrets.
  Prints a human-readable result and returns :ok, :ok-keyless, :drift, or
  :missing. Without an identity, falls back to comparing the manifest's
  recorded :ciphertext-sha against the actual ciphertext (freshness only)."
  [{:keys [secrets-file manifest identity-file name] :as env}]
  (let [nm (clojure.core/name name)]
    (cond
      (not (string? manifest))
      (do (info nm "— manifest disabled; skipping.") :ok)

      (not (.exists (io/file secrets-file)))
      (do (warn nm "— no secrets file at" secrets-file) :missing)

      (not (.exists (io/file (str manifest))))
      (do (warn nm "— no manifest at" manifest (str "(run `bb secrets edit " nm "` to create it)")) :missing)

      :else
      (let [committed (parse-edn (slurp (io/file (str manifest))))
            {:keys [version ciphertext-sha] committed-keys :keys} (:value committed)]
        (cond
          (not (:ok? committed))
          (do (oops nm "— manifest is not valid EDN:" (:error committed)) :drift)

          (not= 1 version)
          (do (oops nm "— manifest version" (pr-str version) "is unsupported by this version of the library.")
              (println (str "    Regenerate it with `bb secrets reencrypt " nm "`, or upgrade the library."))
              :drift)

          ;; No identity → keyless freshness check against :ciphertext-sha.
          (not (.exists (io/file identity-file)))
          (cond
            (nil? ciphertext-sha)
            (do (warn nm "— no identity at" identity-file
                      "and the manifest records no :ciphertext-sha; cannot verify.")
                :missing)

            (= ciphertext-sha (sha256 secrets-file))
            (do (ok nm "— ciphertext matches the manifest (freshness verified without a key; values not checked).")
                :ok-keyless)

            :else
            (do (oops nm "— ciphertext changed since the manifest was written" (str "(" manifest ")."))
                (println (str "    Regenerate with:  bb secrets reencrypt " nm))
                :drift))

          :else
          (let [{:keys [ok? value error]} (parse-edn (age/decrypt identity-file secrets-file))]
            (if-not ok?
              (do (oops nm "— encrypted secrets are not valid EDN:" error) :drift)
              (let [fresh          (manifest/entries value (manifest-hmac-key env))
                    d              (manifest/diff committed-keys fresh)
                    stale-entries? (not (every? empty? (vals d)))
                    stale-sha?     (and ciphertext-sha (not= ciphertext-sha (sha256 secrets-file)))]
                (when stale-entries?
                  (oops nm "— manifest is STALE" (str "(" manifest "):"))
                  (doseq [p (:added d)]   (println "    +" (pr-str p) "— in secrets, missing from manifest"))
                  (doseq [p (:removed d)] (println "    -" (pr-str p) "— in manifest, gone from secrets"))
                  (doseq [p (:changed d)] (println "    ~" (pr-str p) "— value or type changed")))
                (when stale-sha?
                  (oops nm "— ciphertext was re-encrypted out-of-band since the manifest was written."))
                (if (or stale-entries? stale-sha?)
                  (do (println "    Regenerate with:" (str "bb secrets reencrypt " nm))
                      :drift)
                  (do (ok nm "— manifest matches" (str "(" manifest ")")) :ok))))))))))

(defn verify!
  "Check that each environment's committed manifest matches its encrypted
  secrets. With no env, verifies all of them. Never exits — returns
  {:results {env-name status} :exit code}, where each status is :ok,
  :ok-keyless, :drift, or :missing, and code is 1 on any drift, else 2 on any
  missing artifact/key, else 0 (:ok and :ok-keyless both pass). `run!` exits
  with the code when it is non-zero, so `bb secrets verify` can gate CI.
  Deliberately does not require `age` up front: the keyless freshness check
  compares hashes only, so a CI job with neither a key nor the binary can
  still gate on it (full verification decrypts, and `age` enforces itself)."
  [config env-arg]
  (let [envs     (if env-arg [(resolve-env config env-arg)] (vals (:environments config)))
        results  (into {} (map (juxt :name verify-one)) envs)
        statuses (set (vals results))]
    {:results results
     :exit    (cond (statuses :drift)   1
                    (statuses :missing) 2
                    :else               0)}))

;; ---------- Dispatch ----------

(def ^:private commands
  [["keygen"        "[env]"        "Generate an age key for an environment"]
   ["new"           "[env]"        "Create a new encrypted secrets file (opens $EDITOR)"]
   ["edit"          "[env]"        "Edit an existing secrets file (decrypt → edit → re-encrypt)"]
   ["verify"        "[env]"        "Check the committed manifest matches the secrets"]
   ["show-key"      "[env]"        "Print public key(s) for sharing"]
   ["add-recipient" "[env] [key]"  "Add a public key to the env's recipients file"]
   ["recipients"    "[env]"        "List the recipients an env encrypts to"]
   ["reencrypt"     "[env]"        "Re-encrypt to current recipients (after a change)"]
   ["encrypt"       "[env] <file>" "Encrypt an arbitrary file to <file>.age"]
   ["decrypt"       "[env] <file>" "Decrypt a <file>.age to stdout"]
   ["help"          ""             "Show this help"]])

(defn- print-help [{:keys [environments default-environment]}]
  (println (paint :bold "Manage encrypted secrets (age).") "\n")
  (println "Usage: bb secrets <command> [args]\n")
  (doseq [[cmd args doc] commands]
    (println (format "  %-14s %-14s %s" cmd args doc)))
  (println)
  (println "Environments:" (str/join ", " (map name (keys environments)))
           (if default-environment (str "(default: " (name default-environment) ")") ""))
  (println (paint :dim "\n  An omitted [env] uses the default environment."))
  (println (paint :dim "  verify exits 0 (ok) · 1 (drift) · 2 (missing artifacts/key).")))

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

(defn run!
  "Entry point. Dispatch `args` (typically *command-line-args*) against `config`.
  The ONLY fn in this namespace that exits the process: command failures arrive
  as ex-info (printed with their :hint/:install/:error/:docs data; exit code
  from :secrets/exit, default 1), and `verify` returns its own exit code."
  [config args]
  (try
    (let [config (normalize-config config)
          [cmd & more] args]
      (case (some-> cmd str/lower-case)
        "keygen"        (keygen!        config (first more))
        "new"           (new!           config (first more))
        "edit"          (edit!          config (first more))
        "verify"        (let [{:keys [exit]} (verify! config (first more))]
                          (when (pos? exit) (System/exit exit)))
        "show-key"      (show-key!      config (first more))
        "add-recipient" (add-recipient! config (first more) (second more))
        "recipients"    (recipients!    config (first more))
        "reencrypt"     (reencrypt!     config (first more))
        ;; encrypt/decrypt take [env] <file>; with one arg it is the file,
        ;; and the default environment applies.
        "encrypt"       (if (second more)
                          (encrypt! config (first more) (second more))
                          (encrypt! config nil (first more)))
        "decrypt"       (if (second more)
                          (decrypt! config (first more) (second more))
                          (decrypt! config nil (first more)))
        ("help" nil)    (print-help config)
        (do (print-help config)
            (fail! (str "Unknown command: " cmd) {:command cmd}))))
    (catch clojure.lang.ExceptionInfo e
      (print-error! e)
      (System/exit (:secrets/exit (ex-data e) 1)))))
