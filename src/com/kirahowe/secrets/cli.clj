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
  secure-delete cycle never leaves plaintext on disk."
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

(defn- die [& xs]
  (apply oops xs)
  (System/exit 1))

(defn- confirm!
  "Prompt y/N; return true on yes, abort (exit 0) otherwise."
  [prompt]
  (print (str (paint :yellow "?") " " prompt " [y/N] "))
  (flush)
  (if (= "y" (some-> (read-line) str/trim str/lower-case))
    true
    (do (info "Aborted.") (System/exit 0))))

;; ---------- Config ----------

(defn normalize-config
  "Apply per-environment defaults (:key-file, :template, :manifest) and stamp
  each env with its :name. Throws if no environments are configured."
  [{:keys [app environments] :as config}]
  (when (empty? environments)
    (throw (ex-info "secrets config has no :environments" {:config config})))
  (let [app (or app "secrets")]
    (assoc config
           :app app
           :environments
           (into {}
                 (map (fn [[env {:keys [secrets-file key-file template manifest recipients-file] :as e}]]
                        [env (assoc e
                                    :name env
                                    :app app
                                    :secrets-file secrets-file
                                    :key-file (secrets/expand-home
                                               (or key-file (str "~/.config/" app "/key.txt")))
                                    :template (or template
                                                  (str/replace secrets-file #"\.age$" ".example"))
                                    ;; :manifest false disables it; absent ⇒ derive from secrets-file.
                                    :manifest (if (contains? e :manifest)
                                                manifest
                                                (str/replace secrets-file #"\.age$" ".manifest"))
                                    :recipients-file (some-> recipients-file secrets/expand-home))]))
                 environments))))

(defn- resolve-env
  "Resolve an environment argument string to its (defaulted) config map."
  [{:keys [environments default-environment]} env-arg]
  (let [env-key (cond
                  (and (nil? env-arg) default-environment) default-environment
                  (nil? env-arg) (die "Missing environment. One of:"
                                      (str/join ", " (map name (keys environments))))
                  :else (keyword env-arg))]
    (or (environments env-key)
        (die (str "Unknown environment: " (name env-key) ". One of: ")
             (str/join ", " (map name (keys environments)))))))

;; ---------- Utilities ----------

(defn- editor [] (or (System/getenv "VISUAL") (System/getenv "EDITOR") "vim"))

(defn- run-editor!
  "Open `$EDITOR` on `path`, inheriting the terminal. Throws if it exits non-zero."
  [path]
  (let [proc (-> (ProcessBuilder. (into-array String [(editor) (str path)]))
                 (.inheritIO)
                 (.start))]
    (when-not (zero? (.waitFor proc))
      (die "Editor exited with an error; leaving secrets unchanged."))))

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
  "Create an owner-only temp file for plaintext secrets."
  []
  (doto (java.io.File/createTempFile "secrets-" ".edn")
    (.deleteOnExit)
    (.setReadable false false) (.setReadable true true)
    (.setWritable false false) (.setWritable true true)))

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
    (die "The `age` tool is not installed.\n"
         "    macOS:  brew install age\n"
         "    Ubuntu: apt install age\n"
         "    Docs:   https://age-encryption.org")))

(defn- require-key! [{:keys [key-file name]}]
  (when-not (.exists (io/file key-file))
    (die (str "No age key for " (clojure.core/name name) " at " key-file "\n")
         (str "    Create one with:  bb secrets keygen " (clojure.core/name name)))))

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
  in multi-recipient mode, otherwise the environment's own identity (single-key)."
  [{:keys [recipients-file key-file]}]
  (if recipients-file {:recipients-file recipients-file} {:identity-file key-file}))

(defn- require-encrypt-target!
  "Ensure we can encrypt: a non-empty recipients file (multi-recipient mode), or
  the private key (single-key mode, where we encrypt to our own identity)."
  [{:keys [recipients-file name] :as env}]
  (if recipients-file
    (when (empty? (read-recipients recipients-file))
      (die (str "No recipients yet for " (clojure.core/name name) " in " recipients-file "\n")
           (str "    Add one with:  bb secrets add-recipient " (clojure.core/name name))))
    (require-key! env)))

;; ---------- Manifest ----------

(defn- manifest-hmac-key
  "The manifest HMAC key for an environment: derived from the shared private key
  in single-key mode, nil in multi-recipient mode (no single shared key), so the
  manifest is structure-only for teams."
  [{:keys [recipients-file key-file]}]
  (when (and (not recipients-file) (.exists (io/file key-file)))
    (manifest/hmac-key (slurp key-file))))

(defn- parse-edn [s]
  (try {:ok? true :value (edn/read-string s)}
       (catch Exception e {:ok? false :error (ex-message e)})))

(defn- write-manifest!
  "Regenerate the plaintext manifest next to the secrets file from `plaintext`
  (the just-saved secrets text). No-op when the env disabled the manifest."
  [{:keys [manifest app] :as env} plaintext]
  (when (string? manifest)
    (let [{:keys [ok? value error]} (parse-edn plaintext)]
      (if-not ok?
        (warn (str "Secrets are not valid EDN (" error ") — manifest not updated:\n")
              (str "    " manifest " — fix with `bb secrets edit` and re-save."))
        (do (spit (io/file (str manifest))
                  (manifest/render app (manifest/entries value (manifest-hmac-key env))))
            (info "Manifest updated:" manifest))))))

;; ---------- Commands ----------

(defn keygen!
  "Generate an age identity for an environment's key-file."
  [config env-arg]
  (require-age!)
  (let [{:keys [key-file name recipients-file]} (resolve-env config env-arg)]
    (when (.exists (io/file key-file))
      (warn "Key already exists:" key-file)
      (confirm! "Overwrite? Existing secrets encrypted to it become UNREADABLE."))
    (info "Generating age key for" (clojure.core/name name) "…")
    (let [pub (age/keygen! key-file)]
      (ok "Key written:" key-file)
      (println)
      (println (paint :bold "  Public key:") pub)
      (println)
      (warn "Back this key up (e.g. a password manager). It is NOT in git and")
      (println "    cannot be recovered. To deploy, set it as the AGE_IDENTITY secret:")
      (println (paint :dim (str "      flyctl secrets set AGE_IDENTITY=\"$(cat " key-file ")\"")))
      (when recipients-file
        (println)
        (info "This project encrypts to a shared recipients file. Add your public")
        (println "    key so teammates encrypt secrets you can read:")
        (println (paint :dim (str "      bb secrets add-recipient " (clojure.core/name name))))))))

(defn new!
  "Create a new encrypted secrets file from a template via $EDITOR."
  [config env-arg]
  (require-age!)
  (let [{:keys [secrets-file name] :as env} (resolve-env config env-arg)]
    (require-encrypt-target! env)
    (when (.exists (io/file secrets-file))
      (warn "Secrets file already exists:" secrets-file)
      (confirm! (str "Overwrite it? (To change values, use `bb secrets edit " (clojure.core/name name) "` instead.)")))
    (let [tmp (temp-plaintext!)]
      (try
        (spit tmp (template-content env))
        (info "Opening" (editor) "…")
        (run-editor! tmp)
        (when-let [parent (.getParentFile (io/file secrets-file))] (.mkdirs parent))
        (info "Encrypting…")
        (age/encrypt-file! (encrypt-recipients env) tmp secrets-file)
        (ok "Encrypted secrets written:" secrets-file)
        (write-manifest! env (slurp tmp))
        (finally (secure-delete! tmp))))))

(defn edit!
  "Decrypt → edit → re-encrypt an existing secrets file (no plaintext left on disk)."
  [config env-arg]
  (require-age!)
  (let [{:keys [secrets-file name] :as env} (resolve-env config env-arg)]
    (require-key! env)
    (require-encrypt-target! env)
    (when-not (.exists (io/file secrets-file))
      (die (str "No secrets file at " secrets-file "\n")
           (str "    Create one with:  bb secrets new " (clojure.core/name name))))
    (let [tmp (temp-plaintext!)]
      (try
        (info "Decrypting" secrets-file "…")
        (age/decrypt-to-file! (:key-file env) secrets-file tmp)
        (let [before (sha256 tmp)]
          (run-editor! tmp)
          (if (= before (sha256 tmp))
            (warn "No changes — leaving" secrets-file "untouched.")
            (do (info "Re-encrypting…")
                (age/encrypt-file! (encrypt-recipients env) tmp secrets-file)
                (ok "Secrets updated:" secrets-file)
                (write-manifest! env (slurp tmp)))))
        (finally (secure-delete! tmp))))))

(defn show-key!
  "Print the public key(s) — share these so teammates can encrypt to you."
  [config env-arg]
  (require-age!)
  (let [envs (if env-arg
               [(resolve-env config env-arg)]
               (vals (:environments config)))]
    (doseq [{:keys [key-file name]} (distinct-by :key-file envs)]
      (if-let [pub (age/public-key key-file)]
        (println (format "  %-6s %s" (str (clojure.core/name name) ":") pub))
        (warn (format "%s: no key at %s" (clojure.core/name name) key-file))))))

(defn encrypt!
  "Encrypt an arbitrary plaintext file to <file>.age using an environment's
  recipients (its recipients file, or its own key in single-key mode)."
  [config env-arg file]
  (require-age!)
  (let [env (resolve-env config env-arg)]
    (require-encrypt-target! env)
    (when-not (.exists (io/file file)) (die "No such file:" file))
    (let [out (str file ".age")]
      (age/encrypt-file! (encrypt-recipients env) file out)
      (ok "Encrypted:" out))))

(defn decrypt!
  "Decrypt a <file>.age to stdout (plaintext is never written to disk)."
  [config env-arg file]
  (require-age!)
  (let [env (resolve-env config env-arg)]
    (require-key! env)
    (when-not (.exists (io/file file)) (die "No such file:" file))
    (print (age/decrypt (:key-file env) file))
    (flush)))

(defn reencrypt!
  "Decrypt and immediately re-encrypt to the environment's current recipients —
  use after adding or removing a recipient (an `edit` with no change is a no-op
  and would not pick up recipient changes). Rewrites the manifest too."
  [config env-arg]
  (require-age!)
  (let [{:keys [secrets-file key-file name] :as env} (resolve-env config env-arg)]
    (require-key! env)
    (require-encrypt-target! env)
    (when-not (.exists (io/file secrets-file))
      (die (str "No secrets file at " secrets-file "\n")
           (str "    Create one with:  bb secrets new " (clojure.core/name name))))
    (let [tmp (temp-plaintext!)]
      (try
        (info "Decrypting" secrets-file "…")
        (age/decrypt-to-file! key-file secrets-file tmp)
        (info "Re-encrypting to current recipients…")
        (age/encrypt-file! (encrypt-recipients env) tmp secrets-file)
        (ok "Re-encrypted:" secrets-file)
        (write-manifest! env (slurp tmp))
        (finally (secure-delete! tmp))))))

(defn add-recipient!
  "Add an age public key to an environment's recipients file. With no key given,
  adds the environment's own public key (from its key-file)."
  [config env-arg pubkey]
  (require-age!)
  (let [{:keys [recipients-file key-file name]} (resolve-env config env-arg)
        nm (clojure.core/name name)]
    (when-not recipients-file
      (die (str nm " has no :recipients-file configured (single-key mode).\n")
           "    Add :recipients-file to its config to encrypt to multiple people."))
    (let [pub (or pubkey (age/public-key key-file))]
      (when-not pub
        (die (str "No public key given and no key at " key-file "\n")
             (str "    Generate one with:  bb secrets keygen " nm)))
      (when-not (age/valid-recipient? pub)
        (die "Not a valid age public key:" pub))
      (let [pub      (str/trim pub)
            existing (or (read-recipients recipients-file) [])]
        (if (some #{pub} existing)
          (info "Already a recipient of" (str nm ":") pub)
          (let [f (io/file (str recipients-file))]
            (when-let [p (.getParentFile f)] (.mkdirs p))
            (spit f (str (str/join "\n" (conj (vec existing) pub)) "\n"))
            (ok "Added recipient to" recipients-file)
            (println "   " pub)
            (warn "Re-encrypt so the new recipient can read existing secrets:")
            (println (paint :dim (str "      bb secrets reencrypt " nm)))))))))

(defn recipients!
  "List the recipients an environment encrypts to."
  [config env-arg]
  (let [{:keys [recipients-file name]} (resolve-env config env-arg)
        nm (clojure.core/name name)]
    (if-not recipients-file
      (info nm "is in single-key mode — it encrypts to its own key, not a recipients list.")
      (let [rs (read-recipients recipients-file)]
        (if (empty? rs)
          (warn "No recipients yet in" recipients-file)
          (do (println (paint :bold (str "Recipients for " nm " (" recipients-file "):")))
              (doseq [r rs] (println "  " r))))))))

(defn- verify-one
  "Verify one environment's manifest against its (decrypted) secrets. Prints a
  human-readable result and returns :ok, :drift, or :missing."
  [{:keys [secrets-file manifest key-file name] :as env}]
  (let [nm (clojure.core/name name)]
    (cond
      (not (string? manifest))
      (do (info nm "— manifest disabled; skipping.") :ok)

      (not (.exists (io/file secrets-file)))
      (do (warn nm "— no secrets file at" secrets-file) :missing)

      (not (.exists (io/file (str manifest))))
      (do (warn nm "— no manifest at" manifest (str "(run `bb secrets edit " nm "` to create it)")) :missing)

      (not (.exists (io/file key-file)))
      (do (warn nm "— no key at" key-file "(needed to decrypt and verify)") :missing)

      :else
      (let [{:keys [ok? value error]} (parse-edn (age/decrypt key-file secrets-file))]
        (if-not ok?
          (do (oops nm "— encrypted secrets are not valid EDN:" error) :drift)
          (let [fresh     (manifest/entries value (manifest-hmac-key env))
                committed (parse-edn (slurp (io/file (str manifest))))]
            (if-not (:ok? committed)
              (do (oops nm "— manifest is not valid EDN:" (:error committed)) :drift)
              (let [d (manifest/diff (:keys (:value committed)) fresh)]
                (if (every? empty? (vals d))
                  (do (ok nm "— manifest matches" (str "(" manifest ")")) :ok)
                  (do (oops nm "— manifest is STALE" (str "(" manifest "):"))
                      (doseq [p (:added d)]   (println "    +" (pr-str p) "— in secrets, missing from manifest"))
                      (doseq [p (:removed d)] (println "    -" (pr-str p) "— in manifest, gone from secrets"))
                      (doseq [p (:changed d)] (println "    ~" (pr-str p) "— value or type changed"))
                      (println "    Regenerate with:" (str "bb secrets reencrypt " nm))
                      :drift))))))))))

(defn verify!
  "Check that each environment's committed manifest matches its encrypted
  secrets. With no env, verifies all of them. Exits non-zero on any drift or
  missing artifact, so it can gate CI."
  [config env-arg]
  (require-age!)
  (let [envs    (if env-arg [(resolve-env config env-arg)] (vals (:environments config)))
        results (mapv verify-one envs)]
    (when (some #{:drift :missing} results)
      (System/exit 1))))

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
   ["encrypt"       "<file> [env]" "Encrypt an arbitrary file to <file>.age"]
   ["decrypt"       "<file> [env]" "Decrypt a <file>.age to stdout"]
   ["help"          ""             "Show this help"]])

(defn- print-help [{:keys [environments default-environment]}]
  (println (paint :bold "Manage encrypted secrets (age).") "\n")
  (println "Usage: bb secrets <command> [args]\n")
  (doseq [[cmd args doc] commands]
    (println (format "  %-14s %-14s %s" cmd args doc)))
  (println)
  (println "Environments:" (str/join ", " (map name (keys environments)))
           (if default-environment (str "(default: " (name default-environment) ")") ""))
  (println (paint :dim "\n  An omitted [env] uses the default environment.")))

(defn run!
  "Entry point. Dispatch `args` (typically *command-line-args*) against `config`."
  [config args]
  (try
    (let [config (normalize-config config)
          [cmd & more] args]
      (case (some-> cmd str/lower-case)
        "keygen"        (keygen!        config (first more))
        "new"           (new!           config (first more))
        "edit"          (edit!          config (first more))
        "verify"        (verify!        config (first more))
        "show-key"      (show-key!      config (first more))
        "add-recipient" (add-recipient! config (first more) (second more))
        "recipients"    (recipients!    config (first more))
        "reencrypt"     (reencrypt!     config (first more))
        ;; encrypt/decrypt take <file> first, optional [env] second
        "encrypt"       (encrypt!       config (second more) (first more))
        "decrypt"       (decrypt!       config (second more) (first more))
        ("help" nil)    (print-help config)
        (do (oops "Unknown command:" cmd) (print-help config) (System/exit 1))))
    (catch clojure.lang.ExceptionInfo e
      (die (ex-message e)))))
