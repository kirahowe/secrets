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

  Commands: keygen · new · edit · show-key · encrypt · decrypt · help.
  The decrypt → edit → re-encrypt → secure-delete cycle never leaves plaintext
  on disk."
  (:require [clojure.java.io :as io]
            [clojure.java.shell :as shell]
            [clojure.string :as str]
            [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.age :as age]))

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
  "Apply per-environment defaults (:key-file, :template) and stamp each env with
  its :name. Throws if no environments are configured."
  [{:keys [app environments] :as config}]
  (when (empty? environments)
    (throw (ex-info "secrets config has no :environments" {:config config})))
  (let [app (or app "secrets")]
    (assoc config
           :app app
           :environments
           (into {}
                 (map (fn [[env {:keys [secrets-file key-file template] :as e}]]
                        [env (assoc e
                                    :name env
                                    :secrets-file secrets-file
                                    :key-file (secrets/expand-home
                                               (or key-file (str "~/.config/" app "/key.txt")))
                                    :template (or template
                                                  (str/replace secrets-file #"\.age$" ".example")))]))
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

;; ---------- Commands ----------

(defn keygen!
  "Generate an age identity for an environment's key-file."
  [config env-arg]
  (require-age!)
  (let [{:keys [key-file name]} (resolve-env config env-arg)]
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
      (println (paint :dim (str "      flyctl secrets set AGE_IDENTITY=\"$(cat " key-file ")\""))))))

(defn new!
  "Create a new encrypted secrets file from a template via $EDITOR."
  [config env-arg]
  (require-age!)
  (let [{:keys [secrets-file name] :as env} (resolve-env config env-arg)]
    (require-key! env)
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
        (age/encrypt-file! (:key-file env) tmp secrets-file)
        (ok "Encrypted secrets written:" secrets-file)
        (finally (secure-delete! tmp))))))

(defn edit!
  "Decrypt → edit → re-encrypt an existing secrets file (no plaintext left on disk)."
  [config env-arg]
  (require-age!)
  (let [{:keys [secrets-file name] :as env} (resolve-env config env-arg)]
    (require-key! env)
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
                (age/encrypt-file! (:key-file env) tmp secrets-file)
                (ok "Secrets updated:" secrets-file))))
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
  "Encrypt an arbitrary plaintext file to <file>.age using an environment's key."
  [config env-arg file]
  (require-age!)
  (let [env (resolve-env config env-arg)]
    (require-key! env)
    (when-not (.exists (io/file file)) (die "No such file:" file))
    (let [out (str file ".age")]
      (age/encrypt-file! (:key-file env) file out)
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

;; ---------- Dispatch ----------

(def ^:private commands
  [["keygen"   "[env]"          "Generate an age key for an environment"]
   ["new"      "[env]"          "Create a new encrypted secrets file (opens $EDITOR)"]
   ["edit"     "[env]"          "Edit an existing secrets file (decrypt → edit → re-encrypt)"]
   ["show-key" "[env]"          "Print public key(s) for sharing"]
   ["encrypt"  "<file> [env]"   "Encrypt an arbitrary file to <file>.age"]
   ["decrypt"  "<file> [env]"   "Decrypt a <file>.age to stdout"]
   ["help"     ""               "Show this help"]])

(defn- print-help [{:keys [environments default-environment]}]
  (println (paint :bold "Manage encrypted secrets (age).") "\n")
  (println "Usage: bb secrets <command> [args]\n")
  (doseq [[cmd args doc] commands]
    (println (format "  %-9s %-14s %s" cmd args doc)))
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
        "keygen"   (keygen!   config (first more))
        "new"      (new!      config (first more))
        "edit"     (edit!     config (first more))
        "show-key" (show-key! config (first more))
        ;; encrypt/decrypt take <file> first, optional [env] second
        "encrypt"  (encrypt!  config (second more) (first more))
        "decrypt"  (decrypt!  config (second more) (first more))
        ("help" nil) (print-help config)
        (do (oops "Unknown command:" cmd) (print-help config) (System/exit 1))))
    (catch clojure.lang.ExceptionInfo e
      (die (ex-message e)))))
