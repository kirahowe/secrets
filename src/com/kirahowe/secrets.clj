(ns com.kirahowe.secrets
  "Runtime loading of age-encrypted EDN secrets.

  Secrets live in a single version-controlled, age-encrypted EDN file
  (`secrets.edn.age`). At runtime they are decrypted once with your age
  identity (private key) and read into a plain Clojure map. The plaintext is
  never written to disk and never committed.

  Two ways to consume secrets:

  • As an Integrant/component value — call `load-secrets` to get the map and
    `get-secret` to read keys from it. (See the README for a two-line init-key.)

  • As EDN reader literals — call `reader-literals` (or `merge-readers`) to get
    `#secret/req` / `#secret/opt` tags you can register with your config
    reader, so config files reference secrets inline:

        :jdbc-url #secret/req :database/url  ; required — throws if absent
        :api-key  #secret/opt :llm/api-key   ; optional — nil if absent

  Identity resolution (where the private key comes from), in order:
    1. $SECRETS_AGE_IDENTITY_FILE — a path to the key file.
    2. $SECRETS_AGE_IDENTITY      — the raw key file *contents*, used verbatim and
       materialized to a 0600 temp file. Lets a deploy inject the key as one
       secret/env var.
    3. $SECRETS_AGE_IDENTITY_B64  — base64-encoded key file contents (newline-tolerant),
       for secret stores that mangle multi-line values. Invalid base64 throws —
       there is no silent fallback.
    4. ~/.config/<app>/key.txt — the local developer default, used only when an
       app name is known (an `:app` option or app argument).
  When none of these yields an identity, resolution returns nil and loading
  throws with the options above rather than guessing a path."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [com.kirahowe.secrets.age :as age]))

(def ^:private not-found ::not-found)

(defn expand-home
  "Expand a leading ~ to the user's home directory."
  [path]
  (let [s (str path)]
    (if (str/starts-with? s "~")
      (str (System/getProperty "user.home") (subs s 1))
      s)))

;; ---------- 0600 temp files ----------

(defn owner-only-temp-file!
  "Create a delete-on-exit temp file that is owner-only (0600) from the moment
  it exists — atomically via NIO POSIX attributes, so there is no window with
  default-umask permissions. Falls back to create-then-chmod on filesystems
  without POSIX permissions. Returns a java.io.File. Used for every file this
  library materializes that may hold sensitive bytes (identities, plaintext)."
  [prefix suffix]
  (doto (try
          (.toFile
           (java.nio.file.Files/createTempFile
            prefix suffix
            (into-array java.nio.file.attribute.FileAttribute
                        [(java.nio.file.attribute.PosixFilePermissions/asFileAttribute
                          #{java.nio.file.attribute.PosixFilePermission/OWNER_READ
                            java.nio.file.attribute.PosixFilePermission/OWNER_WRITE})])))
          (catch UnsupportedOperationException _
            (doto (java.io.File/createTempFile prefix suffix)
              (.setReadable false false) (.setReadable true true)
              (.setWritable false false) (.setWritable true true))))
    (.deleteOnExit)))

;; ---------- Identity (private key) resolution ----------

(def ^:private identity-temp
  "Caches the temp file materialized from $SECRETS_AGE_IDENTITY / $SECRETS_AGE_IDENTITY_B64 so
  the key is written to disk at most once per process, keyed on its contents."
  (atom {}))

(defn- decode-b64-identity
  "Decode an $SECRETS_AGE_IDENTITY_B64 value (base64 of the key file contents,
  newline-tolerant) to the raw identity text. Throws on invalid base64 —
  never falls back to using the value verbatim."
  [contents]
  (try
    (String. (.decode (java.util.Base64/getMimeDecoder) (str/trim contents)) "UTF-8")
    (catch IllegalArgumentException e
      (throw (ex-info (str "SECRETS_AGE_IDENTITY_B64 is not valid base64. Set it to the"
                           " base64-encoded age key file contents, or use"
                           " SECRETS_AGE_IDENTITY (raw contents) / SECRETS_AGE_IDENTITY_FILE"
                           " (a path) instead.")
                      {:env "SECRETS_AGE_IDENTITY_B64"}
                      e)))))

(defn- materialize-identity!
  "Write age identity `contents` (verbatim) to an owner-only 0600 temp file,
  at most once per process per distinct contents, and return its path."
  [contents]
  (or (@identity-temp contents)
      (let [f (owner-only-temp-file! "age-identity-" ".txt")]
        (spit f contents)
        (let [path (.getAbsolutePath f)]
          (swap! identity-temp assoc contents path)
          path))))

(defn identity-from-env
  "Resolve the age identity (private key) file path from the environment, or
  nil when no identity variable is set. Checked in order:
    $SECRETS_AGE_IDENTITY_FILE — a path to the key file, returned as-is.
    $SECRETS_AGE_IDENTITY      — the raw key file contents, used verbatim.
    $SECRETS_AGE_IDENTITY_B64  — base64-encoded key file contents (invalid base64 throws).
  Contents are materialized to a 0600 temp file, written at most once per
  process. Public (rather than folded into `resolve-identity-file`) so callers
  like the CLI namespace can layer their own defaults under it when it
  returns nil."
  []
  (or (System/getenv "SECRETS_AGE_IDENTITY_FILE")
      (when-let [c (System/getenv "SECRETS_AGE_IDENTITY")]
        (materialize-identity! c))
      (when-let [c (System/getenv "SECRETS_AGE_IDENTITY_B64")]
        (materialize-identity! (decode-b64-identity c)))))

(defn resolve-identity-file
  "Resolve the age identity (private key) file path: the environment first
  (see `identity-from-env`), then `~/.config/<app>/key.txt` when an app name
  is given. Returns nil when no env var is set and no app is known — there is
  deliberately no default path, so callers fail loudly instead of reading some
  other app's key. `app-or-opts` is an app-name string or a map with `:app`."
  ([] (resolve-identity-file nil))
  ([app-or-opts]
   (let [app (if (map? app-or-opts) (:app app-or-opts) app-or-opts)]
     (or (identity-from-env)
         (when app (expand-home (str "~/.config/" app "/key.txt")))))))

(def ^:private identity-options
  "One-line remediation appended to \"no identity\" errors."
  (str "Set SECRETS_AGE_IDENTITY_FILE (key path), SECRETS_AGE_IDENTITY (raw key contents), or "
       "SECRETS_AGE_IDENTITY_B64 (base64 contents); pass {:identity-file …} or "
       "{:app \"myapp\"} (→ ~/.config/myapp/key.txt); or create the key with "
       "`bb secrets keygen`."))

;; ---------- Loading ----------

(defn- source->file
  "Coerce a secrets `source` to a [file cleanup!] pair. Path strings and Files
  naming an existing file are used in place (no cleanup). Anything else that
  `io/input-stream` can open — any URL (including a jar: resource URL from
  inside an uberjar), an InputStream, … — is copied to a 0600 temp file so
  `age` can read it; cleanup deletes that copy."
  [source]
  (let [f (when (or (instance? java.io.File source) (string? source))
            (io/file source))]
    (if (and f (.exists f))
      [f (fn [])]
      (let [tmp (owner-only-temp-file! "secrets-" ".age")]
        (with-open [in  (io/input-stream source)
                    out (io/output-stream tmp)]
          (io/copy in out))
        [tmp #(.delete tmp)]))))

(defn load-secrets
  "Decrypt and read an age-encrypted EDN file into a map.

  `source` is the encrypted file: a path string, a File, or a URL/resource (as
  returned by `clojure.java.io/resource`, including a jar: URL inside an
  uberjar). `identity-or-opts` selects the identity (private key): a path
  String/File, or an opts map:
    :identity-file  explicit identity path (wins over :app and the env vars)
    :app            app name for the default ~/.config/<app>/key.txt
  With neither, the identity comes from `resolve-identity-file` (the
  SECRETS_AGE_IDENTITY* env vars). Throws when no identity resolves or the resolved
  identity file does not exist.

  Reads with `clojure.edn` (no eval), so secret files are plain data and may use
  any EDN — including native sets for allowlists, e.g. `#{\"a@b.com\"}`."
  ([source] (load-secrets source nil))
  ([source identity-or-opts]
   (let [identity (if (map? identity-or-opts)
                    (or (:identity-file identity-or-opts)
                        (resolve-identity-file identity-or-opts))
                    (or identity-or-opts (resolve-identity-file)))]
     (when-not (and identity (.exists (io/file (str identity))))
       (throw (ex-info (str "No age identity found"
                            (when identity (str " (" identity " does not exist)"))
                            ". " identity-options)
                       {:identity (some-> identity str) :source (str source)})))
     (let [[file cleanup!] (source->file source)]
       (try
         (edn/read-string (age/decrypt identity (.getAbsolutePath ^java.io.File file)))
         (finally (cleanup!)))))))

(defn get-secret
  "Read a secret from a loaded map. `key-path` is a single key (`:database/url`)
  or a vector path into nested maps (`[:database :url]`). Returns `default`
  (nil) when absent."
  ([secrets key-path] (get-secret secrets key-path nil))
  ([secrets key-path default]
   (if (vector? key-path)
     (get-in secrets key-path default)
     (get secrets key-path default))))

;; ---------- EDN reader literals ----------

(defn reader-literals
  "Build the `#secret/req` / `#secret/opt` EDN reader-literal functions, bound
  to a secrets source. Returns a map of `{symbol fn}` ready to merge into the
  `:readers` you pass to `clojure.edn/read-string` or `integrant.core/read-string`.

  Options:
    :resource      classpath resource name to decrypt, e.g. \"secrets.edn.age\"
                   (resolved lazily with io/resource; nil/absent ⇒ no secrets).
    :file          an explicit file path, used instead of :resource.
    :app           app name for the default key path ~/.config/<app>/key.txt.
    :identity-file explicit identity path (overrides resolution).

  The file is resolved and decrypted at most once, on the first tag
  encountered — so configs with no secret tags (e.g. dev/test) never touch
  `age` or the key, even when a secrets file happens to be on the classpath.

  Semantics, mirroring required/optional env reads:
    #secret/req k → required: throws when no secrets file is found, when no
                    identity (key) is available, or when the key is missing
                    from the decrypted map.
    #secret/opt k → optional: nil in all three of those cases.
  A genuine decryption failure — the identity file exists but `age` fails
  (wrong key, not a recipient, `age` not installed) — always throws, for both
  tags, on every use."
  [{:keys [resource file app identity-file]}]
  (let [identity (delay (or identity-file (resolve-identity-file app)))
        ;; One of {:present? false :reason :no-file}, {:present? false :reason
        ;; :no-identity}, or {:present? true :secrets m} — computed once; a
        ;; decryption failure is cached and re-thrown by every tag.
        loaded   (delay
                   (let [src (cond file     (when (.exists (io/file (str file))) (io/file (str file)))
                                   resource (io/resource resource))]
                     (cond
                       (nil? src)
                       {:present? false :reason :no-file}

                       (not (and @identity (.exists (io/file (str @identity)))))
                       {:present? false :reason :no-identity}

                       :else
                       {:present? true :secrets (load-secrets src @identity)})))
        describe (or file resource "secrets")]
    {'secret/req
     (fn [key-path]
       (let [{:keys [present? reason secrets]} @loaded]
         (when-not present?
           (throw (ex-info (if (= reason :no-identity)
                             (str "Required secret " (pr-str key-path)
                                  " needs an age identity, but none is available. "
                                  identity-options)
                             (str "Required secret " (pr-str key-path)
                                  " — but no secrets file found (" describe ")."))
                           {:key key-path :source describe :reason reason})))
         (let [v (get-secret secrets key-path not-found)]
           (when (= v not-found)
             (throw (ex-info (str "Required secret " (pr-str key-path)
                                  " is missing from the secrets file.")
                             {:key key-path :source describe :reason :missing-key})))
           v)))

     'secret/opt
     (fn [key-path]
       (let [{:keys [present? secrets]} @loaded]
         (when present?
           (get-secret secrets key-path))))}))

(defn merge-readers
  "Convenience: merge `reader-literals` into an existing `:readers` map."
  [readers opts]
  (merge readers (reader-literals opts)))
