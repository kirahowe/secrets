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

(def ^:private identity-env-help
  "What each identity variable should contain, for the set-but-empty error."
  {"SECRETS_AGE_IDENTITY_FILE" "a path to the age key file"
   "SECRETS_AGE_IDENTITY"      "the age key file contents"
   "SECRETS_AGE_IDENTITY_B64"  "the base64-encoded age key file contents"})

(defn- identity-env-value
  "The value of identity variable `k`, or nil when it is unset. A variable that
  is set but blank throws rather than resolving. Takes the value rather than
  reading it, so the rule is testable without setting process environment.

  CI runners expand a missing or misnamed secret to the empty string
  (`SECRETS_AGE_IDENTITY: ${{ secrets.AGE_KEY }}` with no such secret, and the
  docker-compose equivalent), so blank means a broken deployment, not an absent
  one. Neither alternative is safe: using the value resolves to an empty key
  file and fails far downstream as \"wrong key, or you are not a recipient\",
  and skipping to the next source would silently fall back to
  ~/.config/<app>/key.txt — succeeding on a developer machine with the *local*
  key while the deployment it was meant to configure is broken."
  [k v]
  (when (and v (str/blank? v))
    (throw (ex-info (str k " is set but empty. Unset it to fall back to the next"
                         " identity source, or set it to " (identity-env-help k) ".")
                    {:env k})))
  v)

(defn- identity-env
  "`identity-env-value` applied to the live environment."
  [k]
  (identity-env-value k (System/getenv k)))

(defn identity-from-env
  "Return an age identity file path from the environment, or nil. Sources are
  checked in order:
    $SECRETS_AGE_IDENTITY_FILE — a path to the key file, returned as-is.
    $SECRETS_AGE_IDENTITY      — the raw key file contents, used verbatim.
    $SECRETS_AGE_IDENTITY_B64  — base64-encoded key file contents (invalid base64 throws).
  A blank value throws. Raw or decoded contents are cached in owner-only temp
  files, one per distinct value."
  []
  (or (identity-env "SECRETS_AGE_IDENTITY_FILE")
      (when-let [c (identity-env "SECRETS_AGE_IDENTITY")]
        (materialize-identity! c))
      (when-let [c (identity-env "SECRETS_AGE_IDENTITY_B64")]
        (materialize-identity! (decode-b64-identity c)))))

(defn resolve-identity-file
  "Return the conventional identity path: `identity-from-env` first, then
  `~/.config/<app>/key.txt` when `app-or-opts` supplies an app name. Does not
  check whether the file exists. Returns nil when neither source is available."
  ([] (resolve-identity-file nil))
  ([app-or-opts]
   (let [app (if (map? app-or-opts) (:app app-or-opts) app-or-opts)]
     (or (identity-from-env)
         (when app (expand-home (str "~/.config/" app "/key.txt")))))))

(defn identity-available?
  "True when the resolved identity file exists. `app-or-opts` accepts an app
  name or an options map with `:app` or `:identity-file`; an explicit
  `:identity-file` takes priority."
  ([] (identity-available? nil))
  ([app-or-opts]
   (let [identity (if (map? app-or-opts)
                    (or (:identity-file app-or-opts)
                        (resolve-identity-file app-or-opts))
                    (resolve-identity-file app-or-opts))]
     (boolean (and identity (.exists (io/file (str identity))))))))

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

(def ^:private no-store-hint
  "One-line remediation appended to \"no secrets file\" errors."
  "Create it with `bb secrets new`.")

(defn load-secrets
  "Decrypt an age-encrypted EDN source and return its value.

  `source` may be a path string, File, URL, classpath resource URL, or another
  value accepted by `clojure.java.io/input-stream`. `identity-or-opts` is an
  identity path or an options map:
    :identity-file  explicit identity path (wins over :app and the env vars)
    :app            app name for the default ~/.config/<app>/key.txt
  Without an explicit identity or app, only the SECRETS_AGE_IDENTITY*
  environment variables are used.

  Missing inputs throw ex-info with a :reason:
    :no-identity  no identity resolves, or the resolved file does not exist.
    :no-file      `source` is nil (almost always because
                  `(io/resource \"secrets.edn.age\")` found nothing on the
                  classpath), a path/File is absent, or reading the source
                  raises an IOException.
  Identity validation happens before source validation. The plaintext is read
  with `clojure.edn`, not `eval`."
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
                       {:identity (some-> identity str) :source (str source) :reason :no-identity})))
     (when (nil? source)
       (throw (ex-info (str "No secrets source given: source is nil. This almost always means"
                            " (io/resource \"secrets.edn.age\") found nothing on the classpath"
                            " — check the encrypted file is present as a classpath resource. "
                            no-store-hint)
                       {:source nil :reason :no-file})))
     ;; Opening is what decides whether a source is readable: a String may name
     ;; a path *or* a URL (io/input-stream tries the URL first), so a
     ;; missing-path check up front would reject `jar:file:…!/secrets.edn.age`
     ;; as a nonexistent file. Let source->file try, and pick the message from
     ;; what the source turned out to be.
     (let [[file cleanup!]
           (try
             (source->file source)
             (catch java.io.IOException e
               (throw (ex-info (if (and (or (instance? java.io.File source) (string? source))
                                        (not (.exists (io/file (str source)))))
                                 (str "Secrets file not found: " source ". " no-store-hint)
                                 (str "Could not read secrets source " (pr-str source)
                                      ": " (.getMessage e)))
                               {:source source :reason :no-file}
                               e))))]
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

  The source is resolved and decrypted at most once, when the first tag is
  read. Configs with no secret tags do not access the source or identity.

  Semantics, mirroring required/optional env reads:
    #secret/req k → required: throws when no secrets file is found, when no
                    identity (key) is available, or when the key is missing
                    from the decrypted map.
    #secret/opt k → optional: nil in all three of those cases.
  If the identity exists but decryption fails, both tags throw."
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
