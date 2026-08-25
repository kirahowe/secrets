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

(defn- user-home
  "Return the current user's home directory."
  []
  (System/getProperty "user.home"))

(defn expand-home
  "Expand a leading ~ to the user's home directory."
  [path]
  (let [s (str path)]
    (if (str/starts-with? s "~")
      (str (user-home) (subs s 1))
      s)))

;;;; Owner-only temp files

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

;;;; Identity resolution

(def ^:private identity-temp
  "Caches delayed identity temp-file paths by a SHA-256 digest of their contents."
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

(defn- identity-digest
  "Return a stable SHA-256 cache key without retaining the raw identity contents."
  [contents]
  (let [bytes (.digest (java.security.MessageDigest/getInstance "SHA-256")
                       (.getBytes (str contents) "UTF-8"))]
    (.encodeToString (java.util.Base64/getEncoder) bytes)))

(defn- write-identity!
  "Write identity contents verbatim to an owner-only temp file and return its path."
  [contents]
  (let [file (owner-only-temp-file! "age-identity-" ".txt")]
    (spit file contents)
    (.getAbsolutePath file)))

(defn- materialize-identity!
  "Materialize identity `contents` once per process and return its temp-file path.

  The cache retains only a digest and, after materialization, the resulting path.
  Installing a delay atomically ensures concurrent callers for identical contents
  share one file write."
  [contents]
  (let [digest (identity-digest contents)
        candidate (delay (write-identity! contents))
        cache (swap! identity-temp
                     #(if (contains? % digest)
                        %
                        (assoc % digest candidate)))
        entry (get cache digest)]
    (if-not (delay? entry)
      entry
      (try
        (let [path @entry]
          (swap! identity-temp
                 #(if (identical? entry (get % digest))
                    (assoc % digest path)
                    %))
          path)
        (catch Exception error
          (swap! identity-temp
                 #(if (identical? entry (get % digest))
                    (dissoc % digest)
                    %))
          (throw error))))))

(def ^:private identity-env-help
  "What each identity variable should contain, for the set-but-empty error."
  {"SECRETS_AGE_IDENTITY_FILE" "a path to the age key file"
   "SECRETS_AGE_IDENTITY" "the age key file contents"
   "SECRETS_AGE_IDENTITY_B64" "the base64-encoded age key file contents"})

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

;;;; Resource limits

(def default-limits
  "Bounds applied while a secrets source is streamed, decrypted, and parsed.

  They exist so a hostile or accidentally enormous source fails fast rather than
  exhausting the process (CWE-400), and each is checked *during* the work rather
  than after it:

    :max-source-bytes     ciphertext bytes read from a URL, InputStream, or
                          file, counted while copying (16 MiB).
    :max-plaintext-bytes  plaintext bytes `age` may produce before the
                          subprocess is killed (8 MiB).
    :max-edn-depth        collection nesting depth the decrypted EDN may reach,
                          checked before it is parsed (100).

  Pass `{:limits {…}}` to `load-secrets`, `reader-literals`, or `merge-readers`
  to override any of them; the supplied map is merged over these defaults. The
  defaults sit far above every documented example — a real store is kilobytes."
  {:max-source-bytes 16777216
   :max-plaintext-bytes age/default-max-plaintext-bytes
   :max-edn-depth 100})

(defn- resolve-limits
  "Merge a supplied `:limits` map over `default-limits`. Rejects anything a
  later read would silently see as a default: a non-map, an unknown key (a typo
  in a security limit must not read as \"unset\"), or a value that is not a
  positive integer."
  [limits]
  (when-not (or (nil? limits) (map? limits))
    (throw (ex-info "secrets :limits must be a map of limit name → positive integer."
                    {:limits limits :reason :invalid-limits})))
  (let [unknown (vec (sort-by str (remove (set (keys default-limits)) (keys limits))))]
    (when (seq unknown)
      (throw (ex-info (str "secrets :limits has unknown key(s): "
                           (str/join ", " unknown) ". Known limits: "
                           (str/join ", " (sort (keys default-limits))) ".")
                      {:limits limits :unknown-keys unknown :reason :invalid-limits}))))
  (doseq [[limit value] limits]
    (when-not (and (integer? value) (pos? value))
      (throw (ex-info (str "secrets :limits " limit " must be a positive integer, got "
                           (pr-str value) ".")
                      {:limits limits :limit limit :value value :reason :invalid-limits}))))
  (merge default-limits limits))

;;;; Loading

(def ^:private source-chunk-bytes
  "Sources are copied in fixed 64 KiB chunks so the running total is checked
  before every further read rather than after the source is exhausted."
  65536)

(defn- source-too-large!
  "Throw the source size failure, naming only the byte count and the limit —
  never any source content."
  [source read-bytes limit]
  (throw (ex-info (str "The secrets source is larger than the configured :max-source-bytes"
                       " limit of " limit " bytes.")
                  {:source (str source)
                   :bytes read-bytes
                   :limit limit
                   :reason :source-too-large})))

(defn- copy-source!
  "Copy `in` to `out` in fixed chunks, refusing to write more than `limit`
  bytes.

  A chunk that would push the total past `limit` is never written, so nothing
  beyond the bound reaches the filesystem and an endless stream is abandoned at
  the bound instead of being read to an end it does not have. Counting while
  copying is what makes a declared length irrelevant: a `Content-Length` that
  lies in either direction, or no length at all, changes nothing here."
  [source ^java.io.InputStream in ^java.io.OutputStream out limit]
  (let [chunk (byte-array source-chunk-bytes)]
    (loop [total 0]
      (let [n (.read in chunk 0 source-chunk-bytes)]
        (when-not (neg? n)
          (let [total (+ total n)]
            (when (> total limit)
              (source-too-large! source total limit))
            (.write out chunk 0 n)
            (recur total)))))))

(defn- source->file
  "Coerce a secrets `source` to a [file cleanup!] pair, refusing a source larger
  than `limit` bytes. Path strings and Files naming an existing file are used in
  place (no cleanup), so their length is checked directly. Anything else that
  `io/input-stream` can open — any URL (including a jar: resource URL from
  inside an uberjar), an InputStream, … — is copied to a 0600 temp file so
  `age` can read it, counting bytes as it goes and deleting the partial copy at
  once if the bound is passed; cleanup deletes that copy."
  [source limit]
  (let [f (when (or (instance? java.io.File source) (string? source))
            (io/file source))]
    (if (and f (.exists f))
      (do
        (when (> (.length f) limit)
          (source-too-large! source (.length f) limit))
        [f (fn [])])
      (let [tmp (owner-only-temp-file! "secrets-" ".age")]
        (try
          (with-open [in (io/input-stream source)
                      out (io/output-stream tmp)]
            (copy-source! source in out limit))
          (catch Exception e
            (.delete tmp)
            (throw e)))
        [tmp #(.delete tmp)]))))

(def ^:private no-store-hint
  "One-line remediation appended to \"no secrets file\" errors."
  "Create it with `bb secrets new`.")

(defn- validate-load-identity!
  "Resolve and validate the identity for `load-secrets`, returning its path."
  [source identity-or-opts]
  (let [identity (if (map? identity-or-opts)
                   (or (:identity-file identity-or-opts)
                       (resolve-identity-file identity-or-opts))
                   (or identity-or-opts (resolve-identity-file)))]
    (when-not (and identity (.exists (io/file (str identity))))
      (throw (ex-info (str "No age identity found"
                           (when identity (str " (" identity " does not exist)"))
                           ". " identity-options)
                      {:identity (some-> identity str)
                       :source (str source)
                       :reason :no-identity})))
    identity))

(defn- acquire-source!
  "Acquire a file and cleanup function for `source` under `limits`, translating
  read failures."
  [source limits]
  (when (nil? source)
    (throw (ex-info (str "No secrets source given: source is nil. This almost always means"
                         " (io/resource \"secrets.edn.age\") found nothing on the classpath"
                         " — check the encrypted file is present as a classpath resource. "
                         no-store-hint)
                    {:source nil :reason :no-file})))
  ;; Opening decides whether a source is readable. A String may name a path or
  ;; a URL, so checking for a missing path first would reject jar:file: URLs.
  (try
    (source->file source (:max-source-bytes limits))
    (catch java.io.IOException e
      (throw (ex-info (if (and (or (instance? java.io.File source) (string? source))
                               (not (.exists (io/file (str source)))))
                        (str "Secrets file not found: " source ". " no-store-hint)
                        (str "Could not read secrets source " (pr-str source)
                             ": " (.getMessage e)))
                      {:source source :reason :no-file}
                      e)))))

(defn- skip-string
  "Return the index just past the EDN string literal whose opening quote sits at
  `i` - 1, so a `\\` escape cannot hide the closing quote."
  [^String s i]
  (let [n (.length s)]
    (loop [i i]
      (cond
        (>= i n) n
        (= \\ (.charAt s i)) (recur (+ i 2))
        (= \" (.charAt s i)) (inc i)
        :else (recur (inc i))))))

(defn- skip-comment
  "Return the index of the newline ending the `;` comment that starts at `i`, or
  the end of `s`."
  [^String s i]
  (let [n (.length s)]
    (loop [i i]
      (if (or (>= i n) (= \newline (.charAt s i)))
        i
        (recur (inc i))))))

(defn- edn-max-depth
  "Return the deepest collection nesting the EDN text `s` reaches, scanning it
  once without parsing it.

  Only delimiters that are structure count: string literals (including their
  `\\` escapes), character literals such as `\\[`, and `;` comments are skipped,
  so a delimiter inside any of them is text rather than depth. `#{` needs no
  special case — its `{` is the opener. Surplus closing delimiters clamp at
  zero: balance is `clojure.edn`'s job, not this scanner's."
  [^String s]
  (let [n (.length s)]
    (loop [i 0 depth 0 deepest 0]
      (if (>= i n)
        deepest
        (case (.charAt s i)
          \" (recur (skip-string s (inc i)) depth deepest)
          \\ (recur (+ i 2) depth deepest)
          \; (recur (skip-comment s (inc i)) depth deepest)
          (\( \[ \{) (recur (inc i) (inc depth) (max deepest (inc depth)))
          (\) \] \}) (recur (inc i) (max 0 (dec depth)) deepest)
          (recur (inc i) depth deepest))))))

(defn- read-secrets-edn
  "Parse decrypted `plaintext` as EDN under `limits`.

  The whole parse policy is two bounds and one deliberate absence. EDN has no
  aliasing, reference, or expansion mechanism, so a parsed graph's size is
  linear in its plaintext's byte count: `:max-plaintext-bytes`, enforced while
  `age` is still writing, already bounds the graph. What a byte bound does not
  bound is parser *recursion*: a few hundred kilobytes of `[[[[…` overflows the
  stack, and `StackOverflowError` is an `Error` no caller should be relying on a
  `catch` for, so `:max-edn-depth` is checked by one linear scan
  ([[edn-max-depth]]) before the parser sees the text. And `clojure.edn` with no
  custom readers evaluates nothing at all — unlike `read`, it cannot construct
  arbitrary classes or run code, so no input, of any size, buys execution."
  [plaintext limits]
  (let [limit (:max-edn-depth limits)
        depth (edn-max-depth plaintext)]
    (when (> depth limit)
      (throw (ex-info (str "The decrypted secrets nest " depth " collections deep, past the"
                           " configured :max-edn-depth limit of " limit ".")
                      {:depth depth :limit limit :reason :edn-too-deep})))
    (edn/read-string plaintext)))

(defn- decrypt-and-read!
  "Decrypt and read `file` under `limits`, always running its source cleanup
  function."
  [identity file limits cleanup!]
  (try
    (read-secrets-edn (age/decrypt identity (.getAbsolutePath ^java.io.File file)
                                   {:limits limits})
                      limits)
    (finally
      (cleanup!))))

(defn load-secrets
  "Decrypt an age-encrypted EDN source and return its value.

  `source` may be a path string, File, URL, classpath resource URL, or another
  value accepted by `clojure.java.io/input-stream`. `identity-or-opts` is an
  identity path or an options map:
    :identity-file  explicit identity path (wins over :app and the env vars)
    :app            app name for the default ~/.config/<app>/key.txt
    :limits         resource bounds merged over `default-limits`
  Without an explicit identity or app, only the SECRETS_AGE_IDENTITY*
  environment variables are used.

  Missing inputs throw ex-info with a :reason:
    :no-identity  no identity resolves, or the resolved file does not exist.
    :no-file      `source` is nil (almost always because
                  `(io/resource \"secrets.edn.age\")` found nothing on the
                  classpath), a path/File is absent, or reading the source
                  raises an IOException.
  An input past one of the `:limits` throws with `:source-too-large`,
  `:plaintext-too-large`, or `:edn-too-deep`, and `:invalid-limits` rejects a
  `:limits` map that is malformed rather than reading it as the defaults.
  Limits are resolved first, then the identity, then the source. The plaintext
  is read with `clojure.edn`, not `eval`."
  ([source] (load-secrets source nil))
  ([source identity-or-opts]
   (let [limits (resolve-limits (when (map? identity-or-opts) (:limits identity-or-opts)))
         identity (validate-load-identity! source identity-or-opts)
         [file cleanup!] (acquire-source! source limits)]
     (decrypt-and-read! identity file limits cleanup!))))

(defn get-secret
  "Read a secret from a loaded map. `key-path` is a single key (`:database/url`)
  or a vector path into nested maps (`[:database :url]`). Returns `default`
  (nil) when absent."
  ([secrets key-path] (get-secret secrets key-path nil))
  ([secrets key-path default]
   (if (vector? key-path)
     (get-in secrets key-path default)
     (get secrets key-path default))))

;;;; EDN reader literals

(defn- reader-loaded-state
  "Resolve and load one readers map's source under its resolved `:limits`, or
  describe why it is unavailable."
  [{:keys [resource file limits]} identity]
  (let [source (cond
                 file (when (.exists (io/file (str file)))
                        (io/file (str file)))
                 resource (io/resource resource))]
    (cond
      (nil? source)
      {:present? false :reason :no-file}

      (not (and @identity (.exists (io/file (str @identity)))))
      {:present? false :reason :no-identity}

      :else
      {:present? true
       :secrets (load-secrets source {:identity-file @identity :limits limits})})))

(defn- required-secret-handler
  "Build the required-secret reader around a shared delayed loaded state."
  [loaded describe]
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
      (let [value (get-secret secrets key-path not-found)]
        (when (= value not-found)
          (throw (ex-info (str "Required secret " (pr-str key-path)
                               " is missing from the secrets file.")
                          {:key key-path :source describe :reason :missing-key})))
        value))))

(defn- optional-secret-handler
  "Build the optional-secret reader around a shared delayed loaded state."
  [loaded]
  (fn [key-path]
    (let [{:keys [present? secrets]} @loaded]
      (when present?
        (get-secret secrets key-path)))))

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
    :limits        resource bounds merged over `default-limits`, validated here
                   rather than at the first tag read.

  The source is resolved and decrypted at most once, when the first tag is
  read. That first successful load or decryption failure is cached for the
  lifetime of the returned readers map; recreate it after editing or repairing
  ciphertext. Configs with no secret tags do not access the source or identity.

  Semantics, mirroring required/optional env reads:
    #secret/req k → required: throws when no secrets file is found, when no
                    identity (key) is available, or when the key is missing
                    from the decrypted map.
    #secret/opt k → optional: nil in all three of those cases.
  If the identity exists but decryption fails, both tags throw."
  [{:keys [app identity-file] :as opts}]
  (let [limits (resolve-limits (:limits opts))
        identity (delay (or identity-file (resolve-identity-file app)))
        loaded (delay (reader-loaded-state (assoc opts :limits limits) identity))
        describe (or (:file opts) (:resource opts) "secrets")]
    {'secret/req (required-secret-handler loaded describe)
     'secret/opt (optional-secret-handler loaded)}))

(defn merge-readers
  "Merge `reader-literals` into an existing `:readers` map. The returned map
  owns a fresh lazy load/cache; call `merge-readers` again after editing or
  repairing ciphertext."
  [readers opts]
  (merge readers (reader-literals opts)))
