(ns com.kirahowe.secrets
  "Runtime loading of age-encrypted EDN secrets.

  Secrets live in a single version-controlled, age-encrypted EDN file
  (`secrets.edn.age`). At runtime they are decrypted once with your age
  identity (private key) and read into a plain Clojure map. The plaintext is
  never written to disk and never committed.

  A successful decryption proves the ciphertext was readable with your
  identity, not who wrote it: age encrypts to recipients and does not sign. The
  loaded map is therefore only as trustworthy as the commit and deployment
  channel that delivered the ciphertext. See `doc/threat-model.md` in the
  repository.

  Two ways to consume secrets:

  • As an Integrant/component value — call `load-secrets` to get the map and
    `get-secret` to read keys from it. (See the README for a two-line init-key.)

  • As EDN reader literals — call `reader-literals` (or `merge-readers`) to get
    `#secret/req` / `#secret/opt` tags you can register with your config
    reader, so config files reference secrets inline:

        :jdbc-url #secret/req :database/url  ; required — throws if absent
        :api-key  #secret/opt :llm/api-key   ; optional — nil if absent

  An explicit identity path takes precedence. Otherwise resolution uses:
    1. $SECRETS_AGE_IDENTITY_FILE — a path to the key file.
    2. $SECRETS_AGE_IDENTITY      — the raw key file *contents*, used verbatim and
       materialized to a 0600 temp file. Lets a deploy inject the key as one
       secret/env var.
    3. $SECRETS_AGE_IDENTITY_B64  — canonical base64-encoded key file contents.
       ASCII space, horizontal tab, carriage return, and line feed are permitted
       for wrapping; every other nonalphabet character or malformed encoding throws.
    4. ~/.config/<app>/key.txt — the local developer default, used only when an
       app name is known (an `:app` option or app argument).
  When none of these yields an identity, resolution returns nil and loading
  throws with the options above rather than guessing a path.

  An identity path is a local filesystem path. A URI-shaped value, which
  includes a bare relative name with a colon such as `key:txt`, fails with
  `:disallowed-identity` and the error names only its scheme; write
  `./key:txt` for such a file. Key contents in a path setting fail the same
  way and are never echoed.

  Sources 2 and 3 are materialized into a private temporary file only while an
  operation needs them, then deleted before that operation returns."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.fs :as fs]
            [com.kirahowe.secrets.safe-edn :as safe-edn]
            [com.kirahowe.secrets.source :as source]))

(def ^:private not-found ::not-found)

(defn- user-home
  "Return the current user's home directory."
  []
  (System/getProperty "user.home"))

(defn expand-home
  "Return `path` as a string, with the user's home directory in place of the
  `~` when it is exactly `~` or begins with `~/`. Every other string, such as
  `~bob/x`, is returned unchanged."
  [path]
  (let [s (str path)]
    (if (or (= s "~") (str/starts-with? s "~/"))
      (str (user-home) (subs s 1))
      s)))

(defn default-key-file
  "Return the default identity path for `app`: `~/.config/<app>/key.txt` with
  the home directory expanded."
  [app]
  (expand-home (str "~/.config/" app "/key.txt")))

;;;; Identity resolution

(def ^:private identity-b64-whitespace-re
  "ASCII whitespace permitted in base64 identity transport: space, horizontal
  tab, carriage return, and line feed."
  #"[ \t\r\n]")

(defn- invalid-b64-identity
  "Return the content-free error for invalid base64 identity input."
  []
  (ex-info (str "SECRETS_AGE_IDENTITY_B64 is not valid base64. Set it to the"
                " base64-encoded age key file contents, or use"
                " SECRETS_AGE_IDENTITY (raw contents) / SECRETS_AGE_IDENTITY_FILE"
                " (a path) instead.")
           {:env "SECRETS_AGE_IDENTITY_B64"}))

(defn- decode-b64-identity
  "Decode canonical base64 identity contents to raw identity text.

  ASCII space, horizontal tab, carriage return, and line feed are removed for
  environment transport. Every other nonalphabet character, noncanonical
  encoding, malformed length, or padding error throws without retaining the
  input or a decoder cause."
  [contents]
  (let [normalized (str/replace contents identity-b64-whitespace-re "")
        decoded (try
                  (.decode (java.util.Base64/getDecoder) normalized)
                  (catch IllegalArgumentException _
                    (throw (invalid-b64-identity))))]
    (when-not (= normalized
                 (.encodeToString (java.util.Base64/getEncoder) decoded))
      (throw (invalid-b64-identity)))
    (String. decoded "UTF-8")))

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

(defn- getenv
  "Read environment variable `k`. This is the only raw environment read in the
  namespace, and the seam tests redefine."
  [k]
  (System/getenv k))

(defn- identity-env
  "`identity-env-value` applied to the live environment."
  [k]
  (identity-env-value k (getenv k)))

(defn- identity-candidate
  "Choose an identity without materializing injected contents.

  The callback scope owns raw and base64 identities. This function only selects
  a source, which keeps option normalization and availability checks free of
  private filesystem effects."
  [identity-or-opts]
  (let [opts (if (map? identity-or-opts) identity-or-opts {})
        explicit (if (map? identity-or-opts) (:identity-file opts) identity-or-opts)]
    (or (when explicit
          {:identity-file explicit :identity-source :identity-file})
        (when-let [path (identity-env "SECRETS_AGE_IDENTITY_FILE")]
          {:identity-file path :identity-source :secrets-age-identity-file})
        (when-let [contents (identity-env "SECRETS_AGE_IDENTITY")]
          {:contents contents :identity-source :secrets-age-identity})
        (when-let [contents (identity-env "SECRETS_AGE_IDENTITY_B64")]
          {:contents (decode-b64-identity contents)
           :identity-source :secrets-age-identity-b64})
        (when-let [path (:key-file opts)]
          {:identity-file path
           :identity-source (case (:key-file-source opts)
                              :default :default-key-file
                              :configured :configured-key-file
                              :configured-key-file)})
        (when-let [app (:app opts)]
          {:identity-file (default-key-file app)
           :identity-source :default-key-file})
        {:identity-file nil :identity-source nil})))

(defn- try-delete-identity-file!
  "Attempt to delete `file`. Kept as the narrow filesystem seam for tests."
  [file]
  (.delete file))

(defn- cleanup-failure
  [path source]
  (ex-info "Could not delete the temporary age identity file."
           {:reason :identity-cleanup-failed
            :identity-file path
            :identity-source source}))

(defn- delete-materialized-identity!
  "Delete a temporary identity, returning nil or a safe cleanup exception.
  A delete that throws is reported the same way and never propagates."
  [path source]
  (let [file (io/file path)]
    (try
      (cond
        (not (.exists file)) nil
        (try-delete-identity-file! file) nil
        (not (.exists file)) nil
        :else (cleanup-failure path source))
      (catch Exception _
        (cleanup-failure path source)))))

(defn- write-identity!
  "Materialize injected contents in a private temp file for one operation.

  A failed write attempts to delete the file before anything propagates. An
  `Exception` is reported as `:identity-not-materialized` without its cause or
  message, with a failed delete under `:cleanup`. An `Error` is rethrown as it
  is, with a failed delete attached as a suppressed `:identity-cleanup-failed`
  error. Either way a file that could not be deleted is named."
  [contents source]
  (let [file (fs/owner-only-temp-file! "age-identity-" ".txt")
        path (.getAbsolutePath file)]
    (try
      (spit file contents)
      path
      (catch Throwable t
        (let [cleanup (delete-materialized-identity! path source)]
          (throw (if-not (instance? Exception t)
                   (cond-> t cleanup (doto (.addSuppressed cleanup)))
                   (ex-info (str "Could not write the injected age identity to a temp file ("
                                 (.getName (class t)) "). Check the temp directory is writable.")
                            (cond-> {:reason :identity-not-materialized
                                     :identity-file path
                                     :identity-source source}
                              cleanup (assoc :cleanup (ex-data cleanup)))))))))))

(def ^:private colon-path-hint
  " Prefix a relative path that contains a colon with ./")

(defn- validate-identity-path!
  "Throw `:disallowed-identity` when `path` cannot name a local identity file.

  A value containing `AGE-SECRET-KEY-` is key contents in a path setting, and
  its error carries only `:identity-source`. A URI-shaped value is a locator
  that can hold a credential, and its error adds only the `:scheme`. Neither
  error renders the value."
  [path identity-source]
  (when-let [s (some-> path str)]
    (let [refuse! (fn [message data]
                    (throw (ex-info message
                                    (assoc data
                                           :reason :disallowed-identity
                                           :identity-source identity-source))))]
      (when (str/includes? s "AGE-SECRET-KEY-")
        (refuse! (str "The age identity setting holds key contents where a file path was"
                      " expected. Key contents belong in SECRETS_AGE_IDENTITY.")
                 {}))
      (when-let [scheme (source/locator-scheme s)]
        (refuse! (str "The age identity must be a local filesystem path, but the value starts"
                      " with the URI scheme " scheme ":." colon-path-hint)
                 {:scheme scheme})))))

(defn with-identity
  "Call `f` with an operation-owned identity descriptor.

  `identity-or-opts` accepts an explicit path or an options map. `f` receives
  `{:identity-file path-or-nil :identity-source source}`. Resolution is an
  explicit path, then SECRETS_AGE_IDENTITY_FILE/raw/base64, then `:key-file`,
  then an `:app` default; no configured identity gives a nil path for keyless
  operations. Paths owned by callers pass through untouched, except that a
  URI-shaped path or one holding key contents throws `:disallowed-identity`
  before `f` runs. Raw and base64
  identities are materialized only for this callback and deleted when it
  returns. If both the callback and cleanup fail, an `ex-info` from the
  callback is rethrown with its message and data plus the cleanup diagnostic
  under `:cleanup`. Any other throwable becomes the cause of an
  `:identity-cleanup-failed` error that carries the same diagnostic."
  [identity-or-opts f]
  (let [{:keys [contents identity-source] :as candidate}
        (identity-candidate identity-or-opts)]
    (if (contains? candidate :contents)
      (let [path (write-identity! contents identity-source)
            descriptor {:identity-file path :identity-source identity-source}
            callback-failure (volatile! nil)]
        (try
          (f descriptor)
          (catch Throwable t
            (vreset! callback-failure t)
            (throw t))
          (finally
            (when-let [cleanup (delete-materialized-identity! path identity-source)]
              (if-let [failure @callback-failure]
                (if (instance? clojure.lang.ExceptionInfo failure)
                  (throw (ex-info (ex-message failure)
                                  (assoc (ex-data failure) :cleanup (ex-data cleanup))
                                  failure))
                  (throw (ex-info (ex-message cleanup)
                                  {:reason :identity-cleanup-failed
                                   :identity-file path
                                   :identity-source identity-source
                                   :cleanup (ex-data cleanup)}
                                  failure)))
                (throw cleanup))))))
      (do
        (validate-identity-path! (:identity-file candidate) identity-source)
        (f (select-keys candidate [:identity-file :identity-source]))))))

(defn- identity-file-exists?
  "True when `path` names an identity file that exists."
  [path]
  (boolean (and path (.exists (io/file (str path))))))

(def ^:private identity-options
  "One-line remediation appended to \"no identity\" errors."
  (str "Set SECRETS_AGE_IDENTITY_FILE (key path), SECRETS_AGE_IDENTITY (raw key contents), or "
       "SECRETS_AGE_IDENTITY_B64 (base64 contents); pass {:identity-file …} or "
       "{:app \"myapp\"} (→ ~/.config/myapp/key.txt); or create the key with "
       "`bb secrets keygen`."))

;;;; Loading

(defn- validate-load-identity!
  "Throw unless `identity` names an existing file."
  [descriptor identity]
  (let [nameable (some-> identity str)]
    (when-not (identity-file-exists? identity)
      (throw (ex-info (str "No age identity found"
                           (when nameable (str " (" nameable " does not exist)"))
                           ". " identity-options)
                      (cond-> {:reason :no-identity}
                        descriptor (assoc :source descriptor)
                        nameable (assoc :identity nameable)))))))

(defn- edn-failure-message
  [{:keys [reason depth limit] :as failure}]
  (case reason
    :edn-empty "The decrypted secrets are empty; expected exactly one EDN value."
    :edn-extra-values (str "The decrypted secrets contain more than one EDN value;"
                           " expected exactly one.")
    :edn-too-deep (str "The decrypted secrets nest " depth " collections deep, past the"
                       " limit of " limit ".")
    :edn-malformed (str "The decrypted secrets contain malformed EDN syntax"
                        (safe-edn/failure-location failure) ".")))

(def ^:private edn-failure-reasons
  #{:edn-empty :edn-extra-values :edn-too-deep :edn-malformed})

(defn- read-secrets-edn
  "Parse decrypted `plaintext` under the shared, content-free EDN policy."
  [plaintext]
  (let [{:keys [ok? value] :as parsed} (safe-edn/parse plaintext)]
    (if ok?
      value
      (throw (ex-info (edn-failure-message parsed)
                      (safe-edn/failure-data parsed))))))

(defn- decrypt-and-read!
  "Decrypt and read `file`, always running its source cleanup function.

  A failure below here knows the file `age` was handed, which for a copied
  source is a temp file the caller never named, so it is re-thrown with the
  `source` descriptor added. Content-free EDN failures drop their intermediate
  exception; other failures retain their cause."
  [identity file source cleanup!]
  (try
    (read-secrets-edn (age/decrypt identity (.getAbsolutePath ^java.io.File file)))
    (catch clojure.lang.ExceptionInfo e
      (let [data (assoc (ex-data e) :source source)]
        (throw (if (contains? edn-failure-reasons (:reason data))
                 (ex-info (ex-message e) data)
                 (ex-info (ex-message e) data e)))))
    (finally
      (cleanup!))))

(defn- load-with-identity
  "Load `source` while an identity descriptor is owned by the calling scope."
  [source {:keys [identity-file]}]
  (let [descriptor (source/descriptor source)]
    (validate-load-identity! descriptor identity-file)
    (let [[file cleanup!] (source/acquire! source descriptor)]
      (decrypt-and-read! identity-file file descriptor cleanup!))))

(defn- load-from
  "Load `source` in an operation-owned identity scope."
  [source identity-or-opts]
  (with-identity identity-or-opts
    #(load-with-identity source %)))

(defn load-secrets
  "Decrypt an age-encrypted EDN source and return its value.

  `source` is local-only: a filesystem path string, File, Path, local `file:`
  URL/URI/string, or a `jar:file:` classpath resource URL/URI/string.
  HTTP(S), every other scheme, remote or nested jar sources, malformed local
  locators, and arbitrary values accepted by `clojure.java.io/input-stream` are
  rejected with `:disallowed-source` before DNS, connection, redirect, or
  response reads. This API performs no remote operation, so it has no network
  timeout contract. `identity-or-opts` is an identity path or an options map:
    :identity-file  explicit identity path (wins over :app and the env vars)
    :app            app name for the default ~/.config/<app>/key.txt
  Without an explicit identity or app, only the SECRETS_AGE_IDENTITY*
  environment variables are used.

  Missing or invalid inputs throw ex-info with a :reason:
    :no-identity        no identity resolves, or the resolved file does not exist.
    :disallowed-identity  the identity path is URI-shaped or holds key
                        contents, so it is not a local path.
    :no-file            `source` is nil, an allowed local file is absent, or an
                        allowed local source cannot be read.
    :disallowed-source  `source` is outside the local-only provenance contract.
  Fixed bounds catch an accidental huge or deeply nested input: a source past
  16 MiB throws `:source-too-large`, plaintext past 8 MiB throws
  `:plaintext-too-large`, and EDN nested past 100 collections throws
  `:edn-too-deep`. Each carries the numeric `:limit`. The identity is resolved
  first, then source policy and opening. The plaintext is read with
  `clojure.edn`, not `eval`.

  Every failure about a source carries `:source`, allowlisted metadata naming
  which source failed — a locator's scheme, host, port, and path, a file's path,
  or a rejected object's class — and never the source value, whose userinfo,
  query, or `toString` can be a credential. Injected identities are kept in a
  private temporary file only for the duration of this operation."
  ([source] (load-secrets source nil))
  ([source identity-or-opts]
   (load-from source identity-or-opts)))

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
  "Load one readers map's source in an operation-owned identity scope, or
  describe why it is unavailable."
  [{:keys [resource file] :as opts}]
  (let [source (cond
                 file (when (.exists (io/file (str file)))
                        (io/file (str file)))
                 resource (io/resource resource))]
    (cond
      (nil? source)
      {:present? false :reason :no-file}

      :else
      (with-identity opts
        (fn [{:keys [identity-file] :as identity}]
          (if-not (identity-file-exists? identity-file)
            {:present? false :reason :no-identity}
            {:present? true :secrets (load-with-identity source identity)}))))))

(defn- validate-reader-source!
  "Throw `:disallowed-source` when the readers' `:file` or `:resource` is
  URI-shaped. `:source` is its descriptor, which drops userinfo, query, and
  fragment, and the message names only the scheme."
  [{:keys [file resource]}]
  (doseq [[option value expected hint]
          [[:file file "a local filesystem path" colon-path-hint]
           [:resource resource "a classpath resource name" ""]]]
    (when-let [scheme (some-> value str source/locator-scheme)]
      (throw (ex-info (str "The secrets " option " must be " expected ", but the value starts"
                           " with the URI scheme " scheme ":." hint)
                      {:reason :disallowed-source
                       :source (source/descriptor (str value))})))))

(defn- required-secret-handler
  "Build the required-secret reader around a shared delayed loaded state.

  A failure names the configured store under `:store`, never `:source`: a load
  failure surfacing through this same reader carries `:source`, the allowlisted
  descriptor of the source that failed, and one key must not mean two shapes."
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
                        {:key key-path :store describe :reason reason})))
      (let [value (get-secret secrets key-path not-found)]
        (when (= value not-found)
          (throw (ex-info (str "Required secret " (pr-str key-path)
                               " is missing from the secrets file.")
                          {:key key-path :store describe :reason :missing-key})))
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
    :file          an explicit local file path, used instead of :resource.
                   A URI-shaped :file or :resource throws `:disallowed-source`
                   here, with the same credential-free `:source` descriptor a
                   load failure carries.
    :app           app name for the default key path ~/.config/<app>/key.txt.
    :identity-file explicit identity path (overrides resolution).

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
  [opts]
  (let [loaded (delay (reader-loaded-state opts))
        _ (validate-reader-source! opts)
        describe (or (:file opts) (:resource opts) "secrets")]
    {'secret/req (required-secret-handler loaded describe)
     'secret/opt (optional-secret-handler loaded)}))

(defn merge-readers
  "Merge `reader-literals` into an existing `:readers` map. The returned map
  owns a fresh lazy load/cache; call `merge-readers` again after editing or
  repairing ciphertext."
  [readers opts]
  (merge readers (reader-literals opts)))
