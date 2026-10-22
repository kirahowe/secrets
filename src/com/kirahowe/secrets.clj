(ns com.kirahowe.secrets
  "Runtime loading of age-encrypted EDN secrets.

  Secrets live in one version-controlled, age-encrypted EDN file
  (`secrets.edn.age`). At runtime they are decrypted with your age identity
  (private key) and read into a plain Clojure map. The plaintext is never
  written to disk.

  Decryption shows the ciphertext was readable with your identity, not who
  wrote it: age does not sign. The loaded map is only as trustworthy as the
  channel that delivered the ciphertext. See `doc/threat-model.md`.

  Two ways to consume secrets:

  - As a value: `load-secrets` returns the map and `get-secret` reads keys
    from it. (See the README for a two-line Integrant init-key.)
  - As EDN reader literals: `reader-literals` (or `merge-readers`) returns
    the `#secret/req` / `#secret/opt` tags to register with your config
    reader:

        :jdbc-url #secret/req :database/url  ; required: throws if absent
        :api-key  #secret/opt :llm/api-key   ; optional: nil if absent

  ## Identity resolution

  An explicit identity path takes precedence. Otherwise the first of these
  that applies wins:
    1. $SECRETS_AGE_IDENTITY_FILE, a path to the key file.
    2. $SECRETS_AGE_IDENTITY, the raw key file contents, used verbatim, so a
       deploy can inject the key as one env var.
    3. $SECRETS_AGE_IDENTITY_B64, canonical base64 of the key file contents.
       Space, tab, CR, and LF may wrap it; any other nonalphabet character or
       malformed encoding throws.
    4. The project's own key: the output of a `:key-command` (such as a
       password manager's read command), else a `:key-file`, else on macOS
       the login Keychain item for the `:app` option.
  When none yields an identity, loading throws and lists these options. There
  is no default key file.

  A key that is not in a file (sources 2 and 3, a `:key-command`, the
  Keychain) is held in memory and handed to `age` on its standard input. It
  is never written to disk.

  ## Identity paths

  A path is a local filesystem path with a leading `~` expanded. A URI-shaped
  value, including a bare name with a colon such as `key:txt` (write
  `./key:txt`), fails with `:disallowed-identity`, naming its source and
  scheme. Key contents in a path setting, raw or base64, fail the same way
  and are never echoed.

  A path you designate must exist: an explicit path, `:identity-file`, or
  $SECRETS_AGE_IDENTITY_FILE naming a missing file fails with `:no-identity`,
  naming the source and path. A `:key-file` or Keychain item may be absent,
  and then no identity is available."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.fs :as fs]
            [com.kirahowe.secrets.identity :as identity]
            [com.kirahowe.secrets.manifest :as manifest]
            [com.kirahowe.secrets.safe-edn :as safe-edn]
            [com.kirahowe.secrets.source :as source]))

(def ^:private not-found ::not-found)

;;;; Identity resolution

(def ^:private identity-b64-whitespace-re
  "Whitespace allowed in base64 identity transport."
  #"[ \t\r\n]")

(defn- invalid-b64-identity
  "The content-free error for invalid base64 identity input."
  []
  (ex-info (str "SECRETS_AGE_IDENTITY_B64 is not valid base64. Set it to the"
                " base64-encoded age key file contents, or use"
                " SECRETS_AGE_IDENTITY (raw contents) / SECRETS_AGE_IDENTITY_FILE"
                " (a path) instead.")
           {:reason :invalid-identity :env "SECRETS_AGE_IDENTITY_B64"}))

(defn- decode-b64-identity
  "Decode canonical base64 identity contents to raw identity text. Anything
  but canonical base64 (after stripping wrapping whitespace) throws without
  retaining the input or a decoder cause."
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
  "What each identity variable holds, for the set-but-empty error."
  {"SECRETS_AGE_IDENTITY_FILE" "a path to the age key file"
   "SECRETS_AGE_IDENTITY" "the age key file contents"
   "SECRETS_AGE_IDENTITY_B64" "the base64-encoded age key file contents"})

(defn- identity-env-value
  "Return `v`, the value of identity variable `k`, or nil when it is unset.
  A value that is set but blank throws `:invalid-identity`: CI expands a
  missing secret to the empty string, and falling through to the next source
  would use a developer's local key while the deployment stays broken."
  [k v]
  (when (and v (str/blank? v))
    (throw (ex-info (str k " is set but empty. Unset it to fall back to the next"
                         " identity source, or set it to " (identity-env-help k) ".")
                    {:reason :invalid-identity :env k})))
  v)

(defn- getenv
  "The only raw environment read here, and the seam tests redefine."
  [k]
  (System/getenv k))

(defn- identity-env
  "`identity-env-value` applied to the live environment."
  [k]
  (identity-env-value k (getenv k)))

(def ^:private identity-source-subject
  "How an error names where an identity path came from."
  {:identity-file "The explicit identity path"
   :secrets-age-identity-file "SECRETS_AGE_IDENTITY_FILE"
   :configured-key-file "The configured :key-file"})

(defn- identity-candidate
  "Choose an identity. An explicit path and SECRETS_AGE_IDENTITY_FILE are
  `:designated?`, so the file must exist. The rest comes from
  [[identity/key-identity]]."
  [identity-or-opts]
  (let [opts (if (map? identity-or-opts) identity-or-opts {})
        explicit (if (map? identity-or-opts) (:identity-file opts) identity-or-opts)
        designated (fn [path source]
                     {:identity-file (fs/expand-home path)
                      :identity-source source
                      :designated? true})]
    (or (when explicit
          (designated explicit :identity-file))
        (when-let [path (identity-env "SECRETS_AGE_IDENTITY_FILE")]
          (designated path :secrets-age-identity-file))
        (when-let [contents (identity-env "SECRETS_AGE_IDENTITY")]
          {:identity-contents contents :identity-source :secrets-age-identity})
        (when-let [contents (identity-env "SECRETS_AGE_IDENTITY_B64")]
          {:identity-contents (decode-b64-identity contents)
           :identity-source :secrets-age-identity-b64})
        (identity/key-identity opts))))

(defn- validate-identity-path!
  "Throw `:disallowed-identity` when `path` holds key contents or is
  URI-shaped. The error names the source and, for a URI, its `:scheme`, never
  the value."
  [path identity-source]
  (when-let [problem (some-> path str source/path-problem)]
    (throw (ex-info (source/path-problem-message (identity-source-subject identity-source)
                                                 "a local filesystem path"
                                                 problem)
                    (cond-> {:reason :disallowed-identity
                             :identity-source identity-source}
                      (:scheme problem) (assoc :scheme (:scheme problem)))))))

(defn identity-available?
  "True when `identity`, a resolved identity, holds a key in memory or names
  an identity file that exists."
  [{:keys [identity-file identity-contents]}]
  (boolean (or identity-contents
               (and identity-file (.exists (io/file (str identity-file)))))))

(defn resolve-identity
  "Resolve `identity-or-opts`, an explicit path or an options map, to the
  identity an operation decrypts with. The first source that applies wins:
  `:identity-file`, SECRETS_AGE_IDENTITY_FILE, SECRETS_AGE_IDENTITY,
  SECRETS_AGE_IDENTITY_B64, then `:key-command`, `:key-file`, and on macOS
  the Keychain item for `:app`. The namespace docstring has the details.

  Returns `{:identity-file path :identity-source source}` for a key file, or
  `{:identity-contents key :identity-source source}` for a key held in memory.

  Throws `:disallowed-identity` for a bad path and `:no-identity` for a
  designated file that does not exist. A missing `:key-file` or Keychain item
  only makes [[identity-available?]] false, so keyless operations stay
  possible."
  [identity-or-opts]
  (let [{:keys [identity-file identity-source designated?] :as candidate}
        (identity-candidate identity-or-opts)]
    (when identity-file
      (validate-identity-path! identity-file identity-source))
    (when (and designated? (not (identity-available? candidate)))
      (throw (ex-info (str (identity-source-subject identity-source)
                           " names an age identity file that does not exist: " identity-file)
                      {:reason :no-identity
                       :identity-file identity-file
                       :identity-source identity-source})))
    (dissoc candidate :designated?)))

(def ^:private identity-options
  "Remediation appended to \"no identity\" errors."
  (str "Store a key with `bb secrets keygen` (the macOS Keychain, or the configured "
       ":key-file), or pass {:key-command [...]} or {:key-file ...}; or set "
       "SECRETS_AGE_IDENTITY_FILE (key path), SECRETS_AGE_IDENTITY (raw key contents), or "
       "SECRETS_AGE_IDENTITY_B64 (base64 contents)."))

;;;; Loading

(defn- validate-load-identity!
  "Throw `:no-identity` unless `identity` is available."
  [descriptor {:keys [identity-file identity-source] :as identity}]
  (when-not (identity-available? identity)
    (let [nameable (some-> identity-file str)]
      (throw (ex-info (str "No age identity found"
                           (cond
                             nameable (str " (" nameable " does not exist)")
                             (= :keychain identity-source)
                             " (the macOS Keychain has no key for this app)")
                           ". " identity-options)
                      (cond-> {:reason :no-identity}
                        descriptor (assoc :source descriptor)
                        nameable (assoc :identity nameable)))))))

(def ^:private edn-failure-reasons
  #{:edn-empty :edn-extra-values :edn-too-deep :edn-malformed})

(defn- read-secrets-edn
  "Parse decrypted `plaintext` under the shared content-free EDN policy. The
  one place decrypted EDN becomes a returned value, so it is where the
  reserved metadata key ([[com.kirahowe.secrets.manifest/store-key]]) is
  dropped."
  [plaintext]
  (let [{:keys [ok? value] :as parsed} (safe-edn/parse plaintext)]
    (if ok?
      (manifest/user-data value)
      (throw (ex-info (str "The decrypted secrets are not valid EDN ("
                           (safe-edn/failure-message parsed) ").")
                      (safe-edn/failure-data parsed))))))

(defn- decrypt-and-read!
  "Decrypt and read `file`, always running `cleanup!`.

  Failures are re-thrown with the `source` descriptor added, since `file` may
  be a temp copy the caller never named. Content-free EDN failures drop their
  cause; others keep it."
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
  "Load `source` with the resolved `identity`."
  [source identity]
  (let [descriptor (source/descriptor source)]
    (validate-load-identity! descriptor identity)
    (let [[file cleanup!] (source/acquire! source descriptor)]
      (decrypt-and-read! identity file descriptor cleanup!))))

(defn load-secrets
  "Decrypt an age-encrypted EDN source and return its value. The reserved
  top-level key `:com.kirahowe.secrets/store`, where the CLI keeps a store's
  metadata, is never returned.

  `source` is local-only: a filesystem path (String, `java.io.File`, or
  `java.nio.file.Path`), or a classpath resource as the `java.net.URL` from
  `clojure.java.io/resource`, with scheme `file:` or `jar:file:`. Anything
  else is rejected with `:disallowed-source` before it is opened.

  `identity-or-opts` is an identity path or an options map, resolved as
  [[resolve-identity]] describes.
    :identity-file  explicit identity path (wins over the env vars)
    :key-command    a program and its arguments, as a vector of strings, that
                    prints the key
    :key-file       the project's key path
    :app            app name; on macOS, its login Keychain item holds the key
  Without any of these, only the SECRETS_AGE_IDENTITY* variables are used.

  Missing or invalid inputs throw ex-info with a :reason:
    :no-identity        no identity resolves, or a designated identity file
                        does not exist.
    :invalid-identity   an identity variable is set but blank,
                        SECRETS_AGE_IDENTITY_B64 is not valid base64, or a
                        :key-command is malformed or prints nothing.
    :key-command-failed the :key-command could not start or exited nonzero.
    :keychain-failed    the macOS Keychain could not be read.
    :disallowed-identity  the identity path is URI-shaped or holds key
                        contents, so it is not a local path.
    :decrypt-failed     age could not decrypt the source with the identity.
    :no-file            `source` is nil or blank, or names no file, or an
                        allowed local source cannot be read.
    :disallowed-source  `source` is outside the local-only provenance contract.
  Fixed bounds catch accidental huge input: a source past 16 MiB throws
  `:source-too-large` (which bounds the plaintext too, as age does not
  compress), and EDN nested past 100 collections throws `:edn-too-deep`. Each
  carries the numeric `:limit`. The identity is resolved first, then source
  policy and opening. The plaintext is read with `clojure.edn`, not `eval`.

  Every failure about a source carries `:source`, allowlisted metadata naming
  it (a file's path, a resource URL's scheme and path, a refused URL's or
  string's scheme alone, or a rejected object's class), never the source
  value itself, whose userinfo or query can be a credential."
  ([source] (load-secrets source nil))
  ([source identity-or-opts]
   (load-with-identity source (resolve-identity identity-or-opts))))

(defn get-secret
  "Read a secret from a loaded store. `key-path` is a vector path
  (`[:database :url]`) or a single key (`:database/url`).

  A path walks maps by key and vectors by integer index only; it does not
  index into strings, sets, or lists. Returns `default` (nil unless given)
  when the path is not found, and the stored value, which may be nil, when it
  is."
  ([secrets key-path] (get-secret secrets key-path nil))
  ([secrets key-path default]
   (reduce (fn [value k]
             (if (or (and (map? value) (contains? value k))
                     (and (vector? value) (integer? k) (contains? value k)))
               (get value k)
               (reduced default)))
           secrets
           (if (vector? key-path) key-path [key-path]))))

;;;; EDN reader literals

(defn- reader-loaded-state
  "Load the readers' source, or describe why it is unavailable."
  [{:keys [resource file] :as opts}]
  (let [source (cond
                 file (when (.isFile (io/file (str file)))
                        (io/file (str file)))
                 resource (io/resource resource))]
    (cond
      (nil? source)
      {:present? false :reason :no-file}

      :else
      (let [identity (resolve-identity opts)]
        (if-not (identity-available? identity)
          {:present? false :reason :no-identity}
          {:present? true :secrets (load-with-identity source identity)})))))

(defn- validate-reader-source!
  "Throw `:disallowed-source` when the readers' `:file` or `:resource` is
  URI-shaped or holds key contents. `:source` is its credential-free
  descriptor and the message names only the scheme."
  [{:keys [file resource]}]
  (doseq [[option value expected]
          [[:file file "a local filesystem path"]
           [:resource resource "a classpath resource name"]]]
    (when-let [problem (some-> value str source/path-problem)]
      (throw (ex-info (source/path-problem-message
                       (str "The secrets " option " option") expected
                       (cond-> problem (= :resource option) (dissoc :bare?)))
                      (cond-> {:reason :disallowed-source}
                        (= :locator (:problem problem))
                        (assoc :source (source/descriptor (str value)))))))))

(defn- required-secret-handler
  "Build the `#secret/req` reader around a shared delayed loaded state.

  A failure names the configured store under `:store`, never `:source`: a load
  failure surfacing through this reader already carries `:source`, and one key
  must not mean two shapes."
  [loaded describe]
  (fn [key-path]
    (let [{:keys [present? reason secrets]} @loaded]
      (when-not present?
        (throw (ex-info (if (= reason :no-identity)
                          (str "Required secret " (pr-str key-path)
                               " needs an age identity, but none is available. "
                               identity-options)
                          (str "Required secret " (pr-str key-path)
                               " cannot be read: no secrets file found (" describe ")."))
                        {:key key-path :store describe :reason reason})))
      (let [value (get-secret secrets key-path not-found)]
        (when (= value not-found)
          (throw (ex-info (str "Required secret " (pr-str key-path)
                               " is missing from the secrets file.")
                          {:key key-path :store describe :reason :missing-key})))
        value))))

(defn- optional-secret-handler
  "Build the `#secret/opt` reader around a shared delayed loaded state."
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
                   (resolved lazily with io/resource; nil/absent means no
                   secrets).
    :file          a local file path, used instead of :resource. A URI-shaped
                   :file or :resource throws `:disallowed-source` here, with
                   the same credential-free `:source` descriptor a load
                   failure carries.
    :app, :key-command, :key-file, :identity-file
                   as in `load-secrets`.

  The source is resolved and decrypted at most once, when the first tag is
  read. That first successful load or decryption failure is cached for the
  life of the returned map; recreate it after editing or repairing
  ciphertext. A config with no secret tags never touches the source or
  identity.

  Semantics, mirroring required/optional env reads:
    #secret/req k  throws when no secrets file is found, when no identity is
                   available, or when the key is missing from the map.
    #secret/opt k  returns nil in all three of those cases.
  \"No identity is available\" means none was designated and the project's
  key file or Keychain item is absent. A designated identity file that does
  not exist makes both tags throw `:no-identity`, and a failed decryption
  makes both throw `:decrypt-failed`."
  [opts]
  (let [loaded (delay (reader-loaded-state opts))
        _ (validate-reader-source! opts)
        describe (or (:file opts) (:resource opts) "secrets")]
    {'secret/req (required-secret-handler loaded describe)
     'secret/opt (optional-secret-handler loaded)}))

(defn merge-readers
  "Merge `reader-literals` into an existing `:readers` map. The result has
  its own fresh cache; call again after editing or repairing ciphertext."
  [readers opts]
  (merge readers (reader-literals opts)))
