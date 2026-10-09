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

  • As an Integrant/component value: call `load-secrets` to get the map and
    `get-secret` to read keys from it. (See the README for a two-line init-key.)

  • As EDN reader literals: call `reader-literals` (or `merge-readers`) to get
    `#secret/req` / `#secret/opt` tags you can register with your config
    reader, so config files reference secrets inline:

        :jdbc-url #secret/req :database/url  ; required: throws if absent
        :api-key  #secret/opt :llm/api-key   ; optional: nil if absent

  An explicit identity path takes precedence. Otherwise resolution uses:
    1. $SECRETS_AGE_IDENTITY_FILE, a path to the key file.
    2. $SECRETS_AGE_IDENTITY, the raw key file *contents*, used verbatim and
       materialized to a 0600 temp file. Lets a deploy inject the key as one
       secret/env var.
    3. $SECRETS_AGE_IDENTITY_B64, canonical base64-encoded key file contents.
       ASCII space, horizontal tab, carriage return, and line feed are permitted
       for wrapping; every other nonalphabet character or malformed encoding throws.
    4. the project's default key location: a `:key-file` option, or
       ~/.config/<app>/key.txt when an app name is known (an `:app` option).
  When none of these yields an identity, resolution returns nil and loading
  throws with the options above rather than guessing a path.

  An identity path is a local filesystem path, with a leading `~` expanded. A
  URI-shaped value, which includes a bare relative name with a colon such as
  `key:txt`, fails with `:disallowed-identity` and the error names its source
  and scheme; write `./key:txt` for such a file. Key contents in a path
  setting, raw or base64-encoded, fail the same way and are never echoed.

  A path you designate has to exist. An explicit path, `:identity-file`, or
  $SECRETS_AGE_IDENTITY_FILE that names a missing file fails with
  `:no-identity`, naming the source and the path. Only the default location
  in 4 may be absent, and then no identity is available.

  Sources 2 and 3 are written to a private temporary file only while an
  operation needs them, then deleted before that operation returns. If the
  delete fails, the error names the remaining path."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.fs :as fs]
            [com.kirahowe.secrets.manifest :as manifest]
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
           {:reason :invalid-identity :env "SECRETS_AGE_IDENTITY_B64"}))

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
  "Read environment variable `k`. This is the only raw environment read in the
  namespace, and the seam tests redefine."
  [k]
  (System/getenv k))

(defn- identity-env
  "`identity-env-value` applied to the live environment."
  [k]
  (identity-env-value k (getenv k)))

(def ^:private identity-source-subject
  "How an error names the place an identity path came from."
  {:identity-file "The explicit identity path"
   :secrets-age-identity-file "SECRETS_AGE_IDENTITY_FILE"
   :configured-key-file "The configured :key-file"
   :default-key-file "The default key path"})

(defn- identity-candidate
  "Choose an identity without materializing injected contents.

  Every path has `~` expanded here, so one rule covers each source. An
  explicit path and SECRETS_AGE_IDENTITY_FILE are `:designated?`: the file has
  to exist. `:key-file` and the app default are where a key is expected by
  default, so their absence means only that no identity is available."
  [identity-or-opts]
  (let [opts (if (map? identity-or-opts) identity-or-opts {})
        explicit (if (map? identity-or-opts) (:identity-file opts) identity-or-opts)
        designated (fn [path source]
                     {:identity-file (expand-home path)
                      :identity-source source
                      :designated? true})]
    (or (when explicit
          (designated explicit :identity-file))
        (when-let [path (identity-env "SECRETS_AGE_IDENTITY_FILE")]
          (designated path :secrets-age-identity-file))
        (when-let [contents (identity-env "SECRETS_AGE_IDENTITY")]
          {:contents contents :identity-source :secrets-age-identity})
        (when-let [contents (identity-env "SECRETS_AGE_IDENTITY_B64")]
          {:contents (decode-b64-identity contents)
           :identity-source :secrets-age-identity-b64})
        (when-let [path (:key-file opts)]
          {:identity-file (expand-home path)
           :identity-source :configured-key-file})
        (when-let [app (:app opts)]
          {:identity-file (default-key-file app)
           :identity-source :default-key-file})
        {:identity-file nil :identity-source nil})))

(defn- validate-identity-path!
  "Throw `:disallowed-identity` when `path` cannot name a local identity file:
  it holds key contents, or it is URI-shaped. The error names where the value
  came from and, for a URI, its `:scheme`. It never renders the value."
  [path identity-source]
  (when-let [problem (some-> path str source/path-problem)]
    (throw (ex-info (source/path-problem-message (identity-source-subject identity-source)
                                                 "a local filesystem path"
                                                 problem)
                    (cond-> {:reason :disallowed-identity
                             :identity-source identity-source}
                      (:scheme problem) (assoc :scheme (:scheme problem)))))))

(defn- identity-file-exists?
  "True when `path` names an identity file that exists."
  [path]
  (boolean (and path (.exists (io/file (str path))))))

(defn- require-designated-identity!
  "Throw `:no-identity` when the designated identity file at `path` does not
  exist, naming where the path came from and the path."
  [path identity-source]
  (when-not (identity-file-exists? path)
    (throw (ex-info (str (identity-source-subject identity-source)
                         " names an age identity file that does not exist: " path)
                    {:reason :no-identity
                     :identity-file path
                     :identity-source identity-source}))))

(defn with-identity
  "Call `f` with an operation-owned identity descriptor.

  `identity-or-opts` accepts an explicit path or an options map. `f` receives
  `{:identity-file path-or-nil :identity-source source}`. Resolution is an
  explicit path, then SECRETS_AGE_IDENTITY_FILE/raw/base64, then `:key-file`,
  then an `:app` default. Every path has a leading `~` expanded.

  Before `f` runs, a path that is URI-shaped or holds key contents throws
  `:disallowed-identity`. An explicit path and SECRETS_AGE_IDENTITY_FILE each
  designate a file, and one that does not exist throws `:no-identity` naming
  its source and the path. `:key-file` and the `:app` default are default
  locations, not designations: `f` receives the path whether or not the file
  exists, and a nil path when there is neither, so keyless operations stay
  possible.

  A raw or base64 identity is written to a private temporary file for this
  call only, through [[com.kirahowe.secrets.fs/with-private-temp-file]], which
  deletes it when `f` returns or throws and names the path under
  `:remaining-file` if the delete fails. A failed write throws
  `:identity-not-materialized` without the cause or its message."
  [identity-or-opts f]
  (let [{:keys [contents identity-source] :as candidate}
        (identity-candidate identity-or-opts)]
    (if (contains? candidate :contents)
      (fs/with-private-temp-file "age-identity-" ".txt"
        (fn [file]
          (try
            (spit file contents)
            (catch Exception e
              (throw (ex-info (str "Could not write the injected age identity to a temp file ("
                                   (.getName (class e)) "). Check the temp directory is writable.")
                              {:reason :identity-not-materialized
                               :identity-source identity-source}))))
          (f {:identity-file (.getAbsolutePath ^java.io.File file)
              :identity-source identity-source})))
      (let [{:keys [identity-file designated?]} candidate]
        (validate-identity-path! identity-file identity-source)
        (when designated?
          (require-designated-identity! identity-file identity-source))
        (f {:identity-file identity-file :identity-source identity-source})))))

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

(def ^:private edn-failure-reasons
  #{:edn-empty :edn-extra-values :edn-too-deep :edn-malformed})

(defn- read-secrets-edn
  "Parse decrypted `plaintext` under the shared, content-free EDN policy and
  return the user's data. This is the one place decrypted EDN becomes a
  returned value, so it is where the library's reserved metadata key
  ([[com.kirahowe.secrets.manifest/store-key]]) is dropped."
  [plaintext]
  (let [{:keys [ok? value] :as parsed} (safe-edn/parse plaintext)]
    (if ok?
      (manifest/user-data value)
      (throw (ex-info (str "The decrypted secrets are not valid EDN ("
                           (safe-edn/failure-message parsed) ").")
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
  "Decrypt an age-encrypted EDN source and return its value. The reserved
  top-level key `:com.kirahowe.secrets/store`, under which the CLI keeps a
  store's metadata, is library data and is never returned.

  `source` is local-only: a filesystem path as a String, `java.io.File`, or
  `java.nio.file.Path`, or a classpath resource as the `java.net.URL` that
  `clojure.java.io/resource` returns, whose scheme is `file:` or `jar:file:`.
  Anything else is rejected with `:disallowed-source` before it is opened.
  `identity-or-opts` is an identity path or an options map:
    :identity-file  explicit identity path (wins over :app and the env vars)
    :app            app name for the default ~/.config/<app>/key.txt
  Without an explicit identity or app, only the SECRETS_AGE_IDENTITY*
  environment variables are used.

  Missing or invalid inputs throw ex-info with a :reason:
    :no-identity        no identity resolves, the app default key file is
                        absent, or a designated identity file does not exist.
    :invalid-identity   an identity variable is set but blank, or
                        SECRETS_AGE_IDENTITY_B64 is not valid base64.
    :disallowed-identity  the identity path is URI-shaped or holds key
                        contents, so it is not a local path.
    :decrypt-failed     age could not decrypt the source with the identity.
    :no-file            `source` is nil, an allowed local file is absent, or an
                        allowed local source cannot be read.
    :disallowed-source  `source` is outside the local-only provenance contract.
  Fixed bounds catch an accidental huge or deeply nested input: a source past
  16 MiB throws `:source-too-large`, which bounds the plaintext too because
  age does not compress, and EDN nested past 100 collections throws
  `:edn-too-deep`. Each carries the numeric `:limit`. The identity is resolved
  first, then source policy and opening. The plaintext is read with
  `clojure.edn`, not `eval`.

  Every failure about a source carries `:source`, allowlisted metadata naming
  which source failed (a file's path, a resource URL's scheme and path, a
  refused URL's or string's scheme alone, or a rejected object's class) and
  never the source value, whose userinfo, query, or `toString` can be a
  credential. Injected identities are kept in a
  private temporary file only for the duration of this operation."
  ([source] (load-secrets source nil))
  ([source identity-or-opts]
   (load-from source identity-or-opts)))

(defn get-secret
  "Read a secret from a loaded store. `key-path` is a vector path
  (`[:database :url]`) or a single key (`:database/url`), which is a path of
  one element.

  A vector path walks maps by key and vectors by integer index, and nothing
  else. It does not index into a string, a set, a list, or any other value, so
  a path that continues past such a leaf is not found. Returns `default` (nil
  unless given) when the path is not found, and the stored value, which may be
  nil, when it is."
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
  URI-shaped or holds key contents. `:source` is its descriptor, which drops
  userinfo, query, and fragment, and the message names only the scheme."
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
                               " cannot be read: no secrets file found (" describe ")."))
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
  \"No identity is available\" means none was designated and the default key
  file is absent. A designated identity file that does not exist makes both
  tags throw `:no-identity`, as does a decryption that fails."
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
