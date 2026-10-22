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
    2. $SECRETS_AGE_IDENTITY, the raw key file *contents*, used verbatim. Lets
       a deploy inject the key as one secret/env var.
    3. $SECRETS_AGE_IDENTITY_B64, canonical base64-encoded key file contents.
       ASCII space, horizontal tab, carriage return, and line feed are permitted
       for wrapping; every other nonalphabet character or malformed encoding throws.
    4. where the project keeps its key: the output of a `:key-command`, such as
       a password manager's read command, else a `:key-file`, else on macOS the
       login Keychain item for the `:app` option.
  When none of these yields an identity, loading throws with the options above
  rather than guessing a path. There is no default key file.

  An identity path is a local filesystem path, with a leading `~` expanded. A
  URI-shaped value, which includes a bare relative name with a colon such as
  `key:txt`, fails with `:disallowed-identity` and the error names its source
  and scheme; write `./key:txt` for such a file. Key contents in a path
  setting, raw or base64-encoded, fail the same way and are never echoed.

  A path you designate has to exist. An explicit path, `:identity-file`, or
  $SECRETS_AGE_IDENTITY_FILE that names a missing file fails with
  `:no-identity`, naming the source and the path. A `:key-file` may be
  absent, and so may the Keychain item, and then no identity is available.

  A key that is not in a file (sources 2 and 3, a `:key-command`, the
  Keychain) is held in memory and handed to `age` on its standard input. The
  library never writes it to disk."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.fs :as fs]
            [com.kirahowe.secrets.keychain :as keychain]
            [com.kirahowe.secrets.manifest :as manifest]
            [com.kirahowe.secrets.safe-edn :as safe-edn]
            [com.kirahowe.secrets.source :as source]))

(def ^:private not-found ::not-found)

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
   :configured-key-file "The configured :key-file"})

(defn- run-key-command!
  "Run `argv`, a `:key-command`, and return what it prints: the age identity.
  It gets no standard input, so it cannot consume a value piped to the CLI.
  A command that is not a vector of strings, cannot start, fails, or prints
  nothing throws, naming the program and never its output."
  [argv]
  (when-not (and (vector? argv) (seq argv) (every? #(and (string? %) (not (str/blank? %))) argv))
    (throw (ex-info (str ":key-command must be a vector of non-blank strings, a program and"
                         " its arguments, such as [\"op\" \"read\" \"op://vault/myapp/key\"].")
                    {:reason :invalid-identity :identity-source :key-command})))
  (let [program (first argv)
        fail (fn [why] (ex-info (str "The :key-command " program " " why)
                                {:reason :key-command-failed
                                 :identity-source :key-command
                                 :program program}))
        {:keys [exit out err]} (try
                                 (fs/sh argv)
                                 (catch java.io.IOException _
                                   (throw (fail "could not be started. Is it installed?"))))]
    (cond
      (not (zero? exit))
      (throw (fail (str "exited " exit (when-not (str/blank? err) (str ": " (str/trim err))))))

      (str/blank? out)
      (throw (ex-info (str "The :key-command " program " printed no age identity.")
                      {:reason :invalid-identity
                       :identity-source :key-command
                       :program program}))

      :else out)))

(defn key-identity
  "Return the identity a project keeps for itself, ignoring the
  SECRETS_AGE_IDENTITY* variables: the output of `:key-command`, else the
  `:key-file`, else on macOS the Keychain item for `:app`. A command or the
  Keychain is read now, and its key is held in memory as
  `:identity-contents`. A key file is named by `:identity-file` whether or
  not it exists. When the Keychain has no item for the app, or nothing names
  a key, the result has no `:identity-contents` and a nil `:identity-file`."
  [{:keys [key-command key-file app]}]
  (cond
    key-command
    {:identity-contents (run-key-command! key-command) :identity-source :key-command}

    key-file
    {:identity-file (fs/expand-home key-file) :identity-source :configured-key-file}

    (and app (keychain/available?))
    (if-let [contents (keychain/read-key app)]
      {:identity-contents contents :identity-source :keychain}
      {:identity-file nil :identity-source :keychain})

    :else
    {:identity-file nil :identity-source nil}))

(defn- identity-candidate
  "Choose an identity. An explicit path and SECRETS_AGE_IDENTITY_FILE are
  `:designated?`: the file has to exist. Everything else comes from
  [[key-identity]]."
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
        (key-identity opts))))

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

(defn identity-available?
  "True when `identity`, a resolved identity, holds a key in memory or names
  an identity file that exists."
  [{:keys [identity-file identity-contents]}]
  (boolean (or identity-contents
               (and identity-file (.exists (io/file (str identity-file)))))))

(defn resolve-identity
  "Resolve `identity-or-opts`, an explicit path or an options map, to the
  identity an operation decrypts with, and return it.

  The result is `{:identity-file path :identity-source source}` for a key
  file, or `{:identity-contents key :identity-source source}` for a key held
  in memory, which is handed to `age` on its standard input and never written
  to disk. Resolution is an explicit path (`:identity-file`), then
  SECRETS_AGE_IDENTITY_FILE, SECRETS_AGE_IDENTITY, SECRETS_AGE_IDENTITY_B64,
  then `:key-command`, `:key-file`, and on macOS the Keychain item for `:app`.
  Every path has a leading `~` expanded.

  A path that is URI-shaped or holds key contents throws
  `:disallowed-identity`. An explicit path and SECRETS_AGE_IDENTITY_FILE each
  designate a file, and one that does not exist throws `:no-identity` naming
  its source and the path. A `:key-file` that does not exist, or a Keychain
  with no item for the app, means only that no identity is available
  ([[identity-available?]] is false), so keyless operations stay possible."
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
  "One-line remediation appended to \"no identity\" errors."
  (str "Store a key with `bb secrets keygen` (the macOS Keychain, or the configured "
       ":key-file), or pass {:key-command [...]} or {:key-file ...}; or set "
       "SECRETS_AGE_IDENTITY_FILE (key path), SECRETS_AGE_IDENTITY (raw key contents), or "
       "SECRETS_AGE_IDENTITY_B64 (base64 contents)."))

;;;; Loading

(defn- validate-load-identity!
  "Throw unless `identity` is available, naming the key file it looked for."
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
  "Load `source` with the resolved `identity`."
  [source identity]
  (let [descriptor (source/descriptor source)]
    (validate-load-identity! descriptor identity)
    (let [[file cleanup!] (source/acquire! source descriptor)]
      (decrypt-and-read! identity file descriptor cleanup!))))

(defn load-secrets
  "Decrypt an age-encrypted EDN source and return its value. The reserved
  top-level key `:com.kirahowe.secrets/store`, under which the CLI keeps a
  store's metadata, is library data and is never returned.

  `source` is local-only: a filesystem path as a String, `java.io.File`, or
  `java.nio.file.Path`, or a classpath resource as the `java.net.URL` that
  `clojure.java.io/resource` returns, whose scheme is `file:` or `jar:file:`.
  Anything else is rejected with `:disallowed-source` before it is opened.
  `identity-or-opts` is an identity path or an options map:
    :identity-file  explicit identity path (wins over the env vars)
    :key-command    a program and its arguments, as a vector of strings, that
                    prints the key, used when no env var is set
    :key-file       the project's key path, used when no env var is set
    :app            app name; on macOS, its login Keychain item holds the key
                    when neither of the two above is given
  Without one of these, only the SECRETS_AGE_IDENTITY* environment variables
  are used.

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
  credential. A key that is not in a file reaches `age` on its standard
  input and is never written to disk."
  ([source] (load-secrets source nil))
  ([source identity-or-opts]
   (load-with-identity source (resolve-identity identity-or-opts))))

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
    :app           app name; on macOS its Keychain item holds the key.
    :key-command   a program and its arguments that print the key.
    :key-file      the project's key path, used when no env var is set.
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
  \"No identity is available\" means none was designated and the project's
  key file or Keychain item is absent. A designated identity file that does not exist makes both
  tags throw `:no-identity`, and a decryption that fails makes both throw
  `:decrypt-failed`."
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
