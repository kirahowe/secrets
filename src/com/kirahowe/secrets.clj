(ns com.kirahowe.secrets
  "Runtime loading of age-encrypted EDN secrets.

  Secrets live in a single version-controlled, age-encrypted EDN file
  (`secrets.edn.age`). At runtime they are decrypted once with your age
  identity (private key) and read into a plain Clojure map. The plaintext is
  never written to disk and never committed.

  Two ways to consume secrets:

  • As an Integrant/component value — call `load-secrets` to get the map and
    `get-secret` to read keys from it. (See the README for a 6-line init-key.)

  • As EDN reader literals — call `reader-literals` (or `merge-readers`) to get
    `#secret` / `#secret/opt` tags you can register with your config reader, so
    config files reference secrets inline:

        :jdbc-url #secret :database/url      ; required — throws if absent
        :api-key  #secret/opt :llm/api-key   ; optional — nil if absent

  Identity resolution (where the private key comes from), in order:
    1. $AGE_IDENTITY_FILE — a path to the key file.
    2. $AGE_IDENTITY      — the key *contents* (raw or base64), materialized to
       a 0600 temp file. Lets a deploy inject the key as one secret/env var.
    3. ~/.config/<app>/key.txt — the local developer default."
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

;; ---------- Identity (private key) resolution ----------

(def ^:private identity-temp
  "Caches the temp file materialized from $AGE_IDENTITY so the key is written
  to disk at most once per process, keyed on its contents."
  (atom {}))

(defn- decode-identity
  "Return raw age identity text from an $AGE_IDENTITY value. A value already
  containing `AGE-SECRET-KEY` is used verbatim; anything else is treated as
  base64 (newline-tolerant) and decoded, falling back to verbatim."
  [contents]
  (if (str/includes? contents "AGE-SECRET-KEY")
    contents
    (try
      (String. (.decode (java.util.Base64/getMimeDecoder) (str/trim contents)))
      (catch Exception _ contents))))

(defn- materialize-identity!
  "Write age identity `contents` to an owner-only temp file (once per process)
  and return its path."
  [contents]
  (or (@identity-temp contents)
      (let [f (doto (java.io.File/createTempFile "age-identity-" ".txt")
                (.deleteOnExit)
                (.setReadable false false) (.setReadable true true)
                (.setWritable false false) (.setWritable true true))]
        (spit f (decode-identity contents))
        (let [path (.getAbsolutePath f)]
          (swap! identity-temp assoc contents path)
          path))))

(defn resolve-identity-file
  "Resolve the age identity (private key) file path for `app` (used only for the
  default `~/.config/<app>/key.txt`). Honors $AGE_IDENTITY_FILE and $AGE_IDENTITY
  first — see this namespace's docstring."
  ([] (resolve-identity-file nil))
  ([app]
   (or (System/getenv "AGE_IDENTITY_FILE")
       (when-let [c (System/getenv "AGE_IDENTITY")]
         (materialize-identity! c))
       (expand-home (str "~/.config/" (or app "secrets") "/key.txt")))))

;; ---------- Loading ----------

(defn- source->file
  "Coerce a secrets `source` to a [file cleanup!] pair. Path strings and Files
  are used in place (no cleanup). Anything slurpable-as-binary that is not a
  plain file (e.g. a jar resource URL from io/resource) is copied to a temp file
  so `age` can read it; cleanup deletes that copy."
  [source]
  (let [f (io/file source)]
    (if (and (instance? java.io.File source) (.exists f))
      [f (fn [])]
      (if (and (string? source) (.exists f))
        [f (fn [])]
        (let [tmp (doto (java.io.File/createTempFile "secrets-" ".age")
                    (.deleteOnExit))]
          (with-open [in  (io/input-stream source)
                      out (io/output-stream tmp)]
            (io/copy in out))
          [tmp #(.delete tmp)])))))

(defn load-secrets
  "Decrypt and read an age-encrypted EDN file into a map.

  `source` is the encrypted file: a path string, a File, or a URL/resource (as
  returned by `clojure.java.io/resource`). `identity-file` defaults to
  `(resolve-identity-file)`.

  Reads with `clojure.edn` (no eval), so secret files are plain data and may use
  any EDN — including native sets for allowlists, e.g. `#{\"a@b.com\"}`."
  ([source] (load-secrets source (resolve-identity-file)))
  ([source identity-file]
   (let [[file cleanup!] (source->file source)]
     (try
       (edn/read-string (age/decrypt identity-file (.getAbsolutePath ^java.io.File file)))
       (finally (cleanup!))))))

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
  "Build the `#secret` / `#secret/opt` EDN reader-literal functions, bound to a
  secrets source. Returns a map of `{symbol fn}` ready to merge into the
  `:readers` you pass to `clojure.edn/read-string` or `integrant.core/read-string`.

  Options:
    :resource      classpath resource name to decrypt, e.g. \"secrets.edn.age\"
                   (resolved lazily with io/resource; nil/absent ⇒ no secrets).
    :file          an explicit file path, used instead of :resource.
    :app           app name for the default key path ~/.config/<app>/key.txt.
    :identity-file explicit identity path (overrides resolution).

  The file is resolved and decrypted at most once, on the first `#secret`
  encountered — so configs with no secret tags (e.g. dev/test) never touch
  `age` or the key, even when a secrets file happens to be on the classpath.

  Semantics, mirroring required/optional env reads:
    #secret      k → required: throws if the file is absent, or the key missing.
    #secret/opt  k → optional: nil if the file is absent or the key missing."
  [{:keys [resource file app identity-file]}]
  (let [identity (delay (or identity-file (resolve-identity-file app)))
        ;; {:present? bool :secrets map} — computed once; a decryption failure
        ;; (bad key, age missing) is cached and re-thrown by every #secret.
        loaded   (delay
                   (if-let [src (cond file     (when (.exists (io/file (str file))) (io/file (str file)))
                                      resource  (io/resource resource))]
                     {:present? true :secrets (load-secrets src @identity)}
                     {:present? false}))
        describe (or file resource "secrets")]
    {'secret
     (fn [key-path]
       (let [{:keys [present? secrets]} @loaded]
         (when-not present?
           (throw (ex-info (str "Required secret " (pr-str key-path)
                                " — but no secrets file found (" describe ").")
                           {:key key-path :source describe})))
         (let [v (get-secret secrets key-path not-found)]
           (when (= v not-found)
             (throw (ex-info (str "Required secret " (pr-str key-path)
                                  " is missing from the secrets file.")
                             {:key key-path :source describe})))
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
