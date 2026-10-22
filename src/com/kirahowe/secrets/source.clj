(ns com.kirahowe.secrets.source
  "Implementation namespace; not part of the public API and may change without notice.

  Local-only, size-bounded acquisition of encrypted secrets sources: a
  filesystem path or a `file:` or `jar:file:` classpath resource URL. A source
  value may itself contain credentials, so diagnostics carry only allowlisted
  descriptors, and a URL is read through its fields, never opened."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [com.kirahowe.secrets.fs :as fs]))

(def ^:private uri-scheme
  "A leading URI scheme, per RFC 3986. A string carrying one is a locator whose
  remainder may hold a credential."
  #"^([A-Za-z][A-Za-z0-9+.\-]*):")

(def ^:private windows-absolute-path
  "A Windows drive path, not a one-letter URI scheme."
  #"(?i)^[a-z]:[\\/]")

(def max-source-bytes
  "The most ciphertext bytes one source may hold (16 MiB), to catch a wrong
  file before it is copied or decrypted."
  16777216)

(def ^:private no-store-hint
  "Remediation appended to no-file errors."
  "Create it with `bb secrets new`.")

(defn- locator-scheme
  "Return the lower-case URI scheme `s` begins with (after trimming), or nil
  for a plain path. A Windows drive path such as `C:\\keys` is a path. A bare
  relative name with a colon, such as `key:txt`, has the scheme `key`;
  `./key:txt` is a path."
  [s]
  (let [s (str/trim s)]
    (when-not (re-find windows-absolute-path s)
      (some-> (second (re-find uri-scheme s)) str/lower-case))))

(defn- key-contents?
  "True when `s` holds an age secret key and must never be echoed: the key,
  its base64 encoding, or the bech32 body of a key missing its
  `AGE-SECRET-KEY-` prefix."
  [s]
  (let [marker "AGE-SECRET-KEY-"
        packed (str/replace s #"[ \t\r\n]" "")]
    (boolean
     (or (str/includes? s marker)
         (re-matches #"1?[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}" s)
         (try (str/includes? (String. (.decode (java.util.Base64/getDecoder) packed)
                                      "ISO-8859-1")
                             marker)
              (catch IllegalArgumentException _ false))))))

(defn path-problem
  "Return nil when string `s` can name a local file, otherwise a map saying
  why not: `{:problem :key-contents}` (an age secret key, raw or base64) or
  `{:problem :locator :scheme scheme :bare? boolean}` (URI-shaped; `:bare?`
  means no `/` follows the scheme, as in a relative file name with a colon).
  The map holds no part of `s` except its scheme."
  [s]
  (let [s (str/trim (str s))]
    (if (key-contents? s)
      {:problem :key-contents}
      (when-let [scheme (locator-scheme s)]
        {:problem :locator
         :scheme scheme
         :bare? (not (str/includes? (subs s (inc (count scheme))) "/"))}))))

(defn path-problem-message
  "Render a [[path-problem]] as a sentence about `subject` (the variable,
  option, or field that held the value). `expected` says what it should have
  been, such as \"a local filesystem path\". The value is never rendered."
  [subject expected {:keys [problem scheme bare?]}]
  (case problem
    :key-contents
    (str subject " holds age key contents where " expected " was expected."
         " Key contents belong in SECRETS_AGE_IDENTITY.")
    :locator
    (str subject " must be " expected ", but its value starts with the URI scheme \""
         scheme "\"."
         (when bare?
           " For a relative file whose name contains a colon, write ./ before the name."))))

(defn- decode
  "Decode percent-escapes in URL path `raw`, leaving `+` alone. Nil when `raw`
  is empty or malformed."
  [raw]
  (when (seq raw)
    (try
      (java.net.URLDecoder/decode (str/replace raw "+" "%2B") "UTF-8")
      (catch IllegalArgumentException _ nil))))

(defn- url-source
  "The local source that classpath resource `url` names, or nil unless it is a
  `file:` URL or a `jar:file:` entry in a local archive, with no authority,
  query, or fragment. Only the URL's fields are read."
  [^java.net.URL url]
  (when (and (empty? (.getAuthority url)) (nil? (.getQuery url)) (nil? (.getRef url)))
    (case (.getProtocol url)
      "file" (when-let [path (decode (.getPath url))]
               {:file (io/file path)})
      "jar" (let [[_ archive entry] (re-matches #"file:(/(?!/).*?)!/(.+)" (.getPath url))]
              (when (and (decode archive) (decode entry))
                {:archive (io/file (decode archive)) :entry (decode entry)}))
      nil)))

(defn descriptor
  "Return allowlisted metadata naming `source` without rendering secret data.

  A File, Path, or path string keeps its path. An accepted classpath URL keeps
  its scheme and path. A refused URL or a URI-shaped string keeps only the
  scheme. Anything else, including a string holding key contents, keeps only
  its class name. `nil` has no descriptor."
  [source]
  (cond
    (nil? source) nil
    (or (instance? java.io.File source) (instance? java.nio.file.Path source))
    {:kind :file :path (str source)}

    (and (string? source) (nil? (path-problem source)))
    {:kind :file :path source}

    (and (string? source) (:scheme (path-problem source)))
    {:kind :url :scheme (:scheme (path-problem source))}

    (instance? java.net.URL source)
    (cond-> {:kind :url :scheme (.getProtocol ^java.net.URL source)}
      (url-source source) (assoc :path (.getPath ^java.net.URL source)))

    :else {:kind :object :class (.getName (class source))}))

(defn- source-description
  "Render a diagnostic phrase from `source-descriptor` alone."
  [{:keys [kind path scheme] class-name :class}]
  (cond
    (= :object kind) (str "an instance of " class-name)
    (= :file kind) path
    path (str scheme ":" path)
    :else (str "a URL with the scheme " scheme)))

(defn- local-source
  "Classify `source` without opening it: `{:file f}` or `{:archive f :entry
  name}`. Anything else throws `:disallowed-source`."
  [source source-descriptor]
  (let [problem (when (string? source) (path-problem source))]
    (or
     (cond
       (instance? java.io.File source) {:file source}
       (instance? java.nio.file.Path source) {:file (.toFile ^java.nio.file.Path source)}
       (instance? java.net.URL source) (url-source source)
       (and (string? source) (nil? problem)) {:file (io/file source)})
     (throw
      (ex-info
       (if problem
         (path-problem-message "The secrets source" "a local filesystem path" problem)
         (str "Secrets sources are local-only. Expected a filesystem path (a String, File,"
              " or Path) or a file: or jar:file: classpath resource URL; "
              (source-description source-descriptor) " is not permitted."))
       {:source source-descriptor :reason :disallowed-source})))))

(defn- source-too-large!
  "Throw `:source-too-large`."
  [source-descriptor observed]
  (throw (ex-info (str "The secrets source " (source-description source-descriptor)
                       " is larger than the " max-source-bytes " byte limit.")
                  {:source source-descriptor
                   :observed observed
                   :limit max-source-bytes
                   :reason :source-too-large})))

(defn- copy-jar-entry!
  "Copy `entry` of local jar `archive` to an owner-only temp file and return
  `[file cleanup!]`. An oversized entry is refused before copying. Any
  failure, an `Error` included, deletes the temp file first."
  [source-descriptor {:keys [archive entry]}]
  (let [tmp (fs/owner-only-temp-file! "secrets-" ".age")]
    (try
      (with-open [jar (java.util.jar.JarFile. ^java.io.File archive)]
        (let [jar-entry (or (.getJarEntry jar entry)
                            (throw (java.io.FileNotFoundException.
                                    "Classpath jar resource not found.")))]
          (when (> (.getSize jar-entry) max-source-bytes)
            (source-too-large! source-descriptor (.getSize jar-entry)))
          (with-open [in (.getInputStream jar jar-entry)]
            (io/copy in tmp))))
      [tmp #(.delete tmp)]
      (catch Throwable t
        (.delete tmp)
        (throw t)))))

(defn- unreadable-source!
  "Throw `:no-file` for an allowed but unreadable local source."
  [source-descriptor e]
  (let [path (when (= :file (:kind source-descriptor)) (:path source-descriptor))]
    (throw
     (if path
       (ex-info (if (.isFile (io/file path))
                  (str "Could not read secrets source " path ": " (.getMessage e))
                  (str "Secrets file not found: " path ". " no-store-hint))
                {:source source-descriptor :reason :no-file}
                e)
       (ex-info (str "Could not read secrets source "
                     (source-description source-descriptor)
                     " (" (.getName (class e)) ").")
                {:source source-descriptor :reason :no-file})))))

(defn acquire!
  "Acquire local `source` as `[file cleanup!]`.

  `source` is a path (String, `File`, or `Path`) or a `file:` or `jar:file:`
  classpath URL. A file is used in place; a jar entry is copied to an
  owner-only temp file that `cleanup!` removes. `source-descriptor` must be
  [[descriptor]] of `source` and is the only representation of it that enters
  failures.

  Throws `:no-file` for a nil or blank source or a path that is not a file,
  `:source-too-large` (with `:limit` and `:observed`) past `max-source-bytes`,
  and `:disallowed-source` for anything else, before it is opened."
  [source source-descriptor]
  (when (nil? source)
    (throw (ex-info (str "No secrets source given: source is nil. This almost always means"
                         " (io/resource \"secrets.edn.age\") found nothing on the classpath."
                         " Check the encrypted file is present as a classpath resource. "
                         no-store-hint)
                    {:reason :no-file})))
  (when (and (string? source) (str/blank? source))
    (throw (ex-info "No secrets source given: the source path is blank."
                    {:reason :no-file})))
  (let [{:keys [^java.io.File file] :as local} (local-source source source-descriptor)]
    (try
      (cond
        (nil? file) (copy-jar-entry! source-descriptor local)
        (not (.isFile file)) (throw (java.io.FileNotFoundException. "No such file."))
        (> (.length file) max-source-bytes) (source-too-large! source-descriptor (.length file))
        :else [file (fn [])])
      (catch java.io.IOException e (unreadable-source! source-descriptor e)))))
