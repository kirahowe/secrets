(ns com.kirahowe.secrets.source
  "Implementation namespace; not part of the public API and may change without notice.

  Local-only, bounded acquisition of encrypted secrets sources.

  A source is a filesystem path or a classpath resource URL whose scheme is
  `file:` or `jar:file:`. Source values may themselves contain credentials, so
  diagnostics cross this boundary only as allowlisted descriptors, and a URL
  is read through its fields and never opened through its handler."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [com.kirahowe.secrets.fs :as fs]))

(def ^:private uri-scheme
  "A leading URI scheme, per RFC 3986. A source string carrying one is a
  locator whose remainder may hold a credential, never a path to keep as-is."
  #"^([A-Za-z][A-Za-z0-9+.\-]*):")

(def ^:private windows-absolute-path
  "A Windows drive path, which is a path rather than a one-letter URI scheme."
  #"(?i)^[a-z]:[\\/]")

(def max-source-bytes
  "The most ciphertext bytes one source may hold (16 MiB). It catches an
  accidental huge input, such as the wrong file, before it is copied or
  decrypted."
  16777216)

(def ^:private no-store-hint
  "One-line remediation appended to no-secrets-file errors."
  "Create it with `bb secrets new`.")

(defn- locator-scheme
  "Return the lower-case URI scheme that string `s` begins with after
  surrounding whitespace is trimmed, or nil when `s` is a plain filesystem
  path. A Windows drive path such as `C:\\keys` is a path. A bare relative
  name with a colon, such as `key:txt`, has the scheme `key`; `./key:txt` is a
  path. A string with a scheme is a locator: its remainder may hold a
  credential, so a diagnostic names the scheme and never the string."
  [s]
  (let [s (str/trim s)]
    (when-not (re-find windows-absolute-path s)
      (some-> (second (re-find uri-scheme s)) str/lower-case))))

(defn path-problem
  "Return nil when string `s` can name a local file, or a map saying why it
  cannot. `{:problem :key-contents}` means it holds an age secret key.
  `{:problem :locator :scheme scheme :bare? boolean}` means it is URI-shaped;
  `:bare?` is true when nothing after the scheme contains a `/`, which is what
  a relative file name with a colon in it looks like. The map never holds any
  part of `s` except its scheme."
  [s]
  (let [s (str/trim (str s))]
    (if (str/includes? s "AGE-SECRET-KEY-")
      {:problem :key-contents}
      (when-let [scheme (locator-scheme s)]
        {:problem :locator
         :scheme scheme
         :bare? (not (str/includes? (subs s (inc (count scheme))) "/"))}))))

(defn path-problem-message
  "Render a [[path-problem]] as one sentence about `subject`, the variable,
  option, or configuration field that held the value. `expected` says what the
  value should have been, such as \"a local filesystem path\". The value
  itself is never rendered."
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
  "Decode the percent-escapes of URL path `raw` without reading `+` as a
  space. Nil when `raw` is empty or malformed."
  [raw]
  (when (seq raw)
    (try
      (java.net.URLDecoder/decode (str/replace raw "+" "%2B") "UTF-8")
      (catch IllegalArgumentException _ nil))))

(defn- url-source
  "The local source that classpath resource `url` names, or nil when it is not
  one `clojure.java.io/resource` returns for a local classpath: a `file:` URL,
  or a `jar:file:` URL of an entry in a local archive, with no authority,
  query, or fragment. Only the URL's fields are read. It is never opened."
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

  A File, a Path, and a path string keep their path. A classpath resource URL
  this namespace accepts keeps its scheme and path. A URL it refuses, and a
  string that is URI-shaped, keep only the scheme. Any other value, a string
  holding key contents included, keeps only its class name, never its
  `toString`. `nil` has no descriptor."
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
  "Render one diagnostic phrase from `source-descriptor` and nothing else."
  [{:keys [kind path scheme] class-name :class}]
  (cond
    (= :object kind) (str "an instance of " class-name)
    (= :file kind) path
    path (str scheme ":" path)
    :else (str "a " scheme ": URL")))

(defn- local-source
  "Classify `source` without opening it: `{:file f}`, or `{:archive f :entry
  name}` for a jar entry. Anything else is refused with `:disallowed-source`."
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
  "Throw a content-free source-size failure."
  [source-descriptor observed]
  (throw (ex-info (str "The secrets source " (source-description source-descriptor)
                       " is larger than the " max-source-bytes " byte limit.")
                  {:source source-descriptor
                   :observed observed
                   :limit max-source-bytes
                   :reason :source-too-large})))

(defn- copy-jar-entry!
  "Copy entry `entry` of local jar `archive` to an owner-only temp file and
  return `[file cleanup!]`. An entry past `max-source-bytes` is refused before
  it is copied. Any failure, an `Error` included, deletes the temp file before
  it propagates."
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
  "Throw a source-safe `:no-file` failure for unreadable allowed local input."
  [source-descriptor e]
  (let [path (when (= :file (:kind source-descriptor)) (:path source-descriptor))]
    (throw
     (if path
       (ex-info (if (.exists (io/file path))
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

  `source` is a filesystem path (a String, `java.io.File`, or
  `java.nio.file.Path`) or a classpath resource URL as
  `clojure.java.io/resource` returns it, whose scheme is `file:` or
  `jar:file:`. `source-descriptor` must be the value returned by
  [[descriptor]] for `source`; it is the only source representation admitted
  to failures. A file is checked in place. A jar entry is copied to an
  owner-only temporary file, and the returned cleanup function removes that
  copy. A source past `max-source-bytes` throws `:source-too-large` with the
  numeric `:limit` and `:observed`. Anything else throws `:disallowed-source`
  before it is opened, and is never rendered."
  [source source-descriptor]
  (when (nil? source)
    (throw (ex-info (str "No secrets source given: source is nil. This almost always means"
                         " (io/resource \"secrets.edn.age\") found nothing on the classpath."
                         " Check the encrypted file is present as a classpath resource. "
                         no-store-hint)
                    {:reason :no-file})))
  (let [{:keys [^java.io.File file] :as local} (local-source source source-descriptor)]
    (try
      (cond
        (nil? file) (copy-jar-entry! source-descriptor local)
        (not (.exists file)) (throw (java.io.FileNotFoundException. "No such file."))
        (> (.length file) max-source-bytes) (source-too-large! source-descriptor (.length file))
        :else [file (fn [])])
      (catch java.io.IOException e (unreadable-source! source-descriptor e)))))
