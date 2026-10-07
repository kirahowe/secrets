(ns com.kirahowe.secrets.source
  "Local-only, bounded acquisition of encrypted secrets sources.

  Source values may themselves contain credentials, so diagnostics cross this
  boundary only as allowlisted descriptors. Acquisition accepts filesystem
  sources and strict local `file:` or `jar:file:` locators, never caller-provided
  URL handlers or arbitrary `clojure.java.io` dispatch, and enforces the byte
  bound while data moves."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [com.kirahowe.secrets.fs :as fs]))

(def ^:private max-locator-schemes
  "How many nested locator schemes a descriptor unwraps — `jar:file:` is two —
  before it keeps only the schemes it has seen. A source string can spell
  `a:b:c:…` to any depth, and describing one is bounded work."
  4)

(def ^:private uri-scheme
  "A leading URI scheme, per RFC 3986. A source string carrying one is a
  locator whose remainder may hold a credential, never a path to keep as-is."
  #"^([A-Za-z][A-Za-z0-9+.\-]*):")

(def ^:private windows-absolute-path
  "A Windows drive path, which is a path rather than a one-letter URI scheme."
  #"(?i)^[a-z]:[\\/]")

(def ^:private source-chunk-bytes
  "Sources are copied in fixed 64 KiB chunks so the running total is checked
  before every further read rather than after the source is exhausted."
  65536)

(def ^:private no-store-hint
  "One-line remediation appended to no-secrets-file errors."
  "Create it with `bb secrets new`.")

(defn locator-scheme
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

(defn- parse-uri
  "Return `s` as a `java.net.URI`, or nil when it does not parse.

  The `URISyntaxException` is dropped rather than reported because its message
  quotes the whole string it rejected."
  [s]
  (try
    (java.net.URI. s)
    (catch Exception _ nil)))

(defn- url->uri
  "Rebuild `url` from field getters without invoking its URLStreamHandler."
  [^java.net.URL url]
  (let [scheme (.getProtocol url)
        user-info (.getUserInfo url)
        host (not-empty (.getHost url))
        port (.getPort url)
        authority? (or user-info host (pos? port))]
    (parse-uri
     (str scheme ":"
          (when authority?
            (str "//" (when user-info (str user-info "@")) host
                 (when (pos? port) (str ":" port))))
          (.getPath url)
          (when-let [query (.getQuery url)] (str "?" query))
          (when-let [fragment (.getRef url)] (str "#" fragment))))))

(defn- locator-parts
  "Return the scheme chain and innermost parsed URI for locator string `s`.

  An opaque URI wraps another locator (`jar:file:/app.jar!/store.age`), and each
  wrapper contributes only its scheme. Unwrapping stops at a part that is not
  opaque, does not parse, or carries no scheme, and at `max-locator-schemes`
  either way."
  [s]
  (loop [s s schemes []]
    (let [scheme (second (re-find uri-scheme s))
          uri (when scheme (parse-uri s))
          schemes (cond-> schemes scheme (conj scheme))]
      (if (and uri (.isOpaque uri) (< (count schemes) max-locator-schemes))
        (recur (.getSchemeSpecificPart uri) schemes)
        [schemes uri]))))

(defn- locator-descriptor
  "Build allowlisted metadata for locator string `s`.

  Scheme chain, host, port, and path may be retained. Userinfo, query, and
  fragment are always dropped because they commonly hold credentials. A path
  can hold a token too, but retaining it is necessary to identify a failing
  resource; that residual diagnostic risk is explicit."
  [s]
  (let [[schemes uri] (locator-parts (str/trim s))
        host (some-> uri .getHost not-empty)
        path (some-> uri .getPath not-empty)
        port (or (some-> uri .getPort) -1)]
    (cond-> {:kind :url :scheme (str/join ":" schemes)}
      host (assoc :host host)
      (pos? port) (assoc :port port)
      path (assoc :path path))))

(defn descriptor
  "Return allowlisted metadata naming `source` without rendering secret data.

  URL, URI, and scheme-carrying string descriptors retain only scheme, host,
  port, and path; userinfo, query, and fragment are dropped. File, Path, and
  plain path strings retain their path. Any other value retains only its class
  name, never its `toString`; `nil` has no descriptor. The result is safe for
  exception data and diagnostics under this namespace's explicit allowlist."
  [source]
  (cond
    (nil? source) nil
    (instance? java.io.File source) {:kind :file :path (str source)}
    (instance? java.nio.file.Path source) {:kind :file :path (str source)}
    (string? source) (if (locator-scheme source)
                       (locator-descriptor source)
                       {:kind :file :path source})
    (instance? java.net.URL source)
    (if-let [uri (url->uri source)]
      (locator-descriptor (str uri))
      {:kind :url :scheme (.getProtocol ^java.net.URL source)})
    (instance? java.net.URI source) (locator-descriptor (str source))
    :else {:kind :object :class (.getName (class source))}))

(defn- source-description
  "Render one diagnostic line from `source-descriptor` and nothing else."
  [{:keys [kind path scheme host port] class-name :class}]
  (if (= :url kind)
    (str scheme ":" (when host (str "//" host)) (when port (str ":" port)) path)
    (or path (str "an instance of " class-name))))

(defn- disallowed-source!
  "Reject `source-descriptor` before opening or resolving its source."
  [source-descriptor]
  (throw
   (ex-info
    (str "Secrets sources are local-only. Expected a filesystem path, File, Path,"
         " local file: locator, or jar:file: classpath resource; "
         (source-description source-descriptor) " is not permitted.")
    {:source source-descriptor :reason :disallowed-source})))

(defn- local-file-uri?
  "True when `uri` is an absolute local `file:` URI with no authority or suffix."
  [^java.net.URI uri]
  (and (= "file" (some-> (.getScheme uri) str/lower-case))
       (not (.isOpaque uri))
       (nil? (.getRawAuthority uri))
       (nil? (.getRawQuery uri))
       (nil? (.getRawFragment uri))
       (seq (.getRawPath uri))))

(defn- decode-jar-entry
  "Decode a jar entry's raw URI path without treating `+` as form-encoded space."
  [raw-entry]
  (when (seq raw-entry)
    (try
      (java.net.URLDecoder/decode (str/replace raw-entry "+" "%2B") "UTF-8")
      (catch IllegalArgumentException _ nil))))

(defn- jar-file-source
  "Return the local archive and entry named by a strict `jar:file:` `uri`."
  [^java.net.URI uri]
  (when (and (= "jar" (some-> (.getScheme uri) str/lower-case))
             (.isOpaque uri)
             (nil? (.getRawFragment uri)))
    (let [raw (.getRawSchemeSpecificPart uri)
          separator (.indexOf ^String raw "!/")]
      (when (pos? separator)
        (let [archive-uri (parse-uri (subs raw 0 separator))
              entry (decode-jar-entry (subs raw (+ separator 2)))]
          (when (and archive-uri (local-file-uri? archive-uri) entry)
            {:archive (io/file archive-uri) :entry entry}))))))

(defn- locator-source
  "Turn an allowed local locator `uri` into a source spec, or nil."
  [^java.net.URI uri]
  (case (some-> (.getScheme uri) str/lower-case)
    "file" (when (local-file-uri? uri) {:file (io/file uri)})
    "jar" (jar-file-source uri)
    nil))

(defn- local-source
  "Classify `source` without opening it, rejecting anything outside local policy."
  [source source-descriptor]
  (or
   (cond
     (instance? java.io.File source) {:file source}
     (instance? java.nio.file.Path source) {:file (.toFile ^java.nio.file.Path source)}
     (string? source) (if (locator-scheme source)
                        (some-> source parse-uri locator-source)
                        {:file (io/file source)})
     (instance? java.net.URI source) (locator-source source)
     (instance? java.net.URL source) (some-> source url->uri locator-source))
   (disallowed-source! source-descriptor)))

(defn- source-too-large!
  "Throw a content-free source-size failure."
  [source-descriptor read-bytes limit]
  (throw (ex-info (str "The secrets source is larger than the configured :max-source-bytes"
                       " limit of " limit " bytes.")
                  {:source source-descriptor
                   :bytes read-bytes
                   :limit limit
                   :reason :source-too-large})))

(defn- copy-source!
  "Copy `in` to `out` in fixed chunks without writing beyond `limit` bytes."
  [source-descriptor ^java.io.InputStream in ^java.io.OutputStream out limit]
  (let [chunk (byte-array source-chunk-bytes)]
    (loop [total 0]
      (let [n (.read in chunk 0 source-chunk-bytes)]
        (when-not (neg? n)
          (let [total (+ total n)]
            (when (> total limit)
              (source-too-large! source-descriptor total limit))
            (.write out chunk 0 n)
            (recur total)))))))

(defn- copy-jar-source!
  "Copy one local jar `source` entry to `out` under `limit`."
  [source-descriptor {:keys [archive entry]} ^java.io.OutputStream out limit]
  (with-open [jar (java.util.jar.JarFile. ^java.io.File archive)]
    (if-let [jar-entry (.getJarEntry jar entry)]
      (with-open [in (.getInputStream jar jar-entry)]
        (copy-source! source-descriptor in out limit))
      (throw (java.io.FileNotFoundException. "Classpath jar resource not found.")))))

(defn- copy-local-source!
  "Copy a local source spec to an owner-only temp file under `limit`. Any
  failure, an `Error` included, deletes the temp file before it propagates."
  [source-descriptor {:keys [file] :as source} limit]
  (let [tmp (fs/owner-only-temp-file! "secrets-" ".age")]
    (try
      (with-open [out (io/output-stream tmp)]
        (if file
          (with-open [in (io/input-stream file)]
            (copy-source! source-descriptor in out limit))
          (copy-jar-source! source-descriptor source out limit)))
      [tmp #(.delete tmp)]
      (catch Throwable t
        (.delete tmp)
        (throw t)))))

(defn- source->file
  "Resolve `source` under local-only policy to a `[file cleanup!]` pair."
  [source source-descriptor limit]
  (let [{:keys [file] :as local} (local-source source source-descriptor)]
    (if (and file (.exists ^java.io.File file))
      (do
        (when (> (.length ^java.io.File file) limit)
          (source-too-large! source-descriptor (.length ^java.io.File file) limit))
        [file (fn [])])
      (copy-local-source! source-descriptor local limit))))

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
                     " (" (.getName (class e)) "). The failure's own message is withheld:"
                     " it is built from the source itself, userinfo and query included.")
                {:source source-descriptor :reason :no-file})))))

(defn acquire!
  "Acquire local `source` under `limit` bytes as `[file cleanup!]`.

  `source-descriptor` must be the value returned by [[descriptor]] for `source`;
  it is the only source representation admitted to failures. Existing files are
  checked in place. Strict local `jar:file:` entries are streamed to an
  owner-only temporary file while the byte count is enforced, and the returned
  cleanup function removes that copy. Nil, remote, malformed, and arbitrary
  object sources fail without invoking caller-provided URL handlers or rendering
  source data."
  [source source-descriptor limit]
  (when (nil? source)
    (throw (ex-info (str "No secrets source given: source is nil. This almost always means"
                         " (io/resource \"secrets.edn.age\") found nothing on the classpath"
                         " — check the encrypted file is present as a classpath resource. "
                         no-store-hint)
                    {:reason :no-file})))
  (try
    (source->file source source-descriptor limit)
    (catch java.io.IOException e (unreadable-source! source-descriptor e))
    (catch IllegalArgumentException e (unreadable-source! source-descriptor e))))
