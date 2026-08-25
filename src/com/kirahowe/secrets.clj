(ns com.kirahowe.secrets
  "Runtime loading of age-encrypted EDN secrets.

  Secrets live in a single version-controlled, age-encrypted EDN file
  (`secrets.edn.age`). At runtime they are decrypted once with your age
  identity (private key) and read into a plain Clojure map. The plaintext is
  never written to disk and never committed.

  A successful decryption proves the ciphertext was readable with your
  identity, not who wrote it: age encrypts to recipients and does not sign. The
  loaded map is therefore only as trustworthy as the commit and deployment
  channel that delivered the ciphertext — see the README's authenticity
  contract and threat model.

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
  throws with the options above rather than guessing a path.

  The temp files that sources 2 and 3 materialize are this library's to clean
  up: `reset-identity-cache!` deletes them, waiting for any decryption still
  holding one, and `.deleteOnExit` is only the backstop."
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

;;; `identity-state` holds every injected identity this library materialized and
;;; the generation they belong to:
;;;
;;;     {:generation 0 :entries {digest entry} :retired {path users}}
;;;
;;; An `:entries` entry is a `delay` while its file is being written and
;;; `{:path … :users n}` once the file exists, where `:users` counts the leases
;;; [[with-identity]] holds. One atom rather than three, for the reason
;;; `com.kirahowe.secrets.aero` documents: a generation and the files that
;;; belong to it have to move together, and replacing `:entries` wholesale is
;;; the single mechanism that retires them.
;;;
;;; `:retired` is not a second mechanism — it is only where an entry waits for a
;;; lease that outlived its generation. It is keyed by path because a temp path
;;; is unique to one materialization, so it names the file a lease is holding
;;; without depending on a digest a newer generation may have re-materialized.
;;;
;;; `:generation` gives a lifecycle an identity that tests and diagnostics can
;;; name. It is deliberately not part of any key.

(defonce ^:private identity-state
  (atom {:generation 0 :entries {} :retired {}}))

(defn- delete-identity-file!
  "Delete a materialized identity file, tolerating one that is already gone.
  Prompt deletion is the lifecycle here; `.deleteOnExit` is only the backstop."
  [path]
  (.delete (io/file path)))

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
  "Write identity contents verbatim to an owner-only temp file and return its
  path.

  A failed write deletes the file it created: a partial identity nothing points
  at is exactly the residue this lifecycle exists to avoid. The failure is
  reported by exception class only, with no cause attached — the underlying
  IOException names the temp file, and a diagnostic must not."
  [contents]
  (let [file (owner-only-temp-file! "age-identity-" ".txt")]
    (try
      (spit file contents)
      (.getAbsolutePath file)
      (catch Exception e
        (.delete file)
        (throw (ex-info (str "Could not write the injected age identity to a temp file ("
                             (.getName (class e)) "). Check the temp directory is writable.")
                        {:reason :identity-not-materialized}))))))

(defn- install-identity
  "Install in-flight `candidate` at `digest`, unless this generation has an entry."
  [state digest candidate]
  (cond-> state
    (not (contains? (:entries state) digest))
    (assoc-in [:entries digest] candidate)))

(defn- promote-identity
  "Replace the in-flight `entry` at `digest` with the `path` it wrote, leaving a
  state that has since retired it untouched."
  [state digest entry path]
  (cond-> state
    (identical? entry (get-in state [:entries digest]))
    (assoc-in [:entries digest] {:path path :users 0})))

(defn- drop-identity
  "Remove the in-flight `entry` at `digest`, unless a retirement already did."
  [state digest entry]
  (cond-> state
    (identical? entry (get-in state [:entries digest]))
    (update :entries dissoc digest)))

(defn- materialize-identity!
  "Materialize identity `contents` to an owner-only temp file once per generation
  and return its path.

  Installing a delay in the same `swap!` that reads it back is what makes
  concurrent callers with identical contents share one write, and what makes a
  [[reset-identity-cache!]] that commits first send this `swap!` around again
  against the new generation rather than write into a retired one. The state
  retains only a digest and, once the write lands, the path.

  A write that throws drops the entry, and losing the promotion to a retirement
  deletes the file and materializes afresh: a file no entry points at is an
  identity nothing would ever delete."
  [contents]
  (let [digest (identity-digest contents)
        candidate (delay (write-identity! contents))
        entry (get-in (swap! identity-state install-identity digest candidate)
                      [:entries digest])]
    (if-not (delay? entry)
      (:path entry)
      (let [path (try
                   @entry
                   (catch Exception e
                     (swap! identity-state drop-identity digest entry)
                     (throw e)))
            promoted (swap! identity-state promote-identity digest entry path)]
        (if (= path (get-in promoted [:entries digest :path]))
          path
          (do (delete-identity-file! path)
              (recur contents)))))))

;;;; Identity leases and retirement

(defn- live-digest
  "The digest whose materialized entry holds `path`, or nil. Entries are keyed by
  digest while a lease names a path, so this scans: a generation holds one entry
  per distinct injected identity, and a second index would be a second thing to
  keep true."
  [entries path]
  (some (fn [[digest entry]]
          (when (and (map? entry) (= path (:path entry))) digest))
        entries))

(defn- acquire-identity!
  "Add one active user to the materialized identity at `path` and return true, or
  false when `path` is not a live materialized identity — a key file the caller
  owns, or one already retired.

  Atomic against [[reset-identity-cache!]]: either the retirement commits first
  and this returns false, or the retirement sees the user added here and leaves
  the deletion to [[release-identity!]]."
  [path]
  (let [[before] (swap-vals! identity-state
                             (fn [state]
                               (if-let [digest (live-digest (:entries state) path)]
                                 (update-in state [:entries digest :users] inc)
                                 state)))]
    (some? (live-digest (:entries before) path))))

(defn- release-user
  "Drop one active user of `path`, forgetting a retired entry whose last user is
  leaving."
  [{:keys [entries retired] :as state} path]
  (if (contains? retired path)
    (if (= 1 (get retired path))
      (update state :retired dissoc path)
      (update-in state [:retired path] dec))
    (if-let [digest (live-digest entries path)]
      (update-in state [:entries digest :users] dec)
      state)))

(defn- release-identity!
  "Release one active user of the identity at `path`, deleting the file when a
  [[reset-identity-cache!]] retired it while this user held it and this was the
  last one. That deferred deletion happens here, not at JVM exit."
  [path]
  (let [[before] (swap-vals! identity-state release-user path)]
    (when (= 1 (get (:retired before) path))
      (delete-identity-file! path))
    nil))

(defn with-identity
  "Call `(f path)` with the identity at `path` held against
  [[reset-identity-cache!]] for exactly the duration of the call, and return what
  `f` returns.

  When this library materialized `path` from `SECRETS_AGE_IDENTITY` or
  `SECRETS_AGE_IDENTITY_B64`, a retirement during the call defers its deletion
  until `f` returns, so a running `age` subprocess never reads a file that has
  been deleted underneath it. A path the caller owns is not tracked and is passed
  through untouched.

  `load-secrets` already wraps its own decryption this way, which covers the
  reader literals and the Aero readers too. Wrap any identity path you resolved
  yourself and hand to `age` directly: a path taken out of
  `resolve-identity-file` and used later sits outside every lease, and no API can
  hold a lease a caller never opened."
  [path f]
  (let [held? (acquire-identity! path)]
    (try
      (f path)
      (finally
        (when held? (release-identity! path))))))

(defn- retire-identities
  "Move `state` to a new generation: a materialized entry with an active user
  waits in `:retired` for its last release, and everything else is dropped —
  including a delay still writing, whose materialization then deletes the orphan
  no entry points at any more."
  [{:keys [generation entries retired]}]
  {:generation (inc generation)
   :entries {}
   :retired (into retired
                  (keep (fn [[_ entry]]
                          (when (and (map? entry) (pos? (:users entry)))
                            [(:path entry) (:users entry)])))
                  entries)})

(defn reset-identity-cache!
  "Retire every temp identity file this library materialized from
  `SECRETS_AGE_IDENTITY` or `SECRETS_AGE_IDENTITY_B64`: delete each one no
  decryption is using, and leave the rest to the last [[with-identity]] release
  holding them. Identity files the caller owns — `SECRETS_AGE_IDENTITY_FILE`,
  an explicit `:identity-file`, `~/.config/<app>/key.txt` — are never touched.

  This is the primary lifecycle for an injected identity, so a long-running
  process can stop keeping a private key on disk without exiting.
  `.deleteOnExit` stays only as the backstop for a process that never reaches
  here, and an abnormal exit can still leave the file behind. Idempotent: a
  second call has nothing to retire and deletes nothing. A resolution after this
  call materializes a fresh file rather than reusing a retired path.

  Returns `{:generation g :deleted n :pending n}` — the new generation, how many
  files this call deleted, and how many it retired into a decryption still in
  flight. No path, digest, or identity content is returned."
  []
  (let [[before after] (swap-vals! identity-state retire-identities)
        unused (into []
                     (keep (fn [[_ entry]]
                             (when (and (map? entry) (zero? (:users entry)))
                               (:path entry))))
                     (:entries before))]
    (run! delete-identity-file! unused)
    {:generation (:generation after)
     :deleted (count unused)
     :pending (- (count (:retired after)) (count (:retired before)))}))

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

(defn- env-identity
  "The environment's age identity as `[path materialized?]`, or nil.
  `materialized?` marks a temp file this library wrote: [[with-identity]] can
  hold one, and a diagnostic must not name one, because the caller never had it."
  []
  (or (when-let [p (identity-env "SECRETS_AGE_IDENTITY_FILE")]
        [p false])
      (when-let [c (identity-env "SECRETS_AGE_IDENTITY")]
        [(materialize-identity! c) true])
      (when-let [c (identity-env "SECRETS_AGE_IDENTITY_B64")]
        [(materialize-identity! (decode-b64-identity c)) true])))

(defn identity-from-env
  "Return an age identity file path from the environment, or nil. Sources are
  checked in order:
    $SECRETS_AGE_IDENTITY_FILE — a path to the key file, returned as-is.
    $SECRETS_AGE_IDENTITY      — the raw key file contents, used verbatim.
    $SECRETS_AGE_IDENTITY_B64  — base64-encoded key file contents (invalid base64 throws).
  A blank value throws. Raw or decoded contents are materialized into owner-only
  temp files, one per distinct value per lifecycle; `reset-identity-cache!`
  deletes them, and a path returned here is outside every [[with-identity]]
  lease until you wrap it in one."
  []
  (first (env-identity)))

(defn- conventional-identity
  "`resolve-identity-file` with provenance: `[path materialized?]`, or nil."
  [app-or-opts]
  (let [app (if (map? app-or-opts) (:app app-or-opts) app-or-opts)]
    (or (env-identity)
        (when app [(expand-home (str "~/.config/" app "/key.txt")) false]))))

(defn resolve-identity-file
  "Return the conventional identity path: `identity-from-env` first, then
  `~/.config/<app>/key.txt` when `app-or-opts` supplies an app name. Does not
  check whether the file exists. Returns nil when neither source is available."
  ([] (resolve-identity-file nil))
  ([app-or-opts] (first (conventional-identity app-or-opts))))

(defn- identity-file-exists?
  "True when `path` names an identity file that exists."
  [path]
  (boolean (and path (.exists (io/file (str path))))))

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
     (identity-file-exists? identity))))

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

;;;; Source descriptors

;;; A secrets source can itself be a credential: a signed URL keeps its
;;; signature in the query, `https://user:pass@host/store.age` keeps a password
;;; in the userinfo, and a caller's own object can render anything at all from
;;; `toString`. So no failure carries a source value — it carries a descriptor
;;; built by allowlist, and every message about a source is written from that
;;; descriptor rather than from the source.

(def ^:private max-locator-schemes
  "How many nested locator schemes a descriptor unwraps — `jar:file:` is two —
  before it keeps only the schemes it has seen. A source string can spell
  `a:b:c:…` to any depth, and describing one is bounded work."
  4)

(def ^:private uri-scheme
  "A leading URI scheme, per RFC 3986. A source string carrying one is a
  locator whose remainder may hold a credential, never a path to keep as-is."
  #"^([A-Za-z][A-Za-z0-9+.\-]*):")

(defn- parse-uri
  "`s` as a `java.net.URI`, or nil when it does not parse. The
  `URISyntaxException` is dropped rather than reported: its message quotes the
  whole string it rejected."
  [s]
  (try
    (java.net.URI. s)
    (catch Exception _ nil)))

(defn- locator-parts
  "The scheme chain of the locator string `s` and its innermost parsed URI, as
  `[schemes uri]`.

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
  "Allowlisted metadata for the locator string `s`: its scheme chain, host,
  port, and path, and nothing else. Userinfo, query, and fragment are dropped —
  a signed URL keeps its credential in the query and an embedded password in its
  userinfo — and a locator whose remainder cannot be taken apart keeps only its
  scheme.

  A *path* can carry a token too (`/t/abc123/store.age`), so keeping it is a
  judgement rather than a safe default: without it a diagnostic cannot say which
  resource failed. That residual risk is real, not zero."
  [s]
  (let [[schemes uri] (locator-parts s)
        host (some-> uri .getHost not-empty)
        path (some-> uri .getPath not-empty)
        port (or (some-> uri .getPort) -1)]
    (cond-> {:kind :url :scheme (str/join ":" schemes)}
      host (assoc :host host)
      (pos? port) (assoc :port port)
      path (assoc :path path))))

(defn- source-descriptor
  "Allowlisted metadata naming which secrets source a failure is about, safe to
  attach to an exception or render into a message.

  It is built kind by kind, never by rendering the value:

  - A URL, URI, or scheme-carrying string keeps what [[locator-descriptor]]
    keeps — scheme, host, port, path — with userinfo, query, and fragment gone.
  - A File or a path string keeps its path. That path is the caller's own, and
    naming it is most of a diagnostic's value.
  - Anything else — an InputStream, a Reader, a caller's own type — keeps only
    its class name. Nothing here calls `str` or `pr-str` on the value: a custom
    `toString` is exactly how a credential-bearing object leaks.

  `nil` describes nothing, so a nil source carries no descriptor at all."
  [source]
  (cond
    (nil? source) nil
    (instance? java.io.File source) {:kind :file :path (str source)}
    (string? source) (if (re-find uri-scheme source)
                       (locator-descriptor source)
                       {:kind :file :path source})
    (or (instance? java.net.URL source)
        (instance? java.net.URI source)) (locator-descriptor (str source))
    :else {:kind :object :class (.getName (class source))}))

(defn- source-description
  "A one-line rendering of a source `descriptor` for a message. It can say no
  more than the descriptor kept: an object contributes its class name, never its
  `toString`."
  [{:keys [kind path scheme host port] class-name :class}]
  (if (= :url kind)
    (str scheme ":" (when host (str "//" host)) (when port (str ":" port)) path)
    (or path (str "an instance of " class-name))))

;;;; Loading

(def ^:private source-chunk-bytes
  "Sources are copied in fixed 64 KiB chunks so the running total is checked
  before every further read rather than after the source is exhausted."
  65536)

(defn- source-too-large!
  "Throw the source size failure, naming only the source descriptor, the byte
  count, and the limit — never any source content."
  [descriptor read-bytes limit]
  (throw (ex-info (str "The secrets source is larger than the configured :max-source-bytes"
                       " limit of " limit " bytes.")
                  {:source descriptor
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
  [descriptor ^java.io.InputStream in ^java.io.OutputStream out limit]
  (let [chunk (byte-array source-chunk-bytes)]
    (loop [total 0]
      (let [n (.read in chunk 0 source-chunk-bytes)]
        (when-not (neg? n)
          (let [total (+ total n)]
            (when (> total limit)
              (source-too-large! descriptor total limit))
            (.write out chunk 0 n)
            (recur total)))))))

(defn- source->file
  "Coerce a secrets `source`, described by `descriptor`, to a [file cleanup!]
  pair, refusing a source larger than `limit` bytes. Path strings and Files
  naming an existing file are used in place (no cleanup), so their length is
  checked directly. Anything else that `io/input-stream` can open — any URL
  (including a jar: resource URL from inside an uberjar), an InputStream, … — is
  copied to a 0600 temp file so `age` can read it, counting bytes as it goes and
  deleting the partial copy at once if the bound is passed; cleanup deletes that
  copy."
  [source descriptor limit]
  (let [f (when (or (instance? java.io.File source) (string? source))
            (io/file source))]
    (if (and f (.exists f))
      (do
        (when (> (.length f) limit)
          (source-too-large! descriptor (.length f) limit))
        [f (fn [])])
      (let [tmp (owner-only-temp-file! "secrets-" ".age")]
        (try
          (with-open [in (io/input-stream source)
                      out (io/output-stream tmp)]
            (copy-source! descriptor in out limit))
          (catch Exception e
            (.delete tmp)
            (throw e)))
        [tmp #(.delete tmp)]))))

(def ^:private no-store-hint
  "One-line remediation appended to \"no secrets file\" errors."
  "Create it with `bb secrets new`.")

(defn- load-identity
  "The identity for one `load-secrets` call as `[path materialized?]`. An
  explicit `:identity-file`, or a bare path argument, is the caller's own file;
  anything resolved from here may be a temp file this library materialized."
  [identity-or-opts]
  (let [explicit (if (map? identity-or-opts)
                   (:identity-file identity-or-opts)
                   identity-or-opts)]
    (if explicit
      [explicit false]
      (conventional-identity (when (map? identity-or-opts) identity-or-opts)))))

(defn- validate-load-identity!
  "Throw unless `identity` names an existing file.

  A caller-supplied path is named in the failure: the caller already has it, and
  naming it is most of the message's value. A path this library materialized is
  not — the caller never saw it, and it points at a file holding key material."
  [descriptor identity materialized?]
  (let [nameable (and identity (not materialized?) (str identity))]
    (when-not (identity-file-exists? identity)
      (throw (ex-info (str "No age identity found"
                           (when nameable (str " (" nameable " does not exist)"))
                           ". " identity-options)
                      (cond-> {:reason :no-identity}
                        descriptor (assoc :source descriptor)
                        nameable (assoc :identity nameable)))))))

(defn- unreadable-source!
  "Throw the `:no-file` failure for a source `io/input-stream` could not read.

  A source that is a path is named, and the transport failure's own message and
  the exception itself travel with it: that message can only name the path,
  which the failure names anyway. For every other kind both are dropped —
  `io/input-stream` builds its message out of the value it was given, a URL in
  full or `pr-str` of a caller's object, and printing an exception prints its
  causes' messages too — so the failure carries the exception's class instead,
  which says which transport failed without quoting what it was handed."
  [descriptor e]
  (let [path (when (= :file (:kind descriptor)) (:path descriptor))]
    (throw
     (if path
       (ex-info (if (.exists (io/file path))
                  (str "Could not read secrets source " path ": " (.getMessage e))
                  (str "Secrets file not found: " path ". " no-store-hint))
                {:source descriptor :reason :no-file}
                e)
       (ex-info (str "Could not read secrets source " (source-description descriptor)
                     " (" (.getName (class e)) "). The failure's own message is withheld:"
                     " it is built from the source itself, userinfo and query included.")
                {:source descriptor :reason :no-file})))))

(defn- acquire-source!
  "Acquire a file and cleanup function for `source`, described by `descriptor`,
  under `limits`, translating read failures."
  [source descriptor limits]
  (when (nil? source)
    (throw (ex-info (str "No secrets source given: source is nil. This almost always means"
                         " (io/resource \"secrets.edn.age\") found nothing on the classpath"
                         " — check the encrypted file is present as a classpath resource. "
                         no-store-hint)
                    {:reason :no-file})))
  ;; Opening decides whether a source is readable. A String may name a path or
  ;; a URL, so checking for a missing path first would reject jar:file: URLs.
  ;; IllegalArgumentException is what `io/input-stream` raises for a source it
  ;; cannot open at all — a Reader, a caller's own type — and it reaches a
  ;; caller for the same reason an IOException does.
  (try
    (source->file source descriptor (:max-source-bytes limits))
    (catch java.io.IOException e (unreadable-source! descriptor e))
    (catch IllegalArgumentException e (unreadable-source! descriptor e))))

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
  "Decrypt and read `file` under `opts` — `:limits`, the `:source` descriptor,
  and whether the identity is `:materialized-identity?` — always running its
  source cleanup function.

  A failure below here knows the file `age` was handed, which for a copied
  source is a temp file the caller never named, so it is re-thrown with the
  source descriptor added and the original as its cause. Message, `:reason`, and
  every other key are carried through unchanged: this adds the context the layer
  below could not have, it does not restate the failure."
  [identity file {:keys [limits source materialized-identity?]} cleanup!]
  (try
    (read-secrets-edn (age/decrypt identity (.getAbsolutePath ^java.io.File file)
                                   {:limits limits
                                    :identity-nameable? (not materialized-identity?)})
                      limits)
    (catch clojure.lang.ExceptionInfo e
      (throw (ex-info (ex-message e) (assoc (ex-data e) :source source) e)))
    (finally
      (cleanup!))))

(defn- load-from
  "Load `source` with the already-resolved identity `[path materialized?]` under
  `limits`.

  Provenance travels with the path rather than being re-derived: nothing can
  recover from a path alone whether the caller supplied it or this library
  materialized it from an injected key, and every diagnostic below here turns on
  that difference."
  [source [identity materialized?] limits]
  (let [descriptor (source-descriptor source)]
    (with-identity identity
      (fn [path]
        (validate-load-identity! descriptor path materialized?)
        (let [[file cleanup!] (acquire-source! source descriptor limits)]
          (decrypt-and-read! path file
                             {:limits limits
                              :source descriptor
                              :materialized-identity? materialized?}
                             cleanup!))))))

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
  is read with `clojure.edn`, not `eval`.

  Every failure about a source carries `:source`, allowlisted metadata naming
  which source failed — a locator's scheme, host, port, and path, a file's path,
  or an object's class — and never the source value, whose userinfo, query, or
  `toString` can be a credential. An identity path is named only when the caller
  supplied it.

  The identity is held with [[with-identity]] for the whole call, so a
  `reset-identity-cache!` cannot delete an injected identity while `age` is
  reading it. That covers the reader literals and the Aero readers, which load
  through here."
  ([source] (load-secrets source nil))
  ([source identity-or-opts]
   (let [limits (resolve-limits (when (map? identity-or-opts) (:limits identity-or-opts)))]
     (load-from source (load-identity identity-or-opts) limits))))

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
  describe why it is unavailable.

  `identity` is a delay over `[path materialized?]`, and it is loaded through
  [[load-from]] rather than [[load-secrets]] for that pair's sake: passing the
  path back in as an explicit `:identity-file` would relabel a path this library
  materialized as one the caller supplied, and diagnostics would then name it."
  [{:keys [resource file limits]} identity]
  (let [source (cond
                 file (when (.exists (io/file (str file)))
                        (io/file (str file)))
                 resource (io/resource resource))]
    (cond
      (nil? source)
      {:present? false :reason :no-file}

      (not (identity-file-exists? (first @identity)))
      {:present? false :reason :no-identity}

      :else
      {:present? true :secrets (load-from source @identity limits)})))

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
        identity (delay (if identity-file
                          [identity-file false]
                          (conventional-identity app)))
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
