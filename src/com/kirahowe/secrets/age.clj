(ns com.kirahowe.secrets.age
  "A thin wrapper over the `age` CLI (https://age-encryption.org).

  Every function shells out to the `age` / `age-keygen` binaries, so this
  namespace loads and runs identically under JVM Clojure and babashka. It holds
  no state and takes no opinion about *where* keys or secrets live — that is the
  caller's job (see `com.kirahowe.secrets` for runtime loading and `com.kirahowe.secrets.cli`
  for the management task).

  `age` is a small, audited, modern file-encryption tool. A keypair is an
  identity file (the private key, `AGE-SECRET-KEY-1…`) plus a recipient (the
  public key, `age1…`). Encrypting to your own identity (`age -e -i key.txt`)
  gives a single-key workflow: the same file both encrypts and decrypts.

  age encrypts *to* a recipient and does not sign. A recipient is shareable by
  design and authorizes *encryption*, not authorship, so nothing here — and
  nothing built on it — can establish who produced a ciphertext."
  (:require [clojure.java.io :as io]
            [clojure.java.shell :as shell]
            [clojure.string :as str]))

(defn version
  "Return the installed `age` version string, or nil when `age` is unavailable
  or its version query fails. Only successful version output is returned:
  subprocess arguments, environment, and failure details are never exposed."
  []
  (try
    (let [{:keys [exit out err]} (shell/sh "age" "--version")]
      (when (zero? exit)
        (let [s (str/trim (if (str/blank? out) err out))]
          (when-not (str/blank? s) s))))
    (catch Exception _ nil)))

(defn installed?
  "Return true when the `age` binary is on the PATH (the decrypt path needs only this)."
  []
  (some? (version)))

(defn ensure-installed!
  "Throw a helpful ex-info unless `age` is installed."
  []
  (when-not (installed?)
    (throw (ex-info "The `age` encryption tool is not installed."
                    {:tool "age"
                     :install "macOS: brew install age  •  Debian/Ubuntu: apt install age"
                     :docs "https://age-encryption.org"}))))

(defn public-key
  "Extract the public key (recipient) from an age identity file's
  `# public key:` header line. Returns nil if the file is missing or has no
  such line."
  [identity-file]
  (let [f (io/file (str identity-file))]
    (when (.exists f)
      (some #(second (re-find #"(?i)public key:\s*(\S+)" %))
            (str/split-lines (slurp f))))))

(defn valid-recipient?
  "Return true when `s` looks like an age recipient (an `age1…` public key, or
  an `ssh-ed25519`/`ssh-rsa` line). This is not a full validation: `age` itself
  is the authority; this just catches obvious typos before writing a keys file."
  [s]
  (let [s (str/trim (str s))]
    (boolean (or (re-matches #"age1[0-9a-z]{20,}" s)
                 (re-matches #"ssh-(ed25519|rsa) .+" s)))))

(defn- path-arg
  "Render `p`, the path argument playing `role`, as an age argument that can
  only mean a filesystem path.

  An option terminator is not enough on its own: age reads a positional `-`
  (and an `-i`/`-R` value of `-`) from stdin and writes `-o -` to stdout, and a
  blank path resolves to stdin rather than to a file. `./` names the same file
  without the ambiguity; an absolute path never begins with `-`. Blank fails
  closed naming its role, the way a blank identity variable does — a blank
  input would otherwise exit 0 with a ciphertext of nothing, and CI is where
  an unset variable expands to nothing."
  ^String [role p]
  (let [s (str p)]
    (when (str/blank? s)
      (throw (ex-info (str "age " (name role) " path is blank") {:argument role :path s})))
    (if (str/starts-with? s "-")
      (str "./" s)
      s)))

(defn keygen!
  "Generate a fresh age identity at `path`, creating parent directories and
  tightening the file to owner-only permissions. Returns the public key.

  Replaces `path` when it already exists, so callers own the decision about
  whether overwriting is allowed. `age-keygen -o` refuses to open an existing
  output file, so the key is generated inside a sibling temp directory and
  moved over `path` only once it succeeds — a failed generation leaves any
  existing key untouched. Throws if `path` is blank, or if `age-keygen` is
  missing or fails."
  [path]
  (let [f (.getAbsoluteFile (io/file (path-arg :key path)))
        parent (.getParentFile f)]
    (.mkdirs parent)
    (let [tmp-dir (java.nio.file.Files/createTempDirectory
                   (.toPath parent) (str "." (.getName f) ".keygen")
                   (into-array java.nio.file.attribute.FileAttribute []))
          tmp (.toFile (.resolve tmp-dir (.getName f)))]
      (try
        (let [{:keys [exit err]} (try
                                   (shell/sh "age-keygen" "-o" (str tmp))
                                   (catch java.io.IOException _
                                     {:exit 127 :err "age-keygen not found on PATH"}))]
          (when-not (zero? exit)
            (throw (ex-info "age-keygen failed"
                            {:path (str path) :error err
                             :install "macOS: brew install age"})))
          (doto tmp
            (.setReadable false false) (.setReadable true true)
            (.setWritable false false) (.setWritable true true))
          ;; Same directory, so this is a rename(2): the old key is never
          ;; observable as a half-written file.
          (java.nio.file.Files/move
           (.toPath tmp) (.toPath f)
           (into-array java.nio.file.CopyOption
                       [java.nio.file.StandardCopyOption/REPLACE_EXISTING]))
          (public-key f))
        (finally
          ;; Never let cleanup mask a genuine age-keygen failure.
          (try
            (.delete tmp)
            (java.nio.file.Files/deleteIfExists tmp-dir)
            (catch Exception _ nil)))))))

(defn encrypt-file!
  "Encrypt plaintext file `in` to ciphertext file `out`. Returns `out`; throws
  on failure.

  `recipients` selects who can decrypt. It is either:
    • a bare String/File — always an identity-*file path*: encrypt to that
      identity's own recipient (`age -e -i`), the single-key workflow. A bare
      `age1…` public-key string throws — pass those as `{:recipients [\"age1…\"]}`
      (age would otherwise try to read the key as a file path); or
    • a map with any of, whose recipients are unioned:
        :identity-file    encrypt to this identity's own recipient (`-i`)
        :recipients-file  path to a file of age public keys, one per line (`-R`)
        :recipients       a seq of age recipient strings (`-r` each)

  Multi-recipient encryption (`:recipients-file` / `:recipients`) lets each
  person hold their *own* key: any one of the listed recipients can decrypt."
  [recipients in out]
  (when (and (string? recipients) (valid-recipient? recipients))
    (throw (ex-info (str "encrypt-file! got a bare public key, but a bare "
                         "recipients value means an identity-file path. Pass "
                         "public keys as {:recipients [\"age1…\"]}.")
                    {:recipients recipients})))
  (let [recipient-spec (if (map? recipients)
                         recipients
                         {:identity-file recipients})
        {:keys [identity-file recipients-file] rs :recipients} recipient-spec
        identity-file? (contains? recipient-spec :identity-file)
        recipients-file? (contains? recipient-spec :recipients-file)
        argv (cond-> ["age" "-e"]
               identity-file? (conj "-i" (path-arg :identity identity-file))
               recipients-file? (conj "-R" (path-arg :recipients-file recipients-file)))
        argv (reduce (fn [argv recipient]
                       (-> argv
                           (conj "-r")
                           (conj (str recipient))))
                     argv
                     rs)
        argv (-> argv
                 (conj "-o")
                 (conj (path-arg :output out))
                 (conj "--")
                 (conj (path-arg :input in)))]
    ;; Local argument validation first: probing the environment must not be
    ;; able to mask a path that never named a file.
    (ensure-installed!)
    (let [{:keys [exit err]} (apply shell/sh argv)]
      (when-not (zero? exit)
        (throw (ex-info "age encryption failed" {:out (str out) :error err})))
      out)))

(def default-max-plaintext-bytes
  "Default bound, in bytes, on the plaintext one decryption may produce (8 MiB).

  It exists so a hostile or accidentally enormous ciphertext fails fast instead
  of exhausting the process: the bound is checked while `age` is still writing,
  not after a complete plaintext has been allocated. Override it per call with
  `{:limits {:max-plaintext-bytes n}}`; `com.kirahowe.secrets` carries the same
  value as one of its runtime `:limits`."
  8388608)

(def ^:private capture-chunk-bytes
  "Plaintext is drained in fixed 64 KiB chunks so the running total is checked
  before every further read rather than after the whole output exists."
  65536)

(defn- plaintext-limit
  "Resolve the plaintext byte bound from the optional trailing options map
  `opts`, rejecting anything a later read would silently see as the default."
  [opts]
  (let [limits (:limits opts)]
    (when-not (or (nil? limits) (map? limits))
      (throw (ex-info "age :limits must be a map of limit name → positive integer."
                      {:limits limits :reason :invalid-limit})))
    (let [n (get limits :max-plaintext-bytes default-max-plaintext-bytes)]
      (when-not (and (integer? n) (pos? n))
        (throw (ex-info (str "age :limits :max-plaintext-bytes must be a positive integer, got "
                             (pr-str n) ".")
                        {:limit :max-plaintext-bytes :value n :reason :invalid-limit})))
      n)))

(defn- destroy-process!
  "Terminate `process`, escalating to a forcible kill when it does not exit
  within a short bounded wait. A process still writing plaintext nobody will
  read has to stop, not linger."
  [^java.lang.Process process]
  (.destroy process)
  (when-not (.waitFor process 2 java.util.concurrent.TimeUnit/SECONDS)
    (.destroyForcibly process)
    (.waitFor process 2 java.util.concurrent.TimeUnit/SECONDS))
  nil)

(defn- read-bounded!
  "Read `in` to its end and return the bytes, refusing an input larger than
  `max-bytes`.

  The running total is checked before every further read, so an oversized input
  is refused while it is still arriving rather than after all of it has been
  allocated. On refusal the partial buffer is discarded and the thrown ex-info
  carries `context`, the byte count, and the limit, never a captured byte."
  ^bytes [^java.io.InputStream in max-bytes context]
  (let [captured (java.io.ByteArrayOutputStream.)
        chunk (byte-array capture-chunk-bytes)]
    (loop [total 0]
      (let [n (.read in chunk 0 capture-chunk-bytes)]
        (if (neg? n)
          (.toByteArray captured)
          (let [total (+ total n)]
            (when (> total max-bytes)
              ;; Discard what was captured before unwinding: the partial
              ;; plaintext stays unreachable through the stream, the buffer is
              ;; garbage the moment this frame goes, and nothing captured is
              ;; attached to the exception.
              (.reset captured)
              (throw (ex-info (str "Decrypted plaintext is larger than the configured "
                                   ":max-plaintext-bytes limit of " max-bytes " bytes.")
                              (assoc context
                                     :bytes total
                                     :limit max-bytes
                                     :reason :plaintext-too-large))))
            (.write captured chunk 0 n)
            (recur total)))))))

(defn- capture-bounded-stdout!
  "Run `argv`, returning `{:exit n :out bytes :err s}` the way
  `clojure.java.shell/sh` does, but refusing an output larger than `max-bytes`.

  `sh` cannot express that bound: it materializes the complete output before any
  caller can look at its size. Here stdout is drained through [[read-bounded!]]
  instead, and passing the bound kills the process on the way out. stderr is
  drained on its own thread because a process that fills the stderr pipe while
  nobody reads it deadlocks."
  [argv max-bytes context]
  (let [process (.start (java.lang.ProcessBuilder. ^java.util.List (vec argv)))
        stderr (future (slurp (.getErrorStream process)))]
    (try
      ;; Nothing here writes to the child, so give it EOF on stdin at once
      ;; rather than leaving it able to block on a pipe no one will fill.
      (.close (.getOutputStream process))
      (let [out (with-open [stdout (.getInputStream process)]
                  (read-bounded! stdout max-bytes context))]
        {:exit (.waitFor process) :out out :err @stderr})
      (finally
        (when (.isAlive process)
          (destroy-process! process))))))

(defn- decrypt-argv
  "Build the `age -d` argv decrypting `encrypted-file` with `identity-file`.
  Both paths go through `path-arg` and `--` sits immediately before the
  positional input, so no path can be read as an option or as stdin."
  [identity-file encrypted-file]
  ["age" "-d" "-i" (path-arg :identity identity-file)
   "--" (path-arg :input encrypted-file)])

(defn decrypt-bytes
  "Decrypt `encrypted-file` with `identity-file`; return the plaintext as a
  byte array (binary-safe — age encrypts arbitrary files, not just text).
  Throws an ex-info (with the captured stderr) on failure.

  Success establishes that the ciphertext is intact and that `identity-file`
  matches one of its recipients. It does not identify who encrypted it: age
  does not sign, so this is payload integrity, never sender authenticity.

  `opts` may carry `{:limits {:max-plaintext-bytes n}}`, defaulting to
  `default-max-plaintext-bytes`. The bound is enforced while `age` is writing:
  an oversized plaintext kills the subprocess and throws with
  `:reason :plaintext-too-large` instead of being allocated in full first."
  (^bytes [identity-file encrypted-file] (decrypt-bytes identity-file encrypted-file nil))
  (^bytes [identity-file encrypted-file opts]
   (let [argv (decrypt-argv identity-file encrypted-file)
         max-bytes (plaintext-limit opts)
         context {:identity-file (str identity-file)
                  :encrypted-file (str encrypted-file)}]
     (ensure-installed!)
     (let [{:keys [exit out err]} (capture-bounded-stdout! argv max-bytes context)]
       (if (zero? exit)
         out
         (throw (ex-info "age decryption failed"
                         (assoc context
                                :error err
                                :hint (str "Wrong key, or you are not a recipient of "
                                           "this file.")))))))))

(defn decrypt
  "Decrypt `encrypted-file` with `identity-file`; return the plaintext as a
  UTF-8 string. Use `decrypt-bytes` for binary plaintexts. Throws an ex-info
  (with the captured stderr) on failure. `opts` carries `:limits` exactly as
  `decrypt-bytes` does."
  ([identity-file encrypted-file] (decrypt identity-file encrypted-file nil))
  ([identity-file encrypted-file opts]
   (String. (decrypt-bytes identity-file encrypted-file opts) "UTF-8")))

(def ^:private no-follow-links
  (into-array java.nio.file.LinkOption [java.nio.file.LinkOption/NOFOLLOW_LINKS]))

(def ^:private staging-write-options
  (into-array java.nio.file.OpenOption
              [java.nio.file.StandardOpenOption/WRITE
               java.nio.file.StandardOpenOption/TRUNCATE_EXISTING
               java.nio.file.LinkOption/NOFOLLOW_LINKS]))

(def ^:private owner-only
  #{java.nio.file.attribute.PosixFilePermission/OWNER_READ
    java.nio.file.attribute.PosixFilePermission/OWNER_WRITE})

(defn- plaintext-destination
  "Resolve `out` to the absolute regular-file destination that plaintext may be
  published to, or throw.

  Only the *final* path component is checked, and it is checked without
  following links. A symlinked parent is legitimate — macOS temp directories
  live under `/var`, itself a link to `/private/var`, so rejecting parent links
  would reject every ordinary caller — while a linked or otherwise non-regular
  final component would redirect plaintext outside the selected directory
  (CWE-59). The path is deliberately never canonicalized: `getCanonicalPath`
  and `toRealPath` resolve a final link *away*, which would defeat exactly the
  check being made. `Files/exists` with NOFOLLOW_LINKS is true of a dangling
  link, so those fail closed too. `path-arg` gives a blank or nil `out` the
  same `blank` failure every other age path role has."
  ^java.io.File [out]
  (let [f (.getAbsoluteFile (io/file (path-arg :output out)))
        parent (.getParentFile f)]
    (when (or (nil? parent) (not (.isDirectory parent)))
      (throw (ex-info (str "The plaintext destination directory is missing or not a directory: "
                           parent)
                      {:destination (str out) :directory (str parent)})))
    (when (and (java.nio.file.Files/exists (.toPath f) no-follow-links)
               (not (java.nio.file.Files/isRegularFile (.toPath f) no-follow-links)))
      (throw (ex-info (str "Refusing to publish plaintext over a symlink or other non-regular "
                           "file: " f)
                      {:destination (str out)
                       :symlink? (java.nio.file.Files/isSymbolicLink (.toPath f))})))
    f))

(defn- owner-only-staging-file!
  "Create a file beside `dest` that is owner-only (0600) from the instant it
  exists, and return it.

  `createTempFile` opens `CREATE_NEW` with a random infix and applies the
  permissions as a *creation* attribute, so the mode never depends on umask and
  a pre-planted file or link sharing the prefix and suffix can never be the file
  we write. The permissions are then read back with NOFOLLOW_LINKS and compared:
  a filesystem that silently widens them, or that cannot report them at all,
  has to fail closed *before* any plaintext exists rather than after."
  ^java.io.File [^java.io.File dest]
  (let [staging (try
                  (.toFile
                   (java.nio.file.Files/createTempFile
                    (.toPath (.getParentFile dest))
                    (str "." (.getName dest) ".") ".plaintext"
                    (into-array java.nio.file.attribute.FileAttribute
                                [(java.nio.file.attribute.PosixFilePermissions/asFileAttribute
                                  owner-only)])))
                  (catch UnsupportedOperationException e
                    (throw (ex-info (str "This filesystem cannot create an owner-only plaintext "
                                         "file, so writing plaintext to disk fails closed rather "
                                         "than using default permissions. Use `decrypt-bytes` or "
                                         "`decrypt`, which never touch the filesystem.")
                                    {:destination (str dest)}
                                    e))))
        permissions (try
                      (set (java.nio.file.Files/getPosixFilePermissions
                            (.toPath staging) no-follow-links))
                      (catch Exception e
                        (.delete staging)
                        (throw (ex-info (str "Cannot verify owner-only permissions on the "
                                             "plaintext staging file, so no plaintext is written. "
                                             "Use `decrypt-bytes` or `decrypt` instead.")
                                        {:destination (str dest)}
                                        e))))]
    (when-not (= owner-only permissions)
      (.delete staging)
      (throw (ex-info (str "The plaintext staging file is not owner-only, so no plaintext is "
                           "written. Use `decrypt-bytes` or `decrypt` instead.")
                      {:destination (str dest)
                       :permissions (sort (map str permissions))})))
    staging))

(defn- publish-plaintext!
  "Atomically replace `dest` with the staged plaintext file `staging`.

  Same directory, so this is a rename(2): `dest` is never observable as a
  half-written or permissively-moded plaintext file, and it keeps its previous
  contents until the move succeeds. `Files/move` replaces a symbolic link
  *itself* rather than following it, so even a destination that turns into a
  link after validation cannot receive plaintext through the link. There is
  deliberately no non-atomic copy fallback: copying is what would reopen that
  window."
  [^java.io.File staging ^java.io.File dest]
  (try
    (java.nio.file.Files/move
     (.toPath staging) (.toPath dest)
     (into-array java.nio.file.CopyOption
                 [java.nio.file.StandardCopyOption/ATOMIC_MOVE
                  java.nio.file.StandardCopyOption/REPLACE_EXISTING]))
    (catch Exception e
      ;; Babashka does not expose AtomicMoveNotSupportedException as a
      ;; resolvable class, so identify this one portable NIO exception by name.
      (if (= "java.nio.file.AtomicMoveNotSupportedException" (.getName (class e)))
        (throw (ex-info (str "The filesystem cannot atomically publish plaintext to " dest)
                        {:destination (str dest)}
                        e))
        (throw e)))))

(defn decrypt-to-file!
  "Decrypt `encrypted-file` to plaintext file `out`, byte-for-byte (binary
  content is preserved). Returns `out`.

  Plaintext reaches the filesystem only through an owner-only (0600) staging
  file beside `out`, which is then atomically moved over it. So the published
  file is 0600 whatever the umask and whatever mode `out` had before, and no
  permissive or partial plaintext is ever observable at `out`. The destination's
  final component is validated without following links, so a symlink or other
  non-regular destination is refused rather than written through. Decryption
  runs before any staging file exists — a wrong key, or a plaintext past the
  `:max-plaintext-bytes` bound in `opts`, therefore never creates one — and any
  later failure removes the staging plaintext and leaves the previous `out`
  intact.

  A filesystem without POSIX permissions fails closed instead of writing
  plaintext with default permissions: use `decrypt-bytes` or `decrypt`, which
  never write plaintext to disk."
  ([identity-file encrypted-file out]
   (decrypt-to-file! identity-file encrypted-file out nil))
  ([identity-file encrypted-file out opts]
   (let [dest (plaintext-destination out)
         plaintext (decrypt-bytes identity-file encrypted-file opts)
         staging (owner-only-staging-file! dest)]
     (try
       ;; NOFOLLOW_LINKS here is defence in depth: it refuses the open if the
       ;; staging name were swapped for a link between creation and write.
       (java.nio.file.Files/write (.toPath staging) ^bytes plaintext staging-write-options)
       (publish-plaintext! staging dest)
       (catch Exception e
         (try (.delete staging) (catch Exception _ nil))
         (throw e)))
     out)))
