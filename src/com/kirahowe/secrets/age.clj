(ns com.kirahowe.secrets.age
  "A thin wrapper over the `age` CLI (https://age-encryption.org).

  Every function shells out to the `age` / `age-keygen` binaries, so this
  namespace loads and runs identically under JVM Clojure and babashka. It holds
  no state and takes no opinion about *where* keys or secrets live. That is the
  caller's job (see `com.kirahowe.secrets` for runtime loading and `com.kirahowe.secrets.cli`
  for the management task).

  `age` is a small, audited, modern file-encryption tool. A keypair is an
  identity file (the private key, `AGE-SECRET-KEY-1…`) plus a recipient (the
  public key, `age1…`). Encrypting to your own identity (`age -e -i key.txt`)
  gives a single-key workflow: the same file both encrypts and decrypts.

  age encrypts *to* a recipient and does not sign. A recipient is shareable by
  design and authorizes *encryption*, not authorship, so nothing here, and
  nothing built on it, can establish who produced a ciphertext."
  (:require [clojure.java.io :as io]
            [clojure.java.shell :as shell]
            [clojure.string :as str]
            [com.kirahowe.secrets.fs :as fs]))

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
                    {:reason :age-not-installed
                     :tool "age"
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
  closed naming its role, the way a blank identity variable does. A blank
  input would otherwise exit 0 with a ciphertext of nothing, and CI is where
  an unset variable expands to nothing."
  ^String [role p]
  (let [s (str p)]
    (when (str/blank? s)
      (throw (ex-info (str "age " (name role) " path is blank")
                      {:reason :blank-path :argument role :path s})))
    (if (str/starts-with? s "-")
      (str "./" s)
      s)))

(defn keygen!
  "Generate a fresh age identity at `path`, creating parent directories, and
  return its public key. The key file is owner-only (0600).

  Replaces `path` when it already exists, so callers own the decision about
  whether overwriting is allowed. The key is written to a private file beside
  `path` and moved over it atomically, so a failed generation leaves any
  existing key untouched. Throws if `path` is blank, or if `age-keygen` is
  missing or fails."
  [path]
  (let [f (.getAbsoluteFile (io/file (path-arg :key path)))
        parent (.getParentFile f)
        {:keys [exit out err]} (try
                                 (shell/sh "age-keygen")
                                 (catch java.io.IOException _
                                   {:exit 127 :err "age-keygen not found on PATH"}))]
    (when-not (zero? exit)
      (throw (ex-info "age-keygen failed"
                      {:reason :keygen-failed
                       :path (str path)
                       :error err
                       :install "macOS: brew install age"})))
    (.mkdirs parent)
    (let [tmp (fs/owner-only-temp-file! parent (str "." (.getName f) ".") ".tmp")]
      (try
        (spit tmp out)
        (fs/atomic-move! tmp f)
        (public-key f)
        (finally
          (.delete tmp))))))

(defn encrypt-file!
  "Encrypt plaintext file `in` to ciphertext file `out`. Returns `out`; throws
  on failure.

  `recipients` selects who can decrypt. It is either:
    • a bare String/File, always an identity-*file path*: encrypt to that
      identity's own recipient (`age -e -i`), the single-key workflow. A bare
      `age1…` public-key string throws. Pass those as `{:recipients [\"age1…\"]}`
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
                    {:reason :invalid-argument :recipients recipients})))
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
        (throw (ex-info "age encryption failed"
                        {:reason :encrypt-failed :out (str out) :error err})))
      out)))

(def max-plaintext-bytes
  "The most plaintext bytes one decryption may produce (8 MiB). It catches an
  accidental huge input, such as the wrong file, while `age` is still writing.
  The CLI refuses to write a store past the same bound, so every store it
  writes can be read back."
  8388608)

(def ^:private capture-chunk-bytes
  "Plaintext is drained in fixed 64 KiB chunks so the running total is checked
  before every further read."
  65536)

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

(defn- stream-bounded-stdout!
  "Run `argv`, copying its stdout to `out`, and return `{:exit n :err s}`.

  At most `max-plaintext-bytes` are written. Each read asks for no more than
  one byte past the bound, and the read that crosses it throws `ex-info` with
  `:reason :plaintext-too-large`, `context`, the numeric `:limit` and
  `:observed`, and never a captured byte. The process is destroyed on the way out if it is
  still running. stderr is drained on its own thread, because a process that
  fills an unread stderr pipe blocks forever."
  [argv ^java.io.OutputStream out context]
  (let [process (.start (java.lang.ProcessBuilder. ^java.util.List (vec argv)))
        stderr (future (slurp (.getErrorStream process)))
        chunk (byte-array capture-chunk-bytes)]
    (try
      ;; Nothing here writes to the child, so it gets EOF on stdin at once and
      ;; cannot block on a pipe no one will fill.
      (.close (.getOutputStream process))
      (with-open [stdout (.getInputStream process)]
        (loop [total 0]
          (let [max-bytes max-plaintext-bytes
                remaining (- max-bytes total)
                requested (int (if (< remaining capture-chunk-bytes)
                                 (inc remaining)
                                 capture-chunk-bytes))
                n (.read stdout chunk 0 requested)]
            (when-not (neg? n)
              (let [observed (+ total n)]
                (when (> observed max-bytes)
                  (throw (ex-info (str "The decrypted plaintext of "
                                       (:encrypted-file context) " is larger than the "
                                       max-bytes " byte limit.")
                                  (assoc context
                                         :observed observed
                                         :limit max-bytes
                                         :reason :plaintext-too-large))))
                (.write out chunk 0 n)
                (recur observed))))))
      {:exit (.waitFor process) :err @stderr}
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
  "Decrypt `encrypted-file` with `identity-file` and return the plaintext as a
  byte array. The plaintext is binary safe and is held in memory only.

  Success establishes that the ciphertext is intact and that `identity-file`
  matches one of its recipients. It does not identify who encrypted it: age
  does not sign, so this is payload integrity, never sender authenticity.

  Plaintext is copied in fixed-size chunks. The chunk that would cross
  [[max-plaintext-bytes]] kills `age` and throws with
  `:reason :plaintext-too-large`.

  A failure names `:encrypted-file` and `:identity-file`, which are filesystem
  paths and never key contents. A non-zero exit also carries the captured
  stderr and a wrong-key `:hint`. A failed decryption returns no partial
  plaintext."
  ^bytes [identity-file encrypted-file]
  (let [argv (decrypt-argv identity-file encrypted-file)
        context {:encrypted-file (str encrypted-file)
                 :identity-file (str identity-file)}
        out (java.io.ByteArrayOutputStream.)]
    (ensure-installed!)
    (let [{:keys [exit err]} (stream-bounded-stdout! argv out context)]
      (when-not (zero? exit)
        (throw (ex-info "age decryption failed"
                        (assoc context
                               :reason :decrypt-failed
                               :error err
                               :hint (str "Wrong key, or you are not a recipient of "
                                          "this file.")))))
      (.toByteArray out))))

(defn decrypt
  "Decrypt `encrypted-file` with `identity-file`; return the plaintext as a
  UTF-8 string. Use `decrypt-bytes` for binary plaintexts. The plaintext bound
  and failures are those of [[decrypt-bytes]]."
  [identity-file encrypted-file]
  (String. (decrypt-bytes identity-file encrypted-file) "UTF-8"))
