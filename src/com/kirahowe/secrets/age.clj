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
  gives a single-key workflow: the same file both encrypts and decrypts."
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
  "True when the `age` binary is on the PATH (the decrypt path needs only this)."
  []
  (some? (version)))

(defn ensure-installed!
  "Throw a helpful ex-info unless `age` is installed."
  []
  (when-not (installed?)
    (throw (ex-info "The `age` encryption tool is not installed."
                    {:tool    "age"
                     :install "macOS: brew install age  •  Debian/Ubuntu: apt install age"
                     :docs    "https://age-encryption.org"}))))

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
  "Cheap sanity check that `s` looks like an age recipient (an `age1…` public
  key, or an `ssh-ed25519`/`ssh-rsa` line). Not a full validation — `age` itself
  is the authority; this just catches obvious typos before writing a keys file."
  [s]
  (let [s (str/trim (str s))]
    (boolean (or (re-matches #"age1[0-9a-z]{20,}" s)
                 (re-matches #"ssh-(ed25519|rsa) .+" s)))))

(defn keygen!
  "Generate a fresh age identity at `path`, creating parent directories and
  tightening the file to owner-only permissions. Returns the public key.

  Replaces `path` when it already exists, so callers own the decision about
  whether overwriting is allowed. `age-keygen -o` refuses to open an existing
  output file, so the key is generated inside a sibling temp directory and
  moved over `path` only once it succeeds — a failed generation leaves any
  existing key untouched. Throws if `age-keygen` is missing or fails."
  [path]
  (let [f      (.getAbsoluteFile (io/file (str path)))
        parent (.getParentFile f)]
    (.mkdirs parent)
    (let [tmp-dir (java.nio.file.Files/createTempDirectory
                   (.toPath parent) (str "." (.getName f) ".keygen")
                   (into-array java.nio.file.attribute.FileAttribute []))
          tmp     (.toFile (.resolve tmp-dir (.getName f)))]
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
  (ensure-installed!)
  (when (and (string? recipients) (valid-recipient? recipients))
    (throw (ex-info (str "encrypt-file! got a bare public key, but a bare "
                         "recipients value means an identity-file path. Pass "
                         "public keys as {:recipients [\"age1…\"]}.")
                    {:recipients recipients})))
  (let [{:keys [identity-file recipients-file] rs :recipients}
        (if (map? recipients) recipients {:identity-file recipients})
        args (concat ["age" "-e"]
                     (when identity-file   ["-i" (str identity-file)])
                     (when recipients-file ["-R" (str recipients-file)])
                     (mapcat (fn [r] ["-r" (str r)]) rs)
                     ["-o" (str out) (str in)])
        {:keys [exit err]} (apply shell/sh args)]
    (when-not (zero? exit)
      (throw (ex-info "age encryption failed" {:out (str out) :error err})))
    out))

(defn decrypt-bytes
  "Decrypt `encrypted-file` with `identity-file`; return the plaintext as a
  byte array (binary-safe — age encrypts arbitrary files, not just text).
  Throws an ex-info (with the captured stderr) on failure."
  ^bytes [identity-file encrypted-file]
  (ensure-installed!)
  ;; :out-enc :bytes leaves stdout undecoded; stderr is still returned as a
  ;; string (both here and on the JVM).
  (let [{:keys [exit out err]} (shell/sh "age" "-d" "-i" (str identity-file)
                                         (str encrypted-file)
                                         :out-enc :bytes)]
    (if (zero? exit)
      out
      (throw (ex-info "age decryption failed"
                      {:identity-file  (str identity-file)
                       :encrypted-file (str encrypted-file)
                       :error          err
                       :hint           "Wrong key, or you are not a recipient of this file."})))))

(defn decrypt
  "Decrypt `encrypted-file` with `identity-file`; return the plaintext as a
  UTF-8 string. Use `decrypt-bytes` for binary plaintexts. Throws an ex-info
  (with the captured stderr) on failure."
  [identity-file encrypted-file]
  (String. (decrypt-bytes identity-file encrypted-file) "UTF-8"))

(defn decrypt-to-file!
  "Decrypt `encrypted-file` to plaintext file `out`, byte-for-byte (binary
  content is preserved). Returns `out`."
  [identity-file encrypted-file out]
  (io/copy (decrypt-bytes identity-file encrypted-file) (io/file (str out)))
  out)
