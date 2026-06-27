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

(defn installed?
  "True when the `age` binary is on the PATH (the decrypt path needs only this)."
  []
  (boolean
   (try
     (zero? (:exit (shell/sh "age" "--version")))
     (catch Exception _ false))))

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

(defn keygen!
  "Generate a fresh age identity at `path`, creating parent directories and
  tightening the file to owner-only permissions. Returns the public key.
  Does not overwrite — callers guard. Throws if `age-keygen` is missing or fails."
  [path]
  (let [f      (io/file (str path))
        parent (.getParentFile f)]
    (when parent (.mkdirs parent))
    (let [{:keys [exit err]} (try
                               (shell/sh "age-keygen" "-o" (str path))
                               (catch java.io.IOException _
                                 {:exit 127 :err "age-keygen not found on PATH"}))]
      (when-not (zero? exit)
        (throw (ex-info "age-keygen failed"
                        {:path (str path) :error err
                         :install "macOS: brew install age"})))
      (doto f
        (.setReadable false false) (.setReadable true true)
        (.setWritable false false) (.setWritable true true))
      (public-key path))))

(defn encrypt-file!
  "Encrypt plaintext file `in` to ciphertext file `out`, for the recipient
  implied by `identity-file` (`age -e -i`). Returns `out`. Throws on failure."
  [identity-file in out]
  (ensure-installed!)
  (let [{:keys [exit err]} (shell/sh "age" "-e" "-i" (str identity-file)
                                     "-o" (str out) (str in))]
    (when-not (zero? exit)
      (throw (ex-info "age encryption failed" {:out (str out) :error err})))
    out))

(defn decrypt
  "Decrypt `encrypted-file` with `identity-file`; return the plaintext as a
  string. Throws an ex-info (with the captured stderr) on failure."
  [identity-file encrypted-file]
  (ensure-installed!)
  (let [{:keys [exit out err]} (shell/sh "age" "-d" "-i" (str identity-file)
                                         (str encrypted-file))]
    (if (zero? exit)
      out
      (throw (ex-info "age decryption failed"
                      {:identity-file  (str identity-file)
                       :encrypted-file (str encrypted-file)
                       :error          err
                       :hint           "Wrong key, or you are not a recipient of this file."})))))

(defn decrypt-to-file!
  "Decrypt `encrypted-file` to plaintext file `out`. Returns `out`."
  [identity-file encrypted-file out]
  (spit (io/file (str out)) (decrypt identity-file encrypted-file))
  out)
