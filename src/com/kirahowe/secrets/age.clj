(ns com.kirahowe.secrets.age
  "Implementation namespace; not part of the public API and may change without notice.

  A thin wrapper over the `age` CLI (https://age-encryption.org).

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
  only name a file. A path that starts with `-` gets `./` in front, because
  age reads `-` as stdin or stdout and a dash-leading name as an option. A
  blank path throws `:blank-path` naming its role."
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

(defn decrypt
  "Decrypt `encrypted-file` with `identity-file` and return the plaintext as a
  UTF-8 string, held in memory only.

  Success establishes that the ciphertext is intact and that `identity-file`
  matches one of its recipients. It does not identify who encrypted it: age
  does not sign, so this is payload integrity, never sender authenticity.

  age does not compress, so the plaintext is smaller than the ciphertext. The
  caller bounds the ciphertext's size before calling, and that bounds what is
  read here.

  Both paths go through `path-arg` and `--` sits immediately before the input,
  so no path can be read as an option or as stdin. A failure names
  `:encrypted-file` and `:identity-file`, which are filesystem paths and never
  key contents, and carries the captured stderr and a wrong-key `:hint`. A
  failed decryption returns no partial plaintext."
  [identity-file encrypted-file]
  (let [argv ["age" "-d" "-i" (path-arg :identity identity-file)
              "--" (path-arg :input encrypted-file)]]
    ;; Local argument validation first: probing the environment must not be
    ;; able to mask a path that never named a file.
    (ensure-installed!)
    (let [{:keys [exit out err]} (apply shell/sh argv)]
      (when-not (zero? exit)
        (throw (ex-info "age decryption failed"
                        {:reason :decrypt-failed
                         :encrypted-file (str encrypted-file)
                         :identity-file (str identity-file)
                         :error err
                         :hint "Wrong key, or you are not a recipient of this file."})))
      out)))
