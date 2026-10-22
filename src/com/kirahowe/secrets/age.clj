(ns com.kirahowe.secrets.age
  "Implementation namespace; not part of the public API and may change without notice.

  A thin wrapper over the `age` CLI (https://age-encryption.org).

  Every function runs the `age` / `age-keygen` binaries, so this
  namespace loads and runs identically under JVM Clojure and babashka. It holds
  no state and takes no opinion about *where* keys or secrets live. That is the
  caller's job (see `com.kirahowe.secrets` for runtime loading and `com.kirahowe.secrets.cli`
  for the management task).

  `age` is a file-encryption tool. A keypair is an
  identity file (the private key, `AGE-SECRET-KEY-1…`) plus a recipient (the
  public key, `age1…`). Encrypting to your own identity (`age -e -i key.txt`)
  gives a single-key workflow: the same file both encrypts and decrypts.

  age encrypts *to* a recipient and does not sign. A recipient is shareable by
  design and authorizes *encryption*, not authorship, so nothing here, and
  nothing built on it, can establish who produced a ciphertext."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [com.kirahowe.secrets.fs :as fs]))

(defn version
  "Return the installed `age` version string, or nil when `age` is unavailable
  or its version query fails. Only successful version output is returned:
  subprocess arguments, environment, and failure details are never exposed."
  []
  (try
    (let [{:keys [exit out err]} (fs/sh ["age" "--version"])]
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

(defn valid-recipient?
  "Return true when `s` looks like an age recipient: an `age1…` public key, or
  an `ssh-ed25519`/`ssh-rsa` line with a base64 key and an optional comment.
  This is not a full validation: `age` itself is the authority; this just
  catches a typo or a junk line before it is written or handed to `age`."
  [s]
  (let [s (str/trim (str s))]
    (boolean (or (re-matches #"age1[0-9a-z]{20,}" s)
                 (re-matches #"ssh-(ed25519|rsa) [A-Za-z0-9+/]+={0,2}( .*)?" s)))))

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

(defn- identity-args
  "The age arguments and standard input that hand `identity` to age.
  `{:identity-file path}` names a key file. `{:identity-contents s}` holds the
  key in memory, and age reads it from standard input (`-i -`), so it is
  never written to disk."
  [{:keys [identity-file identity-contents]}]
  (if identity-contents
    {:args ["-i" "-"] :in identity-contents}
    {:args ["-i" (path-arg :identity identity-file)]}))

(defn public-key
  "Return the public key (recipient) of `identity`, an `{:identity-file path}`
  or `{:identity-contents s}` map, or nil when the file is missing or holds no
  key. A key file's `# public key:` comment is read when it has one. Anything
  else is handed to `age-keygen -y`, which needs `age` installed."
  [{:keys [identity-file identity-contents] :as identity}]
  (let [f (some-> identity-file str io/file)]
    (when (or identity-contents (and f (.exists ^java.io.File f)))
      (or (when f
            (some #(second (re-find #"(?i)public key:\s*(\S+)" %))
                  (str/split-lines (slurp f))))
          (do (ensure-installed!)
              (let [{:keys [args in]} (identity-args identity)
                    ;; age-keygen -y takes the key as its one operand or
                    ;; reads it from standard input.
                    argv (into ["age-keygen" "-y"] (when-not in [(last args)]))
                    {:keys [exit out]} (fs/sh argv {:in in})]
                (when (zero? exit) (not-empty (str/trim out)))))))))

(defn generate
  "Generate a fresh age identity in memory with `age-keygen` and return
  `{:identity-contents secret-key-line :public-key recipient}`. Throws if
  `age-keygen` is missing or fails."
  []
  (let [{:keys [exit out err]} (try
                                 (fs/sh ["age-keygen"])
                                 (catch java.io.IOException _
                                   {:exit 127 :err "age-keygen not found on PATH"}))
        secret-key (when (zero? exit)
                     (some #(re-matches #"AGE-SECRET-KEY-1[0-9A-Z]+" (str/trim %))
                           (str/split-lines out)))
        pub (when secret-key
              (some #(second (re-find #"(?i)public key:\s*(\S+)" %))
                    (str/split-lines out)))]
    (when-not (and secret-key pub)
      (throw (ex-info "age-keygen failed"
                      {:reason :keygen-failed
                       :error err
                       :install "macOS: brew install age"})))
    {:identity-contents secret-key :public-key pub}))

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
        {:keys [identity-contents public-key]} (generate)]
    (.mkdirs parent)
    (let [tmp (fs/owner-only-temp-file! parent (str "." (.getName f) ".") ".tmp")]
      (try
        (spit tmp (str "# public key: " public-key "\n" identity-contents "\n"))
        (fs/atomic-move! tmp f)
        public-key
        (finally
          (.delete tmp))))))

(defn encrypt-file!
  "Encrypt plaintext file `in` to ciphertext file `out`. Returns `out`; throws
  on failure.

  `target` says who can decrypt. An identity, `{:identity-file path}` or
  `{:identity-contents s}`, encrypts to that identity's own recipient
  (`age -e -i`), the single-key workflow. `{:recipients [\"age1…\" …]}`
  encrypts to each listed recipient (`-r` each), so each person holds their
  own key and any one of them can decrypt."
  [{:keys [recipients] :as target} in out]
  (let [identity (when (some #(contains? target %) [:identity-file :identity-contents])
                   (identity-args target))
        argv (-> ["age" "-e"]
                 (into (:args identity))
                 (into (mapcat (fn [recipient] ["-r" (str recipient)])) recipients)
                 (into ["-o" (path-arg :output out) "--" (path-arg :input in)]))]
    ;; Local argument validation first: probing the environment must not be
    ;; able to mask a path that never named a file.
    (ensure-installed!)
    (let [{:keys [exit err]} (fs/sh argv {:in (:in identity)})]
      (when-not (zero? exit)
        (throw (ex-info "age encryption failed"
                        {:reason :encrypt-failed :out (str out) :error err})))
      out)))

(defn decrypt
  "Decrypt `encrypted-file` with `identity`, an `{:identity-file path}` or
  `{:identity-contents s}` map, and return the plaintext as a UTF-8 string,
  held in memory only.

  Success establishes that the ciphertext is intact and that the identity
  matches one of its recipients. It does not identify who encrypted it: age
  does not sign, so this is payload integrity, never sender authenticity.

  age does not compress, so the plaintext is smaller than the ciphertext. The
  caller bounds the ciphertext's size before calling, and that bounds what is
  read here.

  Both paths go through `path-arg` and `--` sits immediately before the input,
  so no path can be read as an option or as stdin. A failure names
  `:encrypted-file` and, for a key file, `:identity-file`, which are
  filesystem paths and never key contents, and carries the captured stderr
  and a wrong-key `:hint`. A failed decryption returns no partial plaintext."
  [{:keys [identity-file] :as identity} encrypted-file]
  (let [{:keys [args in]} (identity-args identity)
        argv (-> ["age" "-d"]
                 (into args)
                 (into ["--" (path-arg :input encrypted-file)]))]
    ;; Local argument validation first: probing the environment must not be
    ;; able to mask a path that never named a file.
    (ensure-installed!)
    (let [{:keys [exit out err]} (fs/sh argv {:in in})]
      (when-not (zero? exit)
        (throw (ex-info "age decryption failed"
                        (cond-> {:reason :decrypt-failed
                                 :encrypted-file (str encrypted-file)
                                 :error err
                                 :hint "Wrong key, or you are not a recipient of this file."}
                          identity-file (assoc :identity-file (str identity-file))))))
      out)))
