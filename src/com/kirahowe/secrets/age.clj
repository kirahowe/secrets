(ns com.kirahowe.secrets.age
  "Implementation namespace; not part of the public API and may change without notice.

  A thin wrapper over the `age` and `age-keygen` CLIs (https://age-encryption.org).
  It shells out, so it behaves the same under JVM Clojure and babashka, and it
  keeps no state: where keys and secrets live is the caller's decision.

  An identity is a private key (`AGE-SECRET-KEY-1…`) and a recipient is its
  public key (`age1…`). Encrypting to your own identity (`age -e -i key.txt`)
  is the single-key workflow.

  age encrypts to a recipient and does not sign, so nothing here can establish
  who produced a ciphertext."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [com.kirahowe.secrets.fs :as fs]))

(defn version
  "Return the installed `age` version string, or nil when `age` is unavailable
  or the query fails. Failure details are never exposed."
  []
  (try
    (let [{:keys [exit out err]} (fs/sh ["age" "--version"])]
      (when (zero? exit)
        (let [s (str/trim (if (str/blank? out) err out))]
          (when-not (str/blank? s) s))))
    (catch Exception _ nil)))

(defn installed?
  "Return true when the `age` binary is on the PATH."
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
  "Return true when `s` looks like an age recipient: an `age1…` public key or
  an `ssh-ed25519`/`ssh-rsa` line. Only a typo check; `age` is the authority."
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
  In-memory `:identity-contents` goes over standard input (`-i -`), so the key
  never touches disk."
  [{:keys [identity-file identity-contents]}]
  (if identity-contents
    {:args ["-i" "-"] :in identity-contents}
    {:args ["-i" (path-arg :identity identity-file)]}))

(defn public-key
  "Return the public key of `identity` (`{:identity-file path}` or
  `{:identity-contents s}`), or nil when the file is missing or holds no key.
  A key file's `# public key:` comment is used when present; otherwise
  `age-keygen -y` derives it, which needs `age` installed."
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
  "Generate an identity in memory and return `{:identity-contents
  secret-key-line :public-key recipient}`. Throws `:keygen-failed` when
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
  "Generate an identity at `path` (mode 0600, parent directories created) and
  return its public key.

  Replaces an existing `path`, so the caller decides whether overwriting is
  allowed. The key is written beside `path` and moved over it atomically, so a
  failed generation leaves an existing key untouched."
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
  "Encrypt plaintext file `in` to ciphertext file `out` and return `out`.
  Throws `:encrypt-failed`.

  `target` is either an identity (`{:identity-file path}` or
  `{:identity-contents s}`), which encrypts to its own recipient, or
  `{:recipients [\"age1…\" …]}`, where any listed recipient can decrypt."
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
  "Decrypt `encrypted-file` with `identity` (`{:identity-file path}` or
  `{:identity-contents s}`) and return the plaintext as a UTF-8 string, in
  memory only.

  Success shows the ciphertext is intact and the identity is one of its
  recipients. It says nothing about who encrypted it, since age does not sign.

  age does not compress, so the caller's bound on the ciphertext size also
  bounds what is read here.

  `path-arg` and the `--` before the input keep any path from being read as an
  option or stdin. Throws `:decrypt-failed` with `:encrypted-file`, the
  `:identity-file` path when there is one (never key contents), the captured
  stderr as `:error`, and a wrong-key `:hint`. No partial plaintext is returned."
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
