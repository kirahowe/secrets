;; # Runtime: reading secrets in your app

^:kindly/hide-code
(ns secrets-book.runtime
  (:require [aero.core :as aero]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.aero :as secrets-aero]
            [com.kirahowe.secrets.age :as age]))

;; There are two ways to get secrets into an application. You can load the
;; complete decrypted map and pass it around, or register reader literals so an
;; EDN config file can reference secrets inline. Both use the same rules for
;; sources and for finding the key.

;; For the examples, we'll create a fresh key and an encrypted file in a
;; temporary directory. The setup calls `com.kirahowe.secrets.age`, the
;; library's internal wrapper around the `age` binary, where you would run
;; `bb secrets keygen` and `bb secrets new`.

(def dir
  (str (java.nio.file.Files/createTempDirectory
        "secrets-runtime-"
        (into-array java.nio.file.attribute.FileAttribute []))))

(def key-file (str dir "/key.txt"))

^:kindly/hide-code
(def public-key (age/keygen! key-file))

(let [plain (str dir "/plain.edn")]
  (spit plain (pr-str {:database/url "jdbc:postgresql://db/app"
                       :llm/api-key "sk-not-real"
                       :r2 {:account-id "abc123"
                            :secret "shhh"}}))
  (age/encrypt-file! {:identity-file key-file} plain (str dir "/secrets.edn.age"))
  (io/delete-file plain))

;; ## Loading the map

;; `load-secrets` takes a source and an optional identity path or options map.
;; The source can be a path string:

(secrets/load-secrets (str dir "/secrets.edn.age") key-file)

;; It also accepts a `java.io.File`, a `java.nio.file.Path`, or a classpath
;; resource, given as the `URL` that `clojure.java.io/resource` returns. That
;; URL is a `file:` one on a directory classpath and a `jar:file:` one inside
;; an uberjar. For the jar case the library copies the ciphertext to an
;; owner-only temp file so `age` can read it. The
;; [production chapter](secrets_book.production.html) demonstrates the jar case.
;; Here is the same call with a `File`:

(secrets/load-secrets (io/file (str dir "/secrets.edn.age")) key-file)

;; Sources are local only. Every other URL, a URI-shaped string, and anything
;; else is rejected before it is opened, so loading secrets never turns into a
;; network request because someone passed in a URL. The error names the
;; scheme and nothing else of the value:

(try
  (secrets/load-secrets "https://user:password@example.com/secrets.edn.age?token=1"
                        key-file)
  (catch Exception e (ex-data e)))

;; A store written by the CLI also holds metadata of the library's own, under
;; the reserved key `:com.kirahowe.secrets/store`. `load-secrets` leaves it
;; out, so the map you get back is your data and nothing else. The
;; [manifest chapter](secrets_book.manifest.html#the-stores-manifest-key) shows
;; this.

;; ## Reading values

;; `get-secret` reads one value. A keyword reads a top-level key, a vector
;; walks into nested maps, and a third argument is the default:

(def loaded (secrets/load-secrets (str dir "/secrets.edn.age") key-file))

(secrets/get-secret loaded :database/url)

(secrets/get-secret loaded [:r2 :account-id])

(secrets/get-secret loaded :missing/key "fallback")

;; A vector path walks maps by key and vectors by integer index, and nothing
;; else. It doesn't index into a string, so a path that runs one step past a
;; secret is not found. It can't hand you one character of a credential:

(secrets/get-secret loaded [:llm/api-key 0] :not-found)

;; `loaded` is an ordinary immutable map.
;; If you use Integrant, the component that provides it is one `defmethod`.
;; Both the resource name and the app name come from the component's config,
;; so the code holds no literal of its own:

;; ```clojure
;; {::secrets {:resource "secrets.edn.age" :app "myapp"}}
;;
;; (defmethod ig/init-key ::secrets [_ {:keys [resource app]}]
;;   (secrets/load-secrets (io/resource resource) {:app app}))
;; ```

;; The [integrant-service example](https://github.com/kirahowe/secrets/tree/main/examples/integrant-service) is a complete HTTP
;; service built this way, with separate resource roots per environment.

;; ## How the key is found

;; The identity argument is a path string or `File` that names the key file
;; directly, or a map. The map can name an identity file, a command that
;; prints the key, a key file, or the app whose macOS Keychain item holds the
;; key:

;; ```clojure
;; (secrets/load-secrets src {:identity-file "/etc/keys/age.txt"})  ; explicit
;; (secrets/load-secrets src {:key-command ["op" "read" "op://Private/myapp age key/password"]})
;; (secrets/load-secrets src {:app "myapp"})   ; the Keychain item for myapp
;; ```

;; The identity is resolved for each operation, from the first of these that
;; applies:
;;
;; 1. an explicit path, as the argument or as `:identity-file`;
;; 2. `SECRETS_AGE_IDENTITY_FILE`, a path;
;; 3. `SECRETS_AGE_IDENTITY`, the key file's contents;
;; 4. `SECRETS_AGE_IDENTITY_B64`, the contents in base64;
;; 5. a `:key-command`, a vector of a program and its arguments whose standard
;;    output is the key;
;; 6. a `:key-file` option, which is how the CLI passes an environment's
;;    configured key file;
;; 7. on macOS, the login Keychain item with service `com.kirahowe.secrets`
;;    and the app name as its account, when an app is named.
;;
;; There is no default key file. With no explicit path, no `:key-command` or
;; `:key-file`, and no app, the environment variables are the only sources.
;; The [production chapter](secrets_book.production.html#injecting-the-key)
;; describes each variable and when to use it.

;; The `:key-command` runs without a shell and with no standard input, each
;; time an operation needs the key. Any password manager with a command that
;; prints a stored value works. Here `cat` stands in for one:

(secrets/load-secrets (str dir "/secrets.edn.age") {:key-command ["cat" key-file]})

;; A command that cannot start, exits with an error, or prints nothing is an
;; error that names the program and never repeats its output.

;; A path you name has to exist. An explicit path or
;; `SECRETS_AGE_IDENTITY_FILE` that points at a missing file is an error, and
;; it says which source named the path:

(try
  (secrets/load-secrets (str dir "/secrets.edn.age")
                        {:identity-file (str dir "/no-such-key.txt")})
  (catch Exception e (ex-message e)))

;; A `:key-file` or a Keychain item only says where the key normally lives.
;; When nothing is named and that key is absent, no identity is available,
;; and `load-secrets` throws with the list of ways to supply one.

;; Identity paths are local filesystem paths, and a leading `~` is expanded. A
;; value that starts with a URI scheme is refused. A bare relative name with a
;; colon in it reads as a scheme, so the message suggests `./`:

(try
  (secrets/load-secrets (str dir "/secrets.edn.age") {:identity-file "key:txt"})
  (catch Exception e (ex-message e)))

;; Key contents put where a path belongs are refused the same way, and the
;; error doesn't repeat them.

;; ### Keys held in memory

;; A key that does not come from a file, whether from `SECRETS_AGE_IDENTITY`,
;; `SECRETS_AGE_IDENTITY_B64`, a `:key-command`, or the Keychain, stays in
;; memory. The library hands it to `age` on standard input (`age -i -`), so
;; it is never written to disk, not even to a temporary file. The library
;; never deletes or changes an identity file you named.

;; `load-secrets` resolves the identity for you. Code that wants to know which
;; identity an operation would use can call `resolve-identity` with the same
;; argument. For a key file, the result names the path and where it came
;; from:

(secrets/resolve-identity key-file)

;; For a key held in memory, the result has `:identity-contents` in place of
;; `:identity-file`. `identity-available?` says whether a resolved identity
;; holds a usable key. This example leaves the key itself out of the result,
;; so the book doesn't print it:

(let [identity (secrets/resolve-identity {:key-command ["cat" key-file]})]
  {:identity-source (:identity-source identity)
   :in-memory? (contains? identity :identity-contents)
   :available? (secrets/identity-available? identity)})

;; ## Size bounds

;; Secret stores are small. Loading refuses a ciphertext past 16 MiB before
;; it decrypts, with `:reason :source-too-large`. age doesn't compress, so
;; that bounds the plaintext too. EDN nested more than 100 collections deep is
;; refused with `:edn-too-deep`. Both carry the numeric `:limit`. The bounds
;; are fixed. They catch an accident, such as a path that names the wrong
;; file. They are not a defence against a hostile source.

;; ## Failures

;; Every failure is an `ex-info` whose data has a `:reason` keyword. The
;; [reference](secrets_book.reference.html#failure-reasons) lists the reasons
;; worth branching on. For loading they are `:no-identity`,
;; `:invalid-identity`, `:disallowed-identity`, `:key-command-failed`,
;; `:keychain-failed`, `:no-file`,
;; `:disallowed-source`, `:source-too-large`, `:decrypt-failed`,
;; `:age-not-installed`, and the EDN reasons.

;; ## Reader literals

;; For systems configured with EDN files, tag literals keep the secret
;; references next to the config that uses them. `reader-literals` returns a
;; map of two tag functions, ready to merge into the `:readers` of
;; `clojure.edn/read-string` or `integrant.core/read-string`:

(def readers
  (secrets/reader-literals {:file (str dir "/secrets.edn.age")
                            :identity-file key-file}))

(keys readers)

;; The tags contain a prefix because the EDN specification reserves
;; unqualified tag names for built-ins. In a config file they look like this:

(edn/read-string {:readers readers}
                 "{:db  {:jdbc-url #secret/req :database/url}
                   :llm {:api-key  #secret/opt :llm/api-key}
                   :s3  {:secret   #secret/req [:r2 :secret]}}")

;; Both tags accept the same key forms as `get-secret`, including vector
;; paths. The options are `:file` (a path) or `:resource` (a classpath
;; resource name), plus `:identity-file`, `:key-command`, `:key-file`, or
;; `:app`.

;; ## Required versus optional

;; Use `#secret/req` when the app shouldn't start without a value. Use
;; `#secret/opt` for something that can be absent, like an API key for a feature
;; you only run in prod. Here's how the two tags handle each case:

;; | Situation | `#secret/req` | `#secret/opt` |
;; |-----------|---------------|---------------|
;; | key present in the store | the value | the value |
;; | key missing from the store | throws | nil |
;; | secrets file not found | throws | nil |
;; | no identity named, and the app's key (its `:key-file` or Keychain item) is absent | throws | nil |
;; | a named identity file does not exist | throws | throws |
;; | decryption fails | throws | throws |

;; The last two rows are broken configurations, and an optional tag doesn't
;; hide them. Naming an identity is a statement about which key to use, so a
;; typo in that path must not look like a store with no optional secrets.
;; Here is a missing required key:

(try
  (edn/read-string {:readers readers} "#secret/req :not/in-the-file")
  (catch Exception e (ex-message e)))

;; Here is an optional read when there is no secrets file:

(let [no-store (secrets/reader-literals
                {:file (str dir "/no-such-secrets.edn.age")
                 :identity-file key-file})]
  (edn/read-string {:readers no-store} "#secret/opt :database/url"))

;; And an optional read with a named identity that isn't there:

(let [typo (secrets/reader-literals
            {:file (str dir "/secrets.edn.age")
             :identity-file (str dir "/nobody-home.txt")})]
  (try
    (edn/read-string {:readers typo} "#secret/opt :database/url")
    (catch Exception e (:reason (ex-data e)))))

;; ## Lazy loading and reloads
;;
;; Building the readers map doesn't read the secrets. The file is resolved and
;; decrypted when the first tag is read, and that load, or that decryption
;; failure, is kept for the life of the readers map. A dev or test config with
;; no secret tags never touches `age` and never needs a key, even when a
;; secrets file sits on the classpath. A config with forty tags decrypts once,
;; and all forty read the same store.
;;
;; The readers map is a value your code owns, and it keeps what it loaded.
;; After you edit the ciphertext, or repair a wrong key, build a new
;; `reader-literals` or `merge-readers` map and read the whole config again.
;; Restarting the process does the same. Readers don't poll or watch the file.
;;
;; In a long-running REPL, build the readers inside the function that reads
;; the config, so every call gets a new map:
;;
;; ```clojure
;; (defn read-app-config []
;;   (let [readers (secrets/reader-literals
;;                  {:app "myapp" :resource "secrets.edn.age"})]
;;     (clojure.edn/read-string
;;      {:readers readers}
;;      (slurp "config.edn"))))
;; ```
;;
;; Don't print the config or a secret value to confirm a reload.

;; ## Merging with readers you already have

;; `merge-readers` folds the two tags into an existing readers map:

(-> {'env (fn [k] (System/getenv (str k)))}
    (secrets/merge-readers {:file (str dir "/secrets.edn.age")
                            :identity-file key-file})
    keys)

;; ## Aero

;; [Aero](https://github.com/juxt/aero) resolves tags through its own
;; multimethod instead of a `:readers` map, so the integration is a namespace
;; with one function. Aero is not a dependency of this library. Add it to your
;; project, then read the config with `com.kirahowe.secrets.aero/read-config`
;; in place of `aero.core/read-config`:

;; ```clojure
;; (ns my-app.config
;;   (:require [com.kirahowe.secrets.aero :as secrets-aero]))
;;
;; (secrets-aero/read-config
;;  "config.edn"
;;  {:profile :dev
;;   :secrets {:app "myapp" :resource "secrets.edn.age"}})
;; ```

;; `:secrets` takes the options of `reader-literals`. Every other key in the
;; map goes to Aero untouched. Here it is with this chapter's store and a
;; config that also uses Aero's own `#profile` and `#or`:

(def config-file (str dir "/config.edn"))

(spit config-file
      "{:db-url  #secret/req :database/url
 :api-key #profile {:default #secret/req :llm/api-key
                    :evals   #secret/req :llm/evals-api-key}
 :mail    #secret/opt :postmark/api-key
 :port    #or [#env DEMO_PORT 8080]}")

(secrets-aero/read-config config-file
                          {:secrets {:file (str dir "/secrets.edn.age")
                                     :identity-file key-file}})

;; Each call decrypts the store at most once, when it reaches the first secret
;; tag, and a config without secret tags never opens it. Nothing is kept
;; between calls. There is no registration and no cache to reset: a second
;; read sees an edited store, and a read that failed can be retried.

;; `read-config` takes both arguments. Without a `:secrets` option there is no
;; store, so a required secret fails and says which option is missing, and an
;; optional one reads nil:

(try
  (secrets-aero/read-config config-file {})
  (catch Exception e (ex-message e)))

;; A config with secret tags read through `aero.core/read-config` directly
;; fails with an error that names the function to use:

(try
  (aero/read-config config-file)
  (catch Exception e (ex-message e)))

;; ### A different key per profile

;; The config above selects a different API key for the `:evals` profile. Aero
;; evaluates only the branch it selects. The default read looked up
;; `:llm/api-key` and never asked for `:llm/evals-api-key`, which this store
;; doesn't have. Selecting `:evals` asks for it:

(try
  (secrets-aero/read-config config-file
                            {:profile :evals
                             :secrets {:file (str dir "/secrets.edn.age")
                                       :identity-file key-file}})
  (catch Exception e (ex-message e)))

;; So a key that one profile needs can be absent from the store another
;; profile reads. The
;; [aero-profiles example](https://github.com/kirahowe/secrets/tree/main/examples/aero-profiles) runs this configuration.

^:kindly/hide-code
(doseq [f (reverse (file-seq (io/file dir)))]
  (.delete f))
