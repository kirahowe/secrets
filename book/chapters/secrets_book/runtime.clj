;; # Runtime: reading secrets in your app

^:kindly/hide-code
(ns secrets-book.runtime
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.age :as age]))

;; There are two ways to get secrets into an application. You can load the
;; complete decrypted map and pass it around, or register reader literals so an
;; EDN config file can reference secrets inline. Both use the same rules for
;; sources, identity resolution, and resource limits.

;; For the examples, we'll create a fresh key and an encrypted file in a
;; temporary directory.

(def dir
  (str (java.nio.file.Files/createTempDirectory
        "secrets-runtime-"
        (into-array java.nio.file.attribute.FileAttribute []))))

(def key-file (str dir "/key.txt"))

^:kindly/hide-code
(age/keygen! key-file)

(let [plain (str dir "/plain.edn")]
  (spit plain (pr-str {:database/url "jdbc:postgresql://db/app"
                       :llm/api-key "sk-not-real"
                       :r2 {:account-id "abc123"
                            :secret "shhh"}}))
  (age/encrypt-file! key-file plain (str dir "/secrets.edn.age"))
  (io/delete-file plain))

;; ## Loading the map

;; `load-secrets` takes a source and an optional identity path or options map.
;; The source can be a path string:

(secrets/load-secrets (str dir "/secrets.edn.age") key-file)

;; It also accepts a `java.io.File`, `java.nio.file.Path`, local `file:` locator,
;; or a `jar:file:` classpath resource. `clojure.java.io/resource` returns a URL,
;; and inside an uberjar that URL normally uses `jar:file:`. The library copies
;; that ciphertext to an owner-only temp file so `age` can read it. The
;; [production chapter](secrets_book.production.html) demonstrates the jar case.
;; Here is the same call with a local file URL:

(secrets/load-secrets (.toURL (.toURI (io/file (str dir "/secrets.edn.age"))))
                      key-file)

;; Sources are local only. HTTP(S), other remote schemes, nested jars, malformed
;; local locators, and arbitrary values accepted by
;; `clojure.java.io/input-stream` are rejected before any network access. This
;; keeps secret loading from quietly turning into an HTTP request just because
;; someone passed in a URL.

;; ## Reading values

;; `get-secret` reads one value. A keyword reads a top-level key, a vector
;; walks into nested maps, and a third argument is the default:

(def loaded (secrets/load-secrets (str dir "/secrets.edn.age") key-file))

(secrets/get-secret loaded :database/url)

(secrets/get-secret loaded [:r2 :account-id])

(secrets/get-secret loaded :missing/key "fallback")

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

;; The identity argument accepts three shapes. A path string or `File` names
;; the key file directly. A map lets you provide an explicit identity file or
;; use the conventional path for an app:

;; ```clojure
;; (secrets/load-secrets src {:identity-file "/etc/keys/age.txt"})  ; explicit
;; (secrets/load-secrets src {:app "myapp"})   ; ~/.config/myapp/key.txt
;; ```

;; Before using the `:app` convention, the library checks the
;; `SECRETS_AGE_IDENTITY_FILE`, `SECRETS_AGE_IDENTITY`, and
;; `SECRETS_AGE_IDENTITY_B64` environment variables, in that order. With no
;; identity argument, these environment variables are the only sources. They
;; also take precedence when you pass `{:app "myapp"}`, so local development can
;; use `~/.config/myapp/key.txt` while production overrides it with an injected
;; identity. The
;; [production chapter](secrets_book.production.html#injecting-the-key)
;; describes each variable and when to use it.

;; There is no default key path when no app is named. This prevents unrelated
;; applications from sharing a conventional path by accident. The error lists
;; the supported identity sources:

(try
  (secrets/load-secrets (str dir "/secrets.edn.age")
                        {:identity-file (str dir "/no-such-key.txt")})
  (catch Exception e (ex-message e)))

;; ### Retiring injected identities

;; Raw and base64 environment identities have to be written to a file because
;; age expects an identity file path. The library reuses an owner-only temporary
;; file instead of writing a new copy for every decryption. A long-running
;; process can retire those files when it has finished loading its config:

;; ```clojure
;; (secrets/reset-identity-cache!)
;; ;; => {:generation 1, :deleted 1, :absent 0, :failed 0, :pending 0}
;; ```

;; A later read materializes a fresh copy. The library never deletes identity
;; files you provide yourself, whether they come from an explicit
;; `:identity-file`, `SECRETS_AGE_IDENTITY_FILE`, or the conventional app key.
;; `load-secrets`, the reader literals, and the Aero readers hold their injected
;; identity for the complete decryption, so a concurrent reset cannot remove it
;; from under a running age process. If you resolve an injected identity
;; yourself and pass it directly to the lower-level age API, wrap that call in
;; `secrets/with-identity` to get the same guarantee.

;; ## Resource limits

;; Secret stores are generally small, so the runtime limits each stage while
;; the bytes are moving. This stops a hostile or accidentally enormous file
;; before it can exhaust the process's memory:

;; | Limit | Default | What it bounds |
;; |-------|---------|----------------|
;; | `:max-source-bytes` | 16 MiB | ciphertext read from a local file or jar resource |
;; | `:max-plaintext-bytes` | 8 MiB | plaintext produced by age |
;; | `:max-edn-depth` | 100 | nested EDN collections before parsing |

;; You can override the limits an application needs to change:

;; ```clojure
;; (secrets/load-secrets
;;  "secrets/secrets.edn.age"
;;  {:app "myapp"
;;   :limits {:max-plaintext-bytes (* 2 1024 1024)
;;            :max-edn-depth 50}})
;; ```

;; The supplied map is merged over `secrets/default-limits`. Unknown keys,
;; non-integers, and non-positive values are errors, so a misspelled limit can't
;; appear to have been accepted. The same `:limits` option works with
;; `reader-literals` and `merge-readers`.

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
;; paths.

;; ## Required versus optional

;; Use `#secret/req` when the app shouldn't start without a value. Use
;; `#secret/opt` for something that can be absent, like an API key for a feature
;; you only run in prod. Here's how the two tags handle each failure case:

;; | Situation | `#secret/req` | `#secret/opt` |
;; |-----------|---------------|---------------|
;; | key present in the file | the value | the value |
;; | key missing from the file | throws | nil |
;; | secrets file not found | throws | nil |
;; | no identity available | throws | nil |
;; | file and key exist, decryption fails | throws | throws |

;; A wrong key is never ignored: it indicates a broken configuration rather
;; than an absent optional feature. Here is a missing required key:

(try
  (edn/read-string {:readers readers} "#secret/req :not/in-the-file")
  (catch Exception e (ex-message e)))

;; Here is an optional read against a source with no key available:

(let [keyless (secrets/reader-literals
               {:file (str dir "/secrets.edn.age")
                :identity-file (str dir "/nobody-home.txt")})]
  (edn/read-string {:readers keyless} "#secret/opt :database/url"))

;; ## Lazy loading, caching, and deliberate reloads
;;
;; Building the readers map doesn't read the secrets. The file is resolved and
;; decrypted when the first tag is read, and that successful load or genuine
;; decryption failure is cached for the life of the readers map. This means a
;; dev or test config with no secret tags never touches `age` and never needs a
;; key, even when a secrets file sits on the classpath. A config with forty tags
;; decrypts once. It also uses one stable store for the whole config read, so a
;; ciphertext change partway through can't mix old and new values.
;;
;; The old readers map keeps its loaded store after you edit the ciphertext. If
;; its first tag hit a wrong-key decryption error, every later tag rethrows that
;; cached failure even after you repair the ciphertext. In either case, create a
;; new `reader-literals` or `merge-readers` map and read the whole config again.
;; Restarting the process also creates fresh readers that see the current
;; ciphertext. Readers don't poll or watch the file, and they don't retry the
;; decryption for each tag.
;;
;; In a long-running REPL, make the reload explicit and inspect only non-secret
;; status or structure:
;;
;; ```clojure
;; (defn read-app-config []
;;   (let [readers (secrets/reader-literals
;;                  {:app "myapp" :resource "secrets.edn.age"})] ; always fresh
;;     (clojure.edn/read-string
;;      {:readers readers}
;;      (slurp "config.edn"))))
;;
;; ;; In another terminal: bb secrets edit dev
;; (def app-config (read-app-config))
;; {:config-loaded? (map? app-config)
;;  :section-count  (count app-config)}
;; ```
;;
;; Don't print the config or any secret value to confirm a reload. Edit it in
;; another process, then reload the whole config explicitly.

;; ## Merging with readers you already have

;; `merge-readers` folds the two tags into an existing readers map:

(-> {'env (fn [k] (System/getenv (str k)))}
    (secrets/merge-readers {:file (str dir "/secrets.edn.age")
                            :identity-file key-file})
    keys)

;; ## Aero

;; [aero](https://github.com/juxt/aero) resolves tags through its own
;; multimethod rather than a `:readers` map. At a REPL, requiring
;; `com.kirahowe.secrets.aero` registers the two methods:

;; ```clojure
;; ;; REPL usage
;; (require '[com.kirahowe.secrets.aero])
;; ```

;; In application source, declare both dependencies in the namespace:

;; ```clojure
;; (ns my-app.config
;;   (:require [aero.core :as aero]
;;             [com.kirahowe.secrets.aero :as secrets-aero]))
;; ```

;; Aero is an optional dependency, so it must already be on the application's
;; classpath. After loading the integration namespace, supply the secrets
;; options either to `register!` or to each `read-config` call.

;; You can supply the same options map accepted by `reader-literals` either for
;; the whole process or for one read:

;; ```clojure
;; ;; process-wide, for one app reading its own config in one place
;; (secrets-aero/register!
;;  {:app "myapp"
;;   :resource "secrets.edn.age"})
;;
;; ;; per read, through aero's own opts — read-config passes its whole opts
;; ;; map to readers, so the config comes straight off a :secrets key
;; (aero/read-config
;;  "config.edn"
;;  {:secrets {:app "myapp" :resource "secrets.edn.age"}})
;; ```

;; A per-read `:secrets` option always takes precedence over a default supplied
;; to `register!`. For each distinct secrets configuration, Aero caches the
;; readers map and its first decrypted store or genuine decryption failure. The
;; same staleness rules described for `reader-literals` apply here. Calling
;; `register!` again retires every cache entry from the previous registration,
;; even when the new map compares equal. `(register! nil)` clears the default
;; and its cache. After editing or repairing ciphertext in a long-running
;; process, call `(secrets-aero/reset-cache!)` before reading the entire config
;; again. It clears every cached readers map, store, and failure while leaving
;; the registered default intact.

;; After registering, `#secret/req :database/url` works inside an aero config
;; file like any other aero tag.

;; ### A different key per profile

;; For example, eval runs can select a different OpenRouter key from production
;; by combining Aero's `#profile` tag with `#secret/req`:

;; ```clojure
;; :api-key #profile {:default #secret/req :openrouter/api-key
;;                    :evals   #secret/req :openrouter/evals-api-key}
;; ```

;; Pass `{:profile :evals}` to `read-config` to select the second branch. Aero
;; evaluates only the branch it selects. With `:default`, it decrypts and looks
;; up `:openrouter/api-key`, and `:openrouter/evals-api-key` doesn't need to
;; exist in the store. With `:evals`, it looks up only the other key. This means
;; a key used by one profile can be absent when another profile reads the
;; config. The
;; [aero-profiles example](https://github.com/kirahowe/secrets/tree/main/examples/aero-profiles) runs exactly this configuration.

^:kindly/hide-code
(doseq [f (reverse (file-seq (io/file dir)))]
  (.delete f))
