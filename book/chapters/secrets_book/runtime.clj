;; # Runtime: reading secrets in your app

^:kindly/hide-code
(ns secrets-book.runtime
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.age :as age]))

;; There are two straightforward ways to get secrets into an application. You
;; can load the complete decrypted map and pass it around, or register reader
;; literals so an EDN config file can reference secrets inline. Both routes use
;; the same source rules, identity resolution, and resource limits.

;; Setup for the examples: a fresh key and an encrypted file in a temp
;; directory.

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

;; Sources are deliberately local-only. HTTP(S), other remote schemes, nested
;; jars, malformed local locators, and arbitrary values accepted by
;; `clojure.java.io/input-stream` are refused before any network access. Secret
;; loading should not quietly become an HTTP client just because a URL was
;; passed in.

;; ## Reading values

;; `get-secret` reads one value. A keyword reads a top-level key, a vector
;; walks into nested maps, and a third argument is the default:

(def loaded (secrets/load-secrets (str dir "/secrets.edn.age") key-file))

(secrets/get-secret loaded :database/url)

(secrets/get-secret loaded [:r2 :account-id])

(secrets/get-secret loaded :missing/key "fallback")

;; `loaded` is an ordinary immutable map.
;; If you use Integrant, the component that provides it is one `defmethod`:

;; ```clojure
;; (defmethod ig/init-key ::secrets [_ {:keys [resource]}]
;;   (secrets/load-secrets (io/resource resource) {:app "myapp"}))
;; ```

;; ## How the key is found

;; The identity argument accepts three shapes. A path string or `File` names
;; the key file directly. A map gives you the two useful indirections:

;; ```clojure
;; (secrets/load-secrets src {:identity-file "/etc/keys/age.txt"})  ; explicit
;; (secrets/load-secrets src {:app "myapp"})   ; ~/.config/myapp/key.txt
;; ```

;; Before the `:app` convention, the library consults the
;; `SECRETS_AGE_IDENTITY_FILE`, `SECRETS_AGE_IDENTITY`, and
;; `SECRETS_AGE_IDENTITY_B64` environment variables, in that order, and with no
;; identity argument at all they are the only sources. They win even when you
;; pass `{:app "myapp"}`, so local development can use
;; `~/.config/myapp/key.txt` while production overrides it with an injected
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

;; Raw and base64 environment identities have to be materialized because age
;; accepts an identity file path. The library reuses an owner-only temp file
;; rather than writing a new copy for every decryption. A long-running process
;; can retire those files when it is finished loading configuration:

;; ```clojure
;; (secrets/reset-identity-cache!)
;; ;; => {:generation 1, :deleted 1, :absent 0, :failed 0, :pending 0}
;; ```

;; A later read materializes a fresh copy. Files you own — an explicit
;; `:identity-file`, `SECRETS_AGE_IDENTITY_FILE`, or the conventional app key —
;; are never deleted. `load-secrets`, the reader literals, and the Aero readers
;; hold their injected identity for the complete decryption, so a concurrent
;; reset cannot remove it from under a running age process. If you resolve an
;; injected identity yourself and pass it directly to the lower-level age API,
;; wrap that call in `secrets/with-identity` to get the same guarantee.

;; ## Resource limits

;; Secret stores are supposed to be small. The runtime therefore bounds each
;; stage while bytes are moving, before a hostile or accidentally enormous file
;; can consume the process:

;; | Limit | Default | What it bounds |
;; |-------|---------|----------------|
;; | `:max-source-bytes` | 16 MiB | ciphertext read from a local file or jar resource |
;; | `:max-plaintext-bytes` | 8 MiB | plaintext produced by age |
;; | `:max-edn-depth` | 100 | nested EDN collections before parsing |

;; Override only what the application genuinely needs:

;; ```clojure
;; (secrets/load-secrets
;;  "secrets/secrets.edn.age"
;;  {:app "myapp"
;;   :limits {:max-plaintext-bytes (* 2 1024 1024)
;;            :max-edn-depth 50}})
;; ```

;; The supplied map is merged over `secrets/default-limits`. Unknown keys,
;; non-integers, and non-positive values are errors; a misspelled safety limit
;; should not look as though it was accepted. The same `:limits` option works
;; with `reader-literals` and `merge-readers`.

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

;; `#secret/req` is a hard dependency: the app should not come up without it.
;; `#secret/opt` is for integrations that can be absent, like an API key for a
;; feature you only run in prod. The two differ in every failure case:

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

;; and an optional read against a source with no key available:

(let [keyless (secrets/reader-literals
               {:file (str dir "/secrets.edn.age")
                :identity-file (str dir "/nobody-home.txt")})]
  (edn/read-string {:readers keyless} "#secret/opt :database/url"))

;; ## Lazy loading, caching, and deliberate reloads
;;
;; Building the readers map does not read the secrets. The file is resolved and
;; decrypted once, on the first tag actually read. That first successful load
;; or genuine decryption failure is cached for the life of that readers map. A
;; dev or test config with no secret tags never touches `age` and never needs a
;; key, even when a secrets file sits on the classpath. A config with forty tags
;; decrypts once, not forty times. Keeping one store stable across every tag also
;; prevents a config read from mixing values from ciphertext changed midway
;; through the read.
;;
;; The flip side is deliberate staleness. After ciphertext is edited, the old
;; readers map keeps its loaded store. If its first tag hit a wrong-key
;; decryption error, every later tag rethrows that cached failure even after the
;; ciphertext is repaired. In both cases, construct a new `reader-literals` or
;; `merge-readers` map and re-read the whole config. A process restart naturally
;; creates fresh readers and observes the current ciphertext. Readers never poll
;; or watch the file, and they never retry decryption once per tag.
;;
;; A safe long-running REPL workflow makes the reload boundary explicit and
;; inspects only non-secret status or structure:
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
;; Do not print the config or any secret value to confirm a reload. Edit out of
;; process and reload deliberately rather than adding filesystem polling.

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

;; `aero` is optional: consumers must already have it on their classpath. After
;; loading the integration namespace, supply the secrets options either to
;; `register!` or to each `read-config` call.

;; Two ways to supply the secrets config — the same opts map `reader-literals`
;; takes above:

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

;; A per-read `:secrets` opt always wins over a `register!`ed default. Aero
;; caches a readers map, and with it the first decrypted store or genuine
;; decryption failure, for each distinct secrets configuration, with the same
;; staleness rules as `reader-literals` above. Calling `register!` again
;; retires every cache entry from the previous registration, even when the new
;; map compares equal, and `(register! nil)` clears the default and its cache.
;; After editing or repairing ciphertext in a long-running process, call
;; `(secrets-aero/reset-cache!)` before re-reading the entire config. It
;; invalidates every cached reader map and store, including cached failures,
;; and leaves the registered default intact.

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
;; evaluates only the selected branch: reading with `:default`
;; decrypts and looks up `:openrouter/api-key` alone, and
;; `:openrouter/evals-api-key` does not need to exist in the store at all;
;; reading with `:evals` selects only the other branch. A key used by one
;; profile can therefore be absent when another profile reads the config.

^:kindly/hide-code
(doseq [f (reverse (file-seq (io/file dir)))]
  (.delete f))
