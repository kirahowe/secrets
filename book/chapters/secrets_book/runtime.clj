;; # Runtime: reading secrets in your app

^{:kindly/hide-code true}
(ns secrets-book.runtime
  (:require [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.age :as age]
            [clojure.edn :as edn]
            [clojure.java.io :as io]))

;; Your app touches the library in one of two ways: it loads the whole
;; decrypted map and passes it around, or it registers reader literals so EDN
;; config files can reference secrets inline. This chapter covers both, plus
;; the part everything depends on, which is how the library finds your private
;; key.

;; Setup for the examples: a fresh key and an encrypted file in a temp
;; directory.

(def dir (str (java.nio.file.Files/createTempDirectory
               "secrets-runtime-" (into-array java.nio.file.attribute.FileAttribute []))))

(def key-file (str dir "/key.txt"))

^{:kindly/hide-code true}
(age/keygen! key-file)

(let [plain (str dir "/plain.edn")]
  (spit plain (pr-str {:database/url "jdbc:postgresql://db/app"
                       :llm/api-key  "sk-not-real"
                       :r2           {:account-id "abc123"
                                      :secret     "shhh"}}))
  (age/encrypt-file! key-file plain (str dir "/secrets.edn.age"))
  (io/delete-file plain))

;; ## Loading the map

;; `load-secrets` takes a source and, optionally, something that identifies
;; the key. The source can be a path string:

(secrets/load-secrets (str dir "/secrets.edn.age") key-file)

;; or a `java.io.File`, or any URL, which matters because
;; `clojure.java.io/resource` returns URLs. Inside an uberjar those are `jar:`
;; URLs, and the library copies the ciphertext out to a temp file so `age` can
;; read it. The [production chapter](secrets_book.production.html) demonstrates
;; that with a real jar. Here is the URL form with a plain file URL:

(secrets/load-secrets (.toURL (.toURI (io/file (str dir "/secrets.edn.age"))))
                      key-file)

;; ## Reading values

;; `get-secret` reads one value. A keyword reads a top-level key, a vector
;; walks into nested maps, and a third argument is the default:

(def loaded (secrets/load-secrets (str dir "/secrets.edn.age") key-file))

(secrets/get-secret loaded :database/url)

(secrets/get-secret loaded [:r2 :account-id])

(secrets/get-secret loaded :missing/key "fallback")

;; `loaded` is an ordinary immutable map. There is no wrapper type to learn.
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

;; With no identity argument at all, only the environment variables are
;; consulted, in this order:

;; | Variable | Meaning |
;; |----------|---------|
;; | `SECRETS_AGE_IDENTITY_FILE` | a path to the key file |
;; | `SECRETS_AGE_IDENTITY` | the raw key file contents, used verbatim |
;; | `SECRETS_AGE_IDENTITY_B64` | base64 of the contents; invalid base64 throws |

;; The env vars always win, even when you pass `{:app "myapp"}`. That is the
;; deployment story in one sentence: code passes `{:app "myapp"}` so local
;; development finds `~/.config/myapp/key.txt`, and production sets
;; `SECRETS_AGE_IDENTITY`, which overrides it.

;; There is deliberately no default key path when no app is named. A library
;; that guessed `~/.config/something/key.txt` would sometimes guess a path
;; belonging to a different app, and secrets are the wrong place for guessing.
;; Instead, you get an error that lists every option:

(try
  (secrets/load-secrets (str dir "/secrets.edn.age")
                        {:identity-file (str dir "/no-such-key.txt")})
  (catch Exception e (ex-message e)))

;; ## Reader literals

;; For systems configured with EDN files, tag literals keep the secret
;; references next to the config that uses them. `reader-literals` returns a
;; map of two tag functions, ready to merge into the `:readers` of
;; `clojure.edn/read-string` or `integrant.core/read-string`:

(def readers
  (secrets/reader-literals {:file (str dir "/secrets.edn.age")
                            :identity-file key-file}))

(keys readers)

;; The tags are namespaced because the EDN spec reserves bare tags like
;; `#secret` for EDN itself. In a config file they look like this:

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

;; The last row is the one to remember. A wrong key is never silently
;; ignored, because nil-ing your way past a decryption failure hides real
;; breakage. Here is a missing required key:

(try
  (edn/read-string {:readers readers} "#secret/req :not/in-the-file")
  (catch Exception e (ex-message e)))

;; and an optional read against a source with no key available:

(let [keyless (secrets/reader-literals
               {:file (str dir "/secrets.edn.age")
                :identity-file (str dir "/nobody-home.txt")})]
  (edn/read-string {:readers keyless} "#secret/opt :database/url"))

;; ## Laziness, and why dev configs stay fast

;; Building the readers map costs nothing. The secrets file is resolved and
;; decrypted once, on the first tag actually read, and the result is cached
;; for the life of that readers value. A dev or test config with no secret
;; tags never touches `age` and never needs a key, even when a secrets file
;; sits on the classpath. A config with forty tags decrypts once, not forty
;; times.

;; The flip side: a failure is cached too. If the first tag hits a wrong-key
;; error, every later tag rethrows it. Build a fresh readers map after fixing
;; the environment.

;; ## Merging with readers you already have

;; `merge-readers` folds the two tags into an existing readers map:

(-> {'env (fn [k] (System/getenv (str k)))}
    (secrets/merge-readers {:file (str dir "/secrets.edn.age")
                            :identity-file key-file})
    keys)

;; ## Aero

;; [aero](https://github.com/juxt/aero) resolves tags through its own
;; multimethod rather than a `:readers` map, so delegate:

;; ```clojure
;; (def secret-readers
;;   (secrets/reader-literals {:app "myapp" :resource "secrets.edn.age"}))
;;
;; (defmethod aero.core/reader 'secret/req [_opts _tag value]
;;   ((secret-readers 'secret/req) value))
;; (defmethod aero.core/reader 'secret/opt [_opts _tag value]
;;   ((secret-readers 'secret/opt) value))
;; ```

;; After that, `#secret/req :database/url` works inside an aero config file
;; like any other aero tag.

^{:kindly/hide-code true}
(doseq [f (reverse (file-seq (io/file dir)))]
  (.delete f))
