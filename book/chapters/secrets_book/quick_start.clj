;; # Quick start

^{:kindly/hide-code true}
(ns secrets-book.quick-start
  (:require [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.age :as age]
            [clojure.edn :as edn]
            [clojure.java.io :as io]))

;; This chapter takes you from nothing to encrypted secrets your app can read.
;; You need two tools installed: `age` (`brew install age` on macOS,
;; `apt install age` on Debian and Ubuntu) and [babashka](https://babashka.org)
;; for the management CLI.

;; ## Install the library

;; Add it to your `deps.edn`:

;; ```clojure
;; com.kirahowe/secrets {:mvn/version "0.1.0"}
;; ```

;; ## Wire the management task

;; The CLI is a babashka task you add to your project's `bb.edn`. It takes a
;; config map describing where each environment's encrypted file lives:

;; ```clojure
;; {:deps  {com.kirahowe/secrets {:mvn/version "0.1.0"}}
;;  :tasks {secrets
;;          {:doc      "Manage encrypted secrets (age)"
;;           :requires ([com.kirahowe.secrets.cli :as secrets-cli])
;;           :task     (secrets-cli/run!
;;                      {:app "myapp"
;;                       :default-environment :prod
;;                       :environments
;;                       {:prod {:secrets-file "env/prod/resources/secrets.edn.age"}
;;                        :dev  {:secrets-file "env/dev/resources/secrets.edn.age"}}}
;;                      *command-line-args*)}}}
;; ```

;; That is the entire integration. Defaults fill in the rest: the key lands at
;; `~/.config/myapp/key.txt`, and each secrets file gets a sibling
;; `.example` template and `.manifest` shape file.

;; ## Create a key and your first secrets

;; ```sh
;; bb secrets keygen prod
;; bb secrets new prod
;; ```

;; `keygen` writes your private key and prints the public half. Back the
;; private key up somewhere that is not git; a password manager entry works.
;; `new` opens `$EDITOR` on a template, and when you save, it encrypts what
;; you wrote to `secrets.edn.age` and writes the manifest next to it. Commit
;; both files. The plaintext never touches the repo.

;; The file you edit is plain EDN:

;; ```clojure
;; {:database/url "jdbc:postgresql://db.internal/app"
;;  :stripe/api-key "sk_live_..."
;;  :auth/admins #{"kira@example.com" "sam@example.com"}}
;; ```

;; ## The same flow, without an editor

;; A book cannot open `$EDITOR`, so this section drives the same machinery
;; through the library API, in a temp directory. This is also exactly what you
;; would do in a REPL.

^{:kindly/hide-code true}
(def dir (str (java.nio.file.Files/createTempDirectory
               "secrets-quickstart-" (into-array java.nio.file.attribute.FileAttribute []))))

(def key-file (str dir "/key.txt"))

(age/keygen! key-file)

;; Write and encrypt a secrets map:

(let [plain (str dir "/secrets.edn")]
  (spit plain (pr-str {:database/url "jdbc:postgresql://db.internal/app"
                       :stripe/api-key "sk_live_not_really"
                       :auth/admins #{"kira@example.com" "sam@example.com"}}))
  (age/encrypt-file! key-file plain (str dir "/secrets.edn.age"))
  (io/delete-file plain))

;; The ciphertext is opaque. Here are its first bytes:

(subs (slurp (str dir "/secrets.edn.age")) 0 60)

;; ## Read secrets in your app

;; `load-secrets` decrypts and reads the file into a map:

(def loaded
  (secrets/load-secrets (str dir "/secrets.edn.age") key-file))

(secrets/get-secret loaded :database/url)

;; Sets stay sets. No comma-splitting, no coercion:

(secrets/get-secret loaded :auth/admins)

;; ## Or reference secrets from your config files

;; If your system config is EDN (Integrant, component setups, plain
;; `edn/read-string`), the reader literals are nicer. `reader-literals`
;; returns two tag functions bound to a secrets source:

(def readers
  (secrets/reader-literals {:file (str dir "/secrets.edn.age")
                            :identity-file key-file}))

;; `#secret/req` is for secrets the app cannot start without. `#secret/opt`
;; returns nil when the secret, the file, or the key is absent:

(edn/read-string {:readers readers}
                 "{:db    {:jdbc-url #secret/req :database/url}
                   :email {:api-key  #secret/opt :postmark/api-key}}")

;; The Postmark key is not in the file, so it read as nil and the rest of the
;; config was untouched. In a real app you would pass `:resource
;; "secrets.edn.age"` instead of `:file`, and the library finds it on the
;; classpath, jar or no jar.

;; ## Day to day

;; ```sh
;; bb secrets edit prod      # decrypt into $EDITOR, re-encrypt on save
;; bb secrets verify         # check the committed manifest still matches
;; bb secrets show-key       # print your public key for teammates
;; ```

;; `edit` never leaves plaintext on disk: it decrypts to an owner-only temp
;; file, waits for your editor, re-encrypts, and securely deletes the temp
;; file even if the editor exits badly.

;; ## Deploying

;; Production needs exactly one secret set out-of-band, the key itself:

;; ```sh
;; flyctl secrets set SECRETS_AGE_IDENTITY="$(cat ~/.config/myapp/key.txt)"
;; ```

;; The encrypted file ships inside your image or jar, and the library decrypts
;; it at startup. The [production chapter](secrets_book.production.html) walks
;; through Docker, Fly, and CI setups.

^{:kindly/hide-code true}
(doseq [f (reverse (file-seq (io/file dir)))]
  (.delete f))
