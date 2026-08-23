;; # Quick start

^:kindly/hide-code
(ns secrets-book.index
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.age :as age]))

;; `com.kirahowe/secrets` stores application secrets in an age-encrypted EDN
;; file that can be committed with the code. An age identity stays outside the
;; repository and decrypts the file at runtime. A committed manifest records
;; key paths and changes without storing plaintext secret values.

;; You need [age](https://age-encryption.org) (`brew install age` on macOS,
;; `apt install age` on Debian and Ubuntu) and
;; [babashka](https://babashka.org) for the management commands.

;; ## Install the library

;; Add it to your `deps.edn`:

;; ```clojure
;; com.kirahowe/secrets {:mvn/version "0.1.0"}
;; ```

;; ## Wire the management task

;; Add a `secrets` task to your project's `bb.edn`. Its config says where each
;; environment's encrypted file lives:

;; ```clojure
;; {:deps  {com.kirahowe/secrets {:mvn/version "0.1.0"}}
;;  :tasks {secrets
;;          {:doc      "Manage encrypted secrets (age)"
;;           :requires ([com.kirahowe.secrets.cli :as secrets-cli])
;;           :task     (secrets-cli/run!
;;                      {:app "myapp"
;;                       :default-environment :prod
;;                       :environments
;;                       {:prod
;;                        {:secrets-file "env/prod/resources/secrets.edn.age"}
;;                        :dev
;;                        {:secrets-file "env/dev/resources/secrets.edn.age"}}}
;;                      *command-line-args*)}}}
;; ```

;; Defaults fill in the other paths. The key lives at
;; `~/.config/myapp/key.txt`. Each ciphertext gets a sibling `.example`
;; template and `.manifest` file.

;; ## Create a key and your first secrets

;; ```sh
;; bb secrets keygen prod
;; bb secrets new prod
;; ```

;; `keygen` writes the private identity and prints its public recipient. Back
;; up the identity somewhere outside git, such as a password manager. `new`
;; opens a template in your editor. Saving it writes `secrets.edn.age` and its
;; manifest; commit both files.

;; The file you edit is plain EDN:

;; ```clojure
;; {:database/url "jdbc:postgresql://db.internal/app"
;;  :stripe/api-key "sk_live_..."
;;  :auth/admins #{"kira@example.com" "sam@example.com"}}
;; ```

;; ## A runtime round trip

;; The lower-level age wrapper can create a ciphertext without opening an
;; editor. Unlike `bb secrets new`, this code does not write a manifest.

^:kindly/hide-code
(def dir
  (str (java.nio.file.Files/createTempDirectory
        "secrets-quickstart-"
        (into-array java.nio.file.attribute.FileAttribute []))))

(def key-file (str dir "/key.txt"))

(age/keygen! key-file)

;; Write and encrypt a secrets map:

(let [plain (str dir "/secrets.edn")]
  (spit plain (pr-str {:database/url "jdbc:postgresql://db.internal/app"
                       :stripe/api-key "sk_live_not_really"
                       :auth/admins #{"kira@example.com" "sam@example.com"}}))
  (age/encrypt-file! key-file plain (str dir "/secrets.edn.age"))
  (io/delete-file plain))

;; The ciphertext does not contain readable EDN. Here are its first bytes:

(subs (slurp (str dir "/secrets.edn.age")) 0 60)

;; ## Read secrets in your app

;; `load-secrets` decrypts and reads the file:

(def loaded
  (secrets/load-secrets (str dir "/secrets.edn.age") key-file))

(secrets/get-secret loaded :database/url)

;; EDN types are preserved:

(secrets/get-secret loaded :auth/admins)

;; ## Reference secrets from config files

;; If your system config is EDN, `reader-literals` supplies required and
;; optional secret tags:

(def readers
  (secrets/reader-literals {:file (str dir "/secrets.edn.age")
                            :identity-file key-file}))

;; `#secret/req` throws when the value cannot be loaded. `#secret/opt` returns
;; nil when the secret, ciphertext, or identity is absent:

(edn/read-string {:readers readers}
                 "{:db    {:jdbc-url #secret/req :database/url}
                   :email {:api-key  #secret/opt :postmark/api-key}}")

;; The Postmark key remains present with nil as its value. That is the intentional
;; contract: nil means the optional integration is disabled; key presence carries no
;; additional meaning. When the ciphertext is a classpath resource, pass
;; `:resource "secrets.edn.age"` instead of `:file`; resources inside jars are supported.

;; ## Day to day

;; ```sh
;; bb secrets edit prod      # edit and re-encrypt
;; bb secrets verify         # check the committed manifest
;; bb secrets show-key       # print your public recipient
;; ```

;; `edit` writes plaintext to an owner-only temporary file while the editor is
;; open. It re-encrypts after a successful edit and deletes the temporary file
;; in a `finally` block. Deletion is best-effort on filesystems where
;; overwriting a file cannot guarantee removal of the underlying blocks.

;; ## Deploy

;; Supply the age identity through the deployment platform's secret mechanism:

;; ```sh
;; flyctl secrets set SECRETS_AGE_IDENTITY="$(cat ~/.config/myapp/key.txt)"
;; ```

;; Ship `secrets.edn.age` with the application and load it at startup. See
;; [runtime](secrets_book.runtime.html) for the application APIs and
;; [production and CI](secrets_book.production.html) for deployment details.

^:kindly/hide-code
(doseq [f (reverse (file-seq (io/file dir)))]
  (.delete f))
