;; # Teams: multi-recipient encryption

^:kindly/hide-code
(ns secrets-book.teams
  (:require [clojure.java.io :as io]
            [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.cli :as cli]))

;; In the single-key setup, every teammate shares one private key. Age also
;; supports multiple recipients: a file can encrypt to many
;; recipients at once, and any one of the matching private keys decrypts it.
;; In team mode, every person generates their own key, the list of
;; public keys is committed to the repo, and teammates do not exchange their
;; private identities.

;; ## Two people, two keys

;; Alice and Bob each run `bb secrets keygen` on their own machines. Here,
;; one temp directory stands in for both machines:

(def dir
  (str (java.nio.file.Files/createTempDirectory
        "secrets-teams-"
        (into-array java.nio.file.attribute.FileAttribute []))))

(def alice-key (str dir "/alice.txt"))
(def bob-key (str dir "/bob.txt"))

(def alice-pub (age/keygen! alice-key))
(def bob-pub (age/keygen! bob-key))

;; The recipients file contains public keys and can be committed:

(def recipients-file (str dir "/recipients.txt"))

(spit recipients-file
      (str "# Everyone who can decrypt the dev secrets.\n"
           alice-pub "\n"
           bob-pub "\n"))

;; ## Encrypting to the list

;; `encrypt-file!` takes a recipients spec. With `:recipients-file`, age
;; encrypts to every key in the list:

(let [plain (str dir "/plain.edn")]
  (spit plain (pr-str {:shared/token "team-secret"}))
  (age/encrypt-file! {:recipients-file recipients-file}
                     plain
                     (str dir "/secrets.edn.age"))
  (io/delete-file plain))

;; One ciphertext, and either private key opens it:

(secrets/load-secrets (str dir "/secrets.edn.age") alice-key)

(secrets/load-secrets (str dir "/secrets.edn.age") bob-key)

;; ## The CLI does this for you

;; In a project, you switch an environment to team mode by adding one config
;; key:

;; ```clojure
;; {:prod {:secrets-file    "env/prod/resources/secrets.edn.age"
;;         :recipients-file "env/prod/recipients.txt"}}
;; ```

;; From then on, every `new`, `edit`, and `reencrypt` encrypts to the complete
;; list. Onboarding a teammate is two commands run by the new person and one
;; by anyone who already has access:

;; ```sh
;; bb secrets keygen prod          # new person, their own machine
;; bb secrets add-recipient prod   # new person, adds their public key
;; bb secrets reencrypt prod       # existing member, so the newcomer can read
;; ```

;; The existing ciphertext must be re-encrypted before the new recipient can
;; read it. `add-recipient` updates the list and prints a reminder; it does not
;; perform the re-encryption itself.

;; Here is `add-recipient!` live, using a config in team mode. A third
;; teammate joins:

(def config
  (cli/normalize-config
   {:app "teams-demo"
    :default-environment :dev
    :environments {:dev {:secrets-file (str dir "/secrets.edn.age")
                         :key-file alice-key
                         :recipients-file recipients-file}}}))

(def carol-pub (age/keygen! (str dir "/carol.txt")))

(cli/add-recipient! config "dev" carol-pub)

;; Re-encrypt so Carol can decrypt the file:

(cli/reencrypt! config "dev")

(secrets/load-secrets (str dir "/secrets.edn.age") (str dir "/carol.txt"))

;; `recipients!` lists the public keys in the configured recipients file:

(cli/recipients! config "dev")

;; ## Offboarding

;; Remove the person's line from `recipients.txt`, run `reencrypt`, and commit
;; both files. They cannot decrypt the new ciphertext, but can still decrypt
;; any version that included their recipient. If the old values must no longer
;; be usable, rotate them at their source as well. See
;; [caveats](secrets_book.caveats.html).

;; ## A key for the robots

;; Deployment and CI can use a dedicated recipient instead of a person's key:

;; ```sh
;; age-keygen -o deploy-key.txt
;; bb secrets add-recipient prod age1...   # the deploy key's public half
;; bb secrets reencrypt prod
;; flyctl secrets set SECRETS_AGE_IDENTITY="$(cat deploy-key.txt)"
;; # store deploy-key.txt in the team password manager, then delete it locally
;; ```

;; A dedicated deploy key keeps production independent of any person's
;; identity and can be rotated separately.

;; ## What team mode costs you

;; In single-key mode, the manifest can include a keyed hash per value, which
;; lets `verify` and reviewers see that a value changed even when its shape
;; did not. Those hashes are keyed by the shared private key, and in team mode
;; there is no shared private key, so team manifests record structure only.
;; Adds, removals, and type changes still show in diffs; a rotated string
;; does not. The [manifest chapter](secrets_book.manifest.html) has the
;; details.

^:kindly/hide-code
(doseq [f (reverse (file-seq (io/file dir)))]
  (.delete f))
