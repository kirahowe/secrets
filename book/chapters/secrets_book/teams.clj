;; # Teams: multi-recipient encryption

^:kindly/hide-code
(ns secrets-book.teams
  (:require [clojure.java.io :as io]
            [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.cli :as cli]))

;; Sharing one private key is simple, but it gets awkward as soon as more than
;; one person needs it. Age can encrypt one file to many public recipients, and
;; any matching private identity can decrypt it. In team mode every person keeps
;; their own identity, while the public recipient list is committed to the
;; repository. Private keys never have to move between teammates.

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
;; list.

;; ### Creating the first team store

;; The first owner generates a key, adds their own public recipient, and then
;; creates the ciphertext:

;; ```sh
;; bb secrets keygen prod
;; bb secrets add-recipient prod
;; bb secrets new prod
;; ```

;; There is no `reencrypt` step yet because no ciphertext exists. `new` (or the
;; first `set`) encrypts directly to the recipients already in the file.

;; ### Adding another person

;; Once a store exists, onboarding a teammate is two commands run by the new
;; person and one by somebody who already has access:

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

;; The [team-ci example](https://github.com/kirahowe/secrets/tree/main/examples/team-ci) is a committed team store: a recipients
;; list, an encrypted fixture, and a CI job that verifies the manifest without
;; a private identity.

;; ## What team mode costs you

;; Team manifests record structure only: adds, removals, and type changes show
;; in diffs, but a rotated string does not. The per-value hashes that catch a
;; rotation are keyed by the private key, and a team has no shared one. The
;; [manifest chapter](secrets_book.manifest.html#catching-value-changes-with-a-keyed-hash)
;; has the details.

^:kindly/hide-code
(doseq [f (reverse (file-seq (io/file dir)))]
  (.delete f))
