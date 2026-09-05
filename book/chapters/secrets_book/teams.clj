;; # Teams: multi-recipient encryption

^:kindly/hide-code
(ns secrets-book.teams
  (:require [clojure.java.io :as io]
            [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.cli :as cli]))

;; Sharing a private key gets awkward when you're working with other people.
;; Age lets us encrypt a file to multiple public recipients, so each person
;; can decrypt it with their own private identity. We commit the list of
;; public keys to the repository, and everyone keeps their private key on
;; their own machine.

;; ## Two people, two keys

;; Alice and Bob each run `bb secrets keygen` on their own machines. For this
;; example, we'll create both keys in a temporary directory:

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

;; We can read the same encrypted file with either private key:

(secrets/load-secrets (str dir "/secrets.edn.age") alice-key)

(secrets/load-secrets (str dir "/secrets.edn.age") bob-key)

;; ## The CLI does this for you

;; To use this through the CLI, add `:recipients-file` to the environment's
;; configuration:

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

;; Once the store exists, a new teammate generates a key and adds their public
;; recipient. Someone who already has access then re-encrypts the file:

;; ```sh
;; bb secrets keygen prod          # new person, their own machine
;; bb secrets add-recipient prod   # new person, adds their public key
;; bb secrets reencrypt prod       # existing member, so the newcomer can read
;; ```

;; The existing ciphertext must be re-encrypted before the new recipient can
;; read it. `add-recipient` updates the list and prints a reminder; it does not
;; perform the re-encryption itself.

;; Let's add a third teammate to our example using `add-recipient!`. First
;; we'll configure the environment to use our recipients file:

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

;; ## A key for deployment and CI {#a-key-for-the-robots}

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

;; ## Value changes in team mode {#what-team-mode-costs-you}

;; Team manifests only record structure. You'll see added and removed keys and
;; type changes in diffs, but you won't see when a string is replaced with
;; another string. Detecting that kind of change needs a hash derived from a
;; shared private key, which we don't have in team mode. The
;; [manifest chapter](secrets_book.manifest.html#catching-value-changes-with-a-keyed-hash)
;; has the details.

^:kindly/hide-code
(doseq [f (reverse (file-seq (io/file dir)))]
  (.delete f))
