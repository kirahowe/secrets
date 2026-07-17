;; # Teams: multi-recipient encryption

^{:kindly/hide-code true}
(ns secrets-book.teams
  (:require [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.cli :as cli]
            [clojure.java.io :as io]))

;; The single-key setup from the earlier chapters has one obvious problem for
;; a team: everyone shares one private key, and sharing a private key is how
;; keys leak. age solves this natively. A file can encrypt to many
;; recipients at once, and any one of the matching private keys decrypts it.
;; So the team model is: every person generates their own key, the list of
;; public keys is committed to the repo, and nobody ever sends a private key
;; anywhere.

;; ## Two people, two keys

;; Alice and Bob each run `bb secrets keygen` on their own machines. Here,
;; one temp directory stands in for both machines:

(def dir (str (java.nio.file.Files/createTempDirectory
               "secrets-teams-" (into-array java.nio.file.attribute.FileAttribute []))))

(def alice-key (str dir "/alice.txt"))
(def bob-key   (str dir "/bob.txt"))

(def alice-pub (age/keygen! alice-key))
(def bob-pub   (age/keygen! bob-key))

;; Public keys are safe to publish. That is what "public" means here, and it
;; is why the recipients file can live in git:

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

;; From then on, every `new`, `edit`, and `reencrypt` encrypts to the whole
;; list. Onboarding a teammate is two commands run by the new person and one
;; by anyone who already has access:

;; ```sh
;; bb secrets keygen prod          # new person, their own machine
;; bb secrets add-recipient prod   # new person, adds their public key
;; bb secrets reencrypt prod       # existing member, so the newcomer can read
;; ```

;; The `reencrypt` step is easy to forget and impossible to skip: encrypting
;; to a new recipient requires re-encrypting, since the existing ciphertext
;; was sealed before they existed. `add-recipient` prints a reminder.

;; Here is `add-recipient!` live, using a config in team mode. A third
;; teammate joins:

(def config
  (cli/normalize-config
   {:app "teams-demo"
    :default-environment :dev
    :environments {:dev {:secrets-file    (str dir "/secrets.edn.age")
                         :key-file        alice-key
                         :recipients-file recipients-file}}}))

(def carol-pub (age/keygen! (str dir "/carol.txt")))

(cli/add-recipient! config "dev" carol-pub)

;; And the re-encryption that makes Carol's access real:

(cli/reencrypt! config "dev")

(secrets/load-secrets (str dir "/secrets.edn.age") (str dir "/carol.txt"))

;; `recipients!` lists who a file currently encrypts to:

(cli/recipients! config "dev")

;; ## Offboarding

;; Remove the person's line from `recipients.txt`, commit, and `reencrypt`.
;; From that commit forward they cannot decrypt. But read that sentence
;; carefully: *forward*. Git history is immutable, and every commit their key
;; could decrypt remains decryptable by them forever. Removing a recipient is
;; access control for the future, not revocation of the past. If the person
;; leaving is a threat, rotate the secret values themselves. The
;; [caveats chapter](secrets_book.caveats.html) treats this properly, because
;; it is the sharpest edge in the whole model.

;; ## A key for the robots

;; Deployment and CI should be a recipient too, with a dedicated key that no
;; human uses:

;; ```sh
;; age-keygen -o deploy-key.txt
;; bb secrets add-recipient prod age1...   # the deploy key's public half
;; bb secrets reencrypt prod
;; flyctl secrets set AGE_IDENTITY="$(cat deploy-key.txt)"
;; # store deploy-key.txt in the team password manager, then delete it locally
;; ```

;; A dedicated deploy key means offboarding a person never breaks production,
;; and rotating the deploy credential never involves anyone's laptop.

;; ## What team mode costs you

;; In single-key mode, the manifest can include a keyed hash per value, which
;; lets `verify` and reviewers see that a value changed even when its shape
;; did not. Those hashes are keyed by the shared private key, and in team mode
;; there is no shared private key, so team manifests record structure only.
;; Adds, removals, and type changes still show in diffs; a rotated string
;; does not. The [manifest chapter](secrets_book.manifest.html) has the
;; details.

^{:kindly/hide-code true}
(doseq [f (reverse (file-seq (io/file dir)))]
  (.delete f))
