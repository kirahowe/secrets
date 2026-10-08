;; # Teams: multi-recipient encryption

^:kindly/hide-code
(ns secrets-book.teams
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.cli :as cli]))

;; Sharing a private key gets awkward when you're working with other people.
;; Age lets us encrypt a file to multiple public recipients, so each person
;; can decrypt it with their own private identity. We commit the list of
;; public keys to the repository, and everyone keeps their private key on
;; their own machine.

;; To use this, add `:recipients-file` to the environment's configuration:

;; ```clojure
;; {:prod {:secrets-file    "env/prod/resources/secrets.edn.age"
;;         :recipients-file "env/prod/recipients.txt"}}
;; ```

;; From then on, every command that writes the store encrypts to the complete
;; list. The manifest is the same as in a single-key setup: it has a value
;; hash for every entry, and every recipient computes the same hashes.

;; ## Creating the first team store

;; The first owner generates a key, adds their own public recipient, and then
;; creates the ciphertext:

;; ```sh
;; bb secrets keygen prod
;; bb secrets add-recipient prod
;; bb secrets new prod            # or: bb secrets set prod :some/key
;; ```

;; There is no `reencrypt` step yet because no ciphertext exists. `new` (or the
;; first `set`) encrypts directly to the recipients already in the file.

;; Let's run that with the command functions, in a temporary directory. Alice
;; and Bob each have a key, as if each had run `keygen` on their own machine:

(def dir
  (str (java.nio.file.Files/createTempDirectory
        "secrets-teams-"
        (into-array java.nio.file.attribute.FileAttribute []))))

(def alice-key (str dir "/alice.txt"))
(def bob-key (str dir "/bob.txt"))

(def alice-pub (age/keygen! alice-key))
(def bob-pub (age/keygen! bob-key))

(def store (str dir "/secrets.edn.age"))

(defn config-for
  "The team's config as one person sees it: only the key file differs."
  [key-file]
  (cli/normalize-config
   {:app "teams-demo"
    :default-environment :dev
    :environments {:dev {:secrets-file store
                         :key-file key-file
                         :recipients-file (str dir "/recipients.txt")}}}))

(def alice (config-for alice-key))
(def bob (config-for bob-key))

^:kindly/hide-code
(defn set-from-pipe!
  "Calls `cli/set-secret!` with `value` on stdin and no terminal attached."
  [config env k value]
  (with-redefs-fn {#'cli/tty? (constantly false)}
    #(with-in-str value (cli/set-secret! config env k false))))

^:kindly/hide-code
(defn manifest-entries
  "The `:keys` of the committed manifest."
  []
  (:keys (edn/read-string (slurp (str dir "/secrets.edn.manifest")))))

;; With no key argument, `add-recipient!` adds the public half of the
;; environment's own key file:

(cli/add-recipient! alice "dev" nil)

;; Alice creates the store. `set-from-pipe!` is a helper for this chapter that
;; calls `cli/set-secret!` with a string on stdin, as
;; `printf %s team-secret | bb secrets set dev :shared/token` would:

(set-from-pipe! alice "dev" ":shared/token" "team-secret")

(manifest-entries)

;; ## Adding another person

;; A new teammate generates a key and sends its public half, which
;; `bb secrets show-key` prints, to someone who can already decrypt the store.
;; That person adds it and re-encrypts:

;; ```sh
;; bb secrets add-recipient prod age1...   # the newcomer's public key
;; bb secrets reencrypt prod
;; ```

;; `add-recipient` only changes the list. The existing ciphertext has to be
;; re-encrypted before the new recipient can read it, and the command says so:

(cli/add-recipient! alice "dev" bob-pub)

(cli/reencrypt! alice "dev")

;; `reencrypt` also gives the store a new manifest key, so the hash below
;; differs from the one above although the value is the same. The section on
;; removing a person explains why.

(manifest-entries)

;; Now either private key reads the store:

(secrets/load-secrets store alice-key)

(secrets/load-secrets store bob-key)

;; `recipients!` lists the public keys in the recipients file:

(cli/recipients! alice "dev")

;; ## Value changes are visible to reviewers

;; Bob rotates the token with his own key:

(set-from-pipe! bob "dev" ":shared/token" "rotated-secret")

(manifest-entries)

;; Bob's write kept the manifest key, because the recipients hadn't changed
;; since the store was last encrypted. The `:vhash` for `[:shared/token]` is
;; different all the same, so a reviewer of that commit sees that the value
;; changed without seeing either value. The hash is keyed by a random key that
;; lives inside the encrypted store, so Alice and Bob compute the same hash
;; for the same value, and someone who can only read the repository cannot
;; test guesses against it. The
;; [manifest chapter](secrets_book.manifest.html) has the details.

;; ## Removing a person {#offboarding}

;; Remove the person's line from the recipients file, run `reencrypt`, and
;; commit the recipients file, the ciphertext, and the manifest together:

(spit (str dir "/recipients.txt") (str alice-pub "\n"))

(cli/reencrypt! alice "dev")

;; Bob's key no longer decrypts the store:

(try
  (secrets/load-secrets store bob-key)
  (catch Exception e (ex-message e)))

;; Removal has limits, and they matter:
;;
;; - Bob can still decrypt every version of the ciphertext that was committed
;;   while he was a recipient. Git history keeps them.
;; - Bob may have copied the values. If they must stop working, rotate them at
;;   their providers. This library can't expire a credential.

;; ### Key renewal

;; Every recipient of a store holds its manifest key, because the key is
;; inside the store. Bob kept the one he had. If the store went on using that
;; key, Bob could hash guesses of a new value and compare them with the
;; `:vhash` in the public manifest, without being able to decrypt anything.

;; So the key is replaced. `reencrypt` always generates a new manifest key,
;; which is why every `:vhash` changes in the commit that removes someone:

(manifest-entries)

;; `edit`, `set`, and `rm` also encrypt to the recipients file as it reads when
;; they run. The store records which recipient set it was last encrypted to,
;; and a write that finds a different set generates a new key too, and says
;; so. Removing a line from the recipients file therefore renews the key on
;; the next write of any kind, even if nobody runs `reencrypt`.

;; The old key still works against the manifests published while it was in
;; use, as Bob's identity still works against the old ciphertexts.

;; ## A key for deployment and CI {#a-key-for-the-robots}

;; Deployment and CI can use a dedicated recipient instead of a person's key:

;; ```sh
;; age-keygen -o deploy-key.txt
;; bb secrets add-recipient prod age1...   # the deploy key's public half
;; bb secrets reencrypt prod
;; flyctl secrets set SECRETS_AGE_IDENTITY="$(cat -- deploy-key.txt)"
;; # store deploy-key.txt in the team password manager, then delete it locally
;; ```

;; A dedicated deploy key keeps production independent of any person's
;; identity and can be replaced separately.

;; The [team-ci example](https://github.com/kirahowe/secrets/tree/main/examples/team-ci) is a committed team store: a recipients
;; list, an encrypted fixture, and a CI job that verifies the manifest without
;; a private identity.

^:kindly/hide-code
(doseq [f (reverse (file-seq (io/file dir)))]
  (.delete f))
