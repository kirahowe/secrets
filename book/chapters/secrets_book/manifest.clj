;; # The manifest: reviewable encrypted changes

^:kindly/hide-code
(ns secrets-book.manifest
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.cli :as cli]
            [com.kirahowe.secrets.manifest :as manifest]))

;; age uses randomized encryption, which means that encrypting the same
;; plaintext twice produces different ciphertext. A diff between ciphertexts
;; therefore can't tell you what changed in the plaintext:

(def dir
  (str (java.nio.file.Files/createTempDirectory
        "secrets-manifest-"
        (into-array java.nio.file.attribute.FileAttribute []))))

^:kindly/hide-code
(def key-file (str dir "/key.txt"))

^:kindly/hide-code
(def public-key (age/keygen! key-file))

(let [plain (str dir "/p.edn")]
  (spit plain (pr-str {:a 1}))
  (age/encrypt-file! {:identity-file key-file} plain (str dir "/one.age"))
  (age/encrypt-file! {:identity-file key-file} plain (str dir "/two.age"))
  (= (slurp (str dir "/one.age")) (slurp (str dir "/two.age"))))

;; If a pull request only changes `secrets.edn.age`, there is very little for a
;; reviewer to learn from the diff. The manifest records the useful parts of
;; the change without storing the plaintext secret values.

;; To show the mechanism, this chapter calls `com.kirahowe.secrets.manifest`
;; and `com.kirahowe.secrets.age` directly. Both are implementation
;; namespaces, not API: you get a manifest by using `bb secrets`.

;; ## What the manifest records

;; `entries` describes a secrets map. It lists every key path, the type of its
;; value, a count for collections, and a keyed hash of the value called
;; `:vhash`. It does not include the values. It recurses into non-empty maps,
;; and every other value, a vector or a set included, is one entry:

(def secrets-v1
  {:database/url "jdbc:postgresql://db/app"
   :auth {:admins #{"kira@example.com" "sam@example.com"}}
   :retries 3})

(def demo-key (manifest/generate-key))

(manifest/entries secrets-v1 demo-key)

;; CLI commands that write secrets render this as line-oriented EDN in a
;; `.manifest` file beside the ciphertext. When both files are committed, the
;; ciphertext still changes opaquely, but the manifest gives you something
;; useful to review. For example, the line for `[:auth :admins]` can show that
;; the set grew from 2 to 3.

;; ## Catching value changes with a keyed hash

;; The path and type can't show a value changing without changing type, which
;; is what happens when you rotate a credential. The `:vhash` does:

(manifest/entries {:token "old-value"} demo-key)

(manifest/entries {:token "new-value"} demo-key)

;; A `:vhash` is the first 64 bits of an HMAC-SHA-256 of the value, keyed by
;; the manifest key, which is 256 random bits. Someone who has only the
;; repository doesn't have the key, so they can't hash guesses of a
;; low-entropy value and compare. At 64 bits two different values can share a
;; hash, so an unchanged hash is strong evidence that a value didn't change
;; and not proof.

;; The key is the only other input. Equal values at different paths therefore
;; have equal hashes, and a reader of the manifest can see that:

(manifest/entries {:primary/token "same" :backup/token "same"} demo-key)

;; Under a different key, the same value hashes differently:

(manifest/entries {:token "old-value"} (manifest/generate-key))

;; ## The store's manifest key {#the-stores-manifest-key}

;; Each store holds its own manifest key inside its encrypted EDN. Everyone
;; who can decrypt the store computes the same hashes, so a solo store and a
;; team store get the same kind of manifest. Let's create a store through the
;; CLI and look:

(def store (str dir "/secrets.edn.age"))

(def config
  (cli/normalize-config
   {:app "manifest-demo"
    :default-environment :dev
    :environments {:dev {:secrets-file store
                         :key-file key-file}}}))

^:kindly/hide-code
(defn set-from-pipe!
  "Calls `cli/set-secret!` with `value` on stdin and no terminal attached."
  [config env k value edn?]
  (with-redefs-fn {#'cli/tty? (constantly false)}
    #(with-in-str value (cli/set-secret! config env k {:edn? edn?}))))

;; `set-from-pipe!` is a helper for this chapter that calls `cli/set-secret!`
;; with a string on stdin, as a shell pipe into `bb secrets set` would.

(set-from-pipe! config "dev" ":database/url" "jdbc:postgresql://db/app" false)

(set-from-pipe! config "dev" ":retries" "3" true)

;; Decrypting the file with `age` directly shows what the library added beside
;; our two values:

(keys (edn/read-string (age/decrypt key-file store)))

;; `:com.kirahowe.secrets/store` is the one key the library reserves. Its
;; value is a small map: a format version, the manifest key, and a record of
;; the recipient set the store was last encrypted to. `load-secrets` never
;; returns it:

(keys (secrets/load-secrets store key-file))

;; The reader literals and `get-secret` on a loaded store don't see this
;; metadata either. `edit` shows the plaintext without it and puts it back
;; when you save. `set`, `rm`, and an edited plaintext can't name it, and
;; `new` drops it from a template, so two stores made from one template never
;; share a key. The manifest has no entry for it.

;; The key's lifetime follows one rule:
;;
;; - `new`, and `set` when no store exists yet, generate a key.
;; - `edit`, `set`, and `rm` keep it, unless the recipients changed.
;; - `reencrypt` always generates a new one, and so does `edit`, `set`, or
;;   `rm` when the recipients file no longer matches the set the store
;;   records. Every `:vhash` changes once when that happens.
;;
;; The [teams chapter](secrets_book.teams.html#key-renewal) explains why a
;; change of recipients has to renew the key.

;; Copying an encrypted store file copies its key. Two copies then publish
;; comparable hashes until one of them is re-encrypted.

;; ## The rendered file

;; This is the manifest the two writes above left beside the ciphertext. Its
;; header records a format version, the app, and the SHA-256 of the
;; ciphertext it describes:

(println (slurp (str dir "/secrets.edn.manifest")))

;; Each key path occupies one line, which lets git show changes to individual
;; entries. `manifest/render` produces this text from an entries map.

;; ## Diffing two sets of entries

;; `diff` compares two entry maps and reports the differences a reviewer needs
;; to know about:

(manifest/diff (manifest/entries {:a 1 :b "x"} demo-key)
               (manifest/entries {:b :keyword-now :c true} demo-key))

;; `:changed` includes type changes, count changes, and value changes.

;; ## Verifying the manifest

;; With an identity, `bb secrets verify` decrypts the store, computes its
;; entries under the store's manifest key, and compares them with the
;; committed manifest. It also compares the ciphertext's SHA-256 with the one
;; the manifest records:

(cli/verify! config "dev")

;; Now change a value behind the CLI's back, by decrypting, editing, and
;; encrypting with `age` directly, without updating the manifest:

(let [plain (str dir "/p2.edn")]
  (spit plain (str/replace (age/decrypt key-file store) "db/app" "db/other"))
  (age/encrypt-file! {:identity-file key-file} plain store)
  (io/delete-file plain))

(cli/verify! config "dev")

;; The returned map contains `:exit 1`, and the output names the path whose
;; value changed. A CI job can use that status to reject a stale manifest.

;; A manifest has to be complete before anything is compared: `:version 3`,
;; this project's `:app`, a `:ciphertext-sha`, and a `:type` and a `:vhash` on
;; every entry. A manifest from another app, in another format version, or
;; with an entry that lacks a hash is reported as drift, with or without an
;; identity.

;; In a team store, a `verify` with an identity also compares the recipients
;; file with the recipient set the store records, and reports a difference as
;; drift. The [teams chapter](secrets_book.teams.html) shows that.

;; `reencrypt` regenerates the manifest from the ciphertext:

(cli/reencrypt! config "dev")

(cli/verify! config "dev")

;; ## Verifying without the key

;; The manifest's `:ciphertext-sha` also allows a check that needs no secret
;; material. When no identity is available, `verify` checks that the manifest
;; is complete and that the recorded hash is the digest of the ciphertext. A
;; CI job with no key, and without `age` installed, can therefore detect a
;; ciphertext that changed without its manifest.

;; "No identity is available" means that none was named by an identity
;; environment variable and no key file is present. A named
;; identity that doesn't exist is an error. This config, for the same app and
;; store, has no key file to find:

(def keyless-config
  (cli/normalize-config
   {:app "manifest-demo"
    :default-environment :dev
    :environments {:dev {:secrets-file store}}}))

(cli/verify! keyless-config "dev")

;; `:ok-keyless` passes with exit 0. It shows that the ciphertext is the one
;; the manifest was written for. It can't show that the manifest describes the
;; plaintext, which needs a key. The
;; [production chapter](secrets_book.production.html) turns both modes into
;; CI jobs.

;; Neither mode shows who wrote the ciphertext. age does not sign files, and
;; everyone who can decrypt a store holds its manifest key. Someone who can
;; replace both files can make them agree. The
;; [caveats chapter](secrets_book.caveats.html#no-signatures-the-repository-is-the-boundary)
;; explains what this means for trusting the repository.

;; ## A store without metadata

;; A store whose metadata is missing, malformed, or of another version can't
;; have a manifest. This happens to a store written by another tool. Here is
;; one, encrypted with `age` directly:

(let [plain (str dir "/p3.edn")]
  (spit plain (pr-str {:database/url "jdbc:postgresql://db/app"}))
  (age/encrypt-file! {:identity-file key-file} plain store)
  (io/delete-file plain))

(cli/verify! config "dev")

;; `edit`, `set`, and `rm` fail on such a store with the same message, which
;; says what is wrong and names the repair. `reencrypt` doesn't read the
;; existing metadata, so it writes a current store whatever was there:

(cli/reencrypt! config "dev")

(cli/verify! config "dev")

;; A store that isn't a map at all can't hold metadata, and no command can
;; repair it. Its message says so and names `bb secrets new`.

;; ## Format versioning

;; Every manifest records `:version 3`, the one format this library reads and
;; writes. `verify` reports any other version as unsupported and asks you to
;; regenerate the file with `reencrypt` or upgrade the library.
;;
;; To hash a value, the library first encodes it as a string in which every
;; value is framed as `<type-tag>:<length>:<payload>`, nested for collections.
;; Since every frame carries its own length, a delimiter inside a secret
;; cannot be mistaken for structure. Every frame also carries its type, so
;; `[[1]]` and `[(1)]` encode differently. Map entries and set elements are
;; sorted, so iteration order doesn't matter. Two values the EDN reader can
;; produce share an encoding only when they are equal. The string is hashed as
;; its UTF-16 code units, since a charset encoder would substitute for an
;; unpaired surrogate and could make two different strings hash alike.

;; ## What the manifest discloses, and how to turn it off

;; Anyone with repository access can see:
;;
;; - every key path, through nested maps at every depth;
;; - each value's type, and the size of each collection;
;; - which values in a store are equal, and when a value changes or returns
;;   to an earlier one, for as long as the store keeps one manifest key;
;; - the size of the ciphertext, and the history of both files.
;;
;; Key paths are public, so secret values must not be used as map keys.
;;
;; Everyone who can decrypt the store holds its manifest key, and can test
;; guesses of a value against any manifest published while that key was in
;; use. That includes a former recipient and the manifests from their time.
;;
;; If even the existence of a key is sensitive, disable the manifest for that
;; environment with `:manifest false`. Its changes are then not reviewable.

^:kindly/hide-code
(doseq [f (reverse (file-seq (io/file dir)))]
  (.delete f))
