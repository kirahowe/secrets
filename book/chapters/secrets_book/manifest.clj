;; # The manifest: reviewable encrypted changes

^:kindly/hide-code
(ns secrets-book.manifest
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.cli :as cli]
            [com.kirahowe.secrets.manifest :as manifest]))

;; Age uses randomized encryption, so two encryptions of the same plaintext
;; differ. A ciphertext diff therefore cannot describe the plaintext change:

(def dir
  (str (java.nio.file.Files/createTempDirectory
        "secrets-manifest-"
        (into-array java.nio.file.attribute.FileAttribute []))))

^:kindly/hide-code
(def key-file (str dir "/key.txt"))

^:kindly/hide-code
(age/keygen! key-file)

(let [plain (str dir "/p.edn")]
  (spit plain (pr-str {:a 1}))
  (age/encrypt-file! key-file plain (str dir "/one.age"))
  (age/encrypt-file! key-file plain (str dir "/two.age"))
  (= (slurp (str dir "/one.age")) (slurp (str dir "/two.age"))))

;; A pull request that changes only `secrets.edn.age` does not show which value
;; changed. The manifest records that information without storing plaintext
;; secret values.

;; ## What the manifest records

;; `entries` maps a secrets value to its shape: every key path, the type of
;; its value, and a count for collections. Plaintext secret values do not
;; appear:

(def secrets-v1
  {:database/url "jdbc:postgresql://db/app"
   :auth {:admins #{"kira@example.com" "sam@example.com"}}
   :retries 3})

(manifest/entries secrets-v1 nil)

;; Secrets-writing CLI commands render this as line-oriented EDN in a
;; `.manifest` file next to the ciphertext. Committed together, the pair gives
;; you a reviewable diff: the ciphertext changes opaquely, and the manifest
;; line for `[:auth :admins]` shows the set grew from 2 to 3.

;; ## Catching value changes with a keyed hash

;; Shape alone misses one case: a value that changed without changing type,
;; which is what a rotation looks like. For that, single-key environments add
;; a `:vhash` to each entry, an HMAC of the value keyed by a secret derived
;; from the private key:

(def hkey (manifest/hmac-key (slurp key-file)))

(manifest/entries {:token "old-value"} hkey)

(manifest/entries {:token "new-value"} hkey)

;; The shape is unchanged but the hash differs. Someone with only the
;; repository cannot test guesses for a low-entropy value because the HMAC key
;; is derived from the private identity. The stored hash is truncated to eight
;; bytes; it is a change marker, not a general-purpose integrity check.

;; For a native age identity, key derivation reads only `AGE-SECRET-KEY` lines,
;; so comments written by `age-keygen` do not matter. If the file has no such
;; line, as with an SSH identity, derivation uses the complete trimmed contents.
;; Two copies of the same native key, one with comments stripped, produce
;; identical hashes:

(let [with-comments (slurp key-file)
      without-comments (->> (str/split-lines with-comments)
                            (filter #(str/starts-with? % "AGE-SECRET-KEY"))
                            first)]
  (java.util.Arrays/equals (manifest/hmac-key with-comments)
                           (manifest/hmac-key without-comments)))

;; In multi-recipient mode there is no shared private key to derive from, so
;; team manifests skip `:vhash` and record structure only.

;; ## The rendered file

;; `render` produces the text that gets committed. The header records the
;; app, a format version, and the SHA-256 of the ciphertext it describes:

(def rendered
  (manifest/render {:app "manifest-demo" :ciphertext-sha "0b7d9f31aa..."}
                   (manifest/entries secrets-v1 hkey)))

^:kindly/hide-code
(print rendered)

;; Each key path occupies one line, so git shows entry-level changes.

;; ## Diffing two shapes

;; `diff` compares two entry maps and reports what a reviewer would want to
;; know:

(manifest/diff (manifest/entries {:a 1 :b "x"} nil)
               (manifest/entries {:b :keyword-now :c true} nil))

;; `:changed` covers type changes, count changes, and, when hashes are
;; present, value changes.

;; ## Verifying the manifest

;; `bb secrets verify` decrypts the secrets, regenerates the entries, and
;; compares them to the committed manifest. First set up an environment:

(def config
  (cli/normalize-config
   {:app "manifest-demo"
    :default-environment :dev
    :environments {:dev {:secrets-file (str dir "/secrets.edn.age")
                         :key-file key-file}}}))

^:kindly/hide-code
(let [plain (str dir "/p2.edn")]
  (spit plain (pr-str secrets-v1))
  (age/encrypt-file! key-file plain (str dir "/secrets.edn.age"))
  (io/delete-file plain))

(cli/reencrypt! config "dev")

(cli/verify! config "dev")

;; Next, re-encrypt different secrets directly with `age`, without updating
;; the manifest:

(let [plain (str dir "/p3.edn")]
  (spit plain (pr-str (assoc secrets-v1 :sneaky/addition "oops")))
  (age/encrypt-file! key-file plain (str dir "/secrets.edn.age"))
  (io/delete-file plain))

(cli/verify! config "dev")

;; The returned map contains `:exit 1`, and the output names the added path. A
;; CI job can use that status to reject a stale manifest.

;; ## Verifying without the key

;; The manifest header's `:ciphertext-sha` enables a check that needs no
;; secret material at all. When `verify` finds no identity, it compares the
;; recorded hash against the actual ciphertext. A CI job with no key, and not
;; even `age` installed, can detect a ciphertext changed without regenerating
;; its manifest. Repair the environment, then verify with a missing key:

^:kindly/hide-code
(cli/reencrypt! config "dev")

(def keyless-config
  (-> (cli/normalize-config
       {:app "manifest-demo"
        :default-environment :dev
        :environments {:dev {:secrets-file (str dir "/secrets.edn.age")
                             :key-file (str dir "/no-key-here.txt")}}})
      ;; Environment identities normally override :key-file. Pin the resolved
      ;; path so this example stays keyless on every build machine.
      (assoc-in [:environments :dev :identity-file]
                (str dir "/no-key-here.txt"))))

(cli/verify! keyless-config "dev")

;; `:ok-keyless` passes with exit 0. It checks freshness, not values; the
;; full comparison still needs a key. The
;; [production chapter](secrets_book.production.html) turns both modes into
;; CI jobs.

;; ## Format versioning

;; Every manifest records `:version 2`. The version names the encoding used to
;; hash values, and it is mixed into the HMAC key, so a hash written by one
;; version can never be read as another's. Version 2 frames each value as
;; `<type-tag>:<code-unit-count>:<payload>`, recursively: because every field
;; carries its own length, a `=` or `;` *inside* a secret cannot be mistaken for
;; the encoding's own punctuation, and because every field carries its own type
;; tag, `[[1]]` and `[(1)]` hash differently. The framed string is hashed as its
;; raw UTF-16 code units, not through a charset encoder, which would substitute
;; a replacement character for an unpaired surrogate and fold two distinct
;; secrets onto one hash. `verify` reports any other version — including a
;; legacy `:version 1` file — as drift and asks you to regenerate the file with
;; `reencrypt` or upgrade the library.

;; ## What the manifest leaks, and how to turn it off

;; Key names, value types, and collection counts are visible to anyone with
;; repo access. If even a key's existence is sensitive, disable the manifest
;; for that environment with `:manifest false`; its ciphertext diff will be
;; opaque.

^:kindly/hide-code
(doseq [f (reverse (file-seq (io/file dir)))]
  (.delete f))
