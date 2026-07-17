;; # The manifest: reviewing what you cannot read

^{:kindly/hide-code true}
(ns secrets-book.manifest
  (:require [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.cli :as cli]
            [com.kirahowe.secrets.manifest :as manifest]
            [clojure.java.io :as io]
            [clojure.string :as str]))

;; Committing encrypted secrets buys you history and review, in theory. In
;; practice, age re-encrypts the whole file every time, so the diff of a
;; ciphertext is noise. Two encryptions of the same plaintext do not even
;; match each other:

(def dir (str (java.nio.file.Files/createTempDirectory
               "secrets-manifest-" (into-array java.nio.file.attribute.FileAttribute []))))

^{:kindly/hide-code true}
(def key-file (str dir "/key.txt"))

^{:kindly/hide-code true}
(age/keygen! key-file)

(let [plain (str dir "/p.edn")]
  (spit plain (pr-str {:a 1}))
  (age/encrypt-file! key-file plain (str dir "/one.age"))
  (age/encrypt-file! key-file plain (str dir "/two.age"))
  (= (slurp (str dir "/one.age")) (slurp (str dir "/two.age"))))

;; So a pull request that changes `secrets.edn.age` tells the reviewer
;; nothing. Did it add a key? Rotate one? Delete half the file? The manifest
;; exists to answer exactly that question without exposing a single value.

;; ## What the manifest records

;; `entries` maps a secrets value to its shape: every key path, the type of
;; its value, and a count for collections. Values themselves never appear:

(def secrets-v1
  {:database/url "jdbc:postgresql://db/app"
   :auth {:admins #{"kira@example.com" "sam@example.com"}}
   :retries 3})

(manifest/entries secrets-v1 nil)

;; The CLI writes this, rendered as line-oriented EDN, to a `.manifest` file
;; next to the ciphertext on every save. Committed together, the pair gives
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

;; Same shape, different hash, visible diff. Two properties make this safe to
;; commit. The hash is keyed, so someone with only the repo cannot brute-force
;; a low-entropy value by hashing guesses; without the private key there is
;; nothing to compare against. And it is truncated to 8 bytes, enough to show
;; change, useless as a fingerprint.

;; The key derivation reads only the `AGE-SECRET-KEY` line of the identity
;; file, so the comment lines age-keygen writes do not matter. Two copies of
;; the same key, one with comments stripped, produce identical hashes:

(let [with-comments    (slurp key-file)
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

^{:kindly/hide-code true}
(print rendered)

;; One key path per line, so git diffs stay line-oriented and merge conflicts
;; stay rare.

;; ## Diffing two shapes

;; `diff` compares two entry maps and reports what a reviewer would want to
;; know:

(manifest/diff (manifest/entries {:a 1 :b "x"} nil)
               (manifest/entries {:b :keyword-now :c true} nil))

;; `:changed` covers type changes, count changes, and, when hashes are
;; present, value changes.

;; ## verify: trust, then check

;; A manifest is only useful while it is true. `bb secrets verify` decrypts
;; the secrets, regenerates the entries, and compares them to the committed
;; manifest. Set up an environment and watch it pass:

(def config
  (cli/normalize-config
   {:app "manifest-demo"
    :default-environment :dev
    :environments {:dev {:secrets-file (str dir "/secrets.edn.age")
                         :key-file     key-file}}}))

^{:kindly/hide-code true}
(let [plain (str dir "/p2.edn")]
  (spit plain (pr-str secrets-v1))
  (age/encrypt-file! key-file plain (str dir "/secrets.edn.age"))
  (io/delete-file plain))

(cli/reencrypt! config "dev")

(cli/verify! config "dev")

;; Now sabotage it. Re-encrypt different secrets out-of-band, the way a
;; hurried teammate with raw `age` might, skipping the manifest write:

(let [plain (str dir "/p3.edn")]
  (spit plain (pr-str (assoc secrets-v1 :sneaky/addition "oops")))
  (age/encrypt-file! key-file plain (str dir "/secrets.edn.age"))
  (io/delete-file plain))

(cli/verify! config "dev")

;; Exit code 1, and the output names the path that appeared. Wiring this into
;; CI means a stale manifest cannot merge.

;; ## Verifying without the key

;; The manifest header's `:ciphertext-sha` enables a check that needs no
;; secret material at all. When `verify` finds no identity, it compares the
;; recorded hash against the actual ciphertext. A CI job with no key, and not
;; even `age` installed, still catches the most common drift, which is a
;; ciphertext edited without regenerating its manifest. Repair the
;; environment, then verify with a key that does not exist:

^{:kindly/hide-code true}
(cli/reencrypt! config "dev")

(def keyless-config
  (cli/normalize-config
   {:app "manifest-demo"
    :default-environment :dev
    :environments {:dev {:secrets-file (str dir "/secrets.edn.age")
                         :key-file     (str dir "/no-key-here.txt")}}}))

(cli/verify! keyless-config "dev")

;; `:ok-keyless` passes with exit 0. It checks freshness, not values; the
;; full comparison still needs a key. The
;; [production chapter](secrets_book.production.html) turns both modes into
;; CI jobs.

;; ## Format versioning

;; Every manifest records `:version 1`. If a future library version changes
;; the format, `verify` reports an unsupported version as drift with a clear
;; message instead of producing a confusing pile of false differences. Small
;; thing, but it means the file format can evolve without ambushing anyone.

;; ## What the manifest leaks, and how to turn it off

;; Key names, value types, and collection counts are visible to anyone with
;; repo access. Usually that is the point; occasionally even a key's
;; existence is sensitive. Disable per environment with `:manifest false`,
;; and that environment trades reviewability for opacity.

^{:kindly/hide-code true}
(doseq [f (reverse (file-seq (io/file dir)))]
  (.delete f))
