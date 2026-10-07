;; # The manifest: reviewable encrypted changes

^:kindly/hide-code
(ns secrets-book.manifest
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
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
(age/keygen! key-file)

(let [plain (str dir "/p.edn")]
  (spit plain (pr-str {:a 1}))
  (age/encrypt-file! key-file plain (str dir "/one.age"))
  (age/encrypt-file! key-file plain (str dir "/two.age"))
  (= (slurp (str dir "/one.age")) (slurp (str dir "/two.age"))))

;; If a pull request only changes `secrets.edn.age`, there is very little for a
;; reviewer to learn from the diff. The manifest records the useful parts of
;; the change without storing the plaintext secret values.

;; ## What the manifest records

;; `entries` describes the shape of a secrets value. It includes every key
;; path, the type of its value, and a count for collections, but does not
;; include the plaintext values themselves:

(def secrets-v1
  {:database/url "jdbc:postgresql://db/app"
   :auth {:admins #{"kira@example.com" "sam@example.com"}}
   :retries 3})

(manifest/entries secrets-v1 nil)

;; CLI commands that write secrets render this as line-oriented EDN in a
;; `.manifest` file beside the ciphertext. When both files are committed, the
;; ciphertext still changes opaquely, but the manifest gives you something
;; useful to review. For example, the line for `[:auth :admins]` can show that
;; the set grew from 2 to 3.

;; ## Catching value changes with a keyed hash

;; The shape alone can't show a value changing without changing type, which
;; is what happens during a rotation. In a single-key environment, each entry
;; therefore includes a `:vhash`: an HMAC of the value, keyed by a secret
;; derived from the private key.

(def hkey (manifest/hmac-key (slurp key-file)))

(manifest/entries {:token "old-value"} hkey)

(manifest/entries {:token "new-value"} hkey)

;; The shape is the same in these two entries, but the hash is different.
;; Someone with access only to the repository can't use it to test guesses for
;; a low-entropy value because the HMAC key comes from the private identity.
;; The stored hash is truncated to eight bytes. It is intended to mark a
;; change, rather than serve as a general-purpose integrity check.

;; For a native age identity, key derivation reads only the
;; `AGE-SECRET-KEY` lines, so comments written by `age-keygen` do not affect the
;; result. If the file has no such line, as with an SSH identity, derivation
;; uses the complete trimmed contents. Two copies of the same native key
;; therefore produce identical hashes even if comments have been removed from
;; one of them:

(let [with-comments (slurp key-file)
      without-comments (->> (str/split-lines with-comments)
                            (filter #(str/starts-with? % "AGE-SECRET-KEY"))
                            first)]
  (java.util.Arrays/equals (manifest/hmac-key with-comments)
                           (manifest/hmac-key without-comments)))

;; In multi-recipient mode, there is no shared private key to derive the HMAC
;; key from, so team manifests omit `:vhash` and record only the structure.

;; ## The rendered file

;; `render` produces the text that will be committed. Its header records the
;; app, a format version, and the SHA-256 hash of the ciphertext it describes:

(def rendered
  (manifest/render {:app "manifest-demo" :ciphertext-sha "0b7d9f31aa..."}
                   (manifest/entries secrets-v1 hkey)))

^:kindly/hide-code
(print rendered)

;; Each key path occupies one line, which lets git show changes to individual
;; entries.

;; ## Diffing two shapes

;; `diff` compares two entry maps and reports the differences a reviewer needs
;; to know about:

(manifest/diff (manifest/entries {:a 1 :b "x"} nil)
               (manifest/entries {:b :keyword-now :c true} nil))

;; `:changed` includes type changes, count changes, and, when hashes are
;; present, value changes.

;; ## Verifying the manifest

;; `bb secrets verify` decrypts the secrets, regenerates their entries, and
;; compares the result with the committed manifest. First, set up an
;; environment:

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

;; Now re-encrypt a different set of secrets directly with `age`, without
;; updating the manifest:

(let [plain (str dir "/p3.edn")]
  (spit plain (pr-str (assoc secrets-v1 :sneaky/addition "oops")))
  (age/encrypt-file! key-file plain (str dir "/secrets.edn.age"))
  (io/delete-file plain))

(cli/verify! config "dev")

;; The returned map contains `:exit 1`, and the output names the path that was
;; added. A CI job can use that status to reject a stale manifest. Verification
;; also rejects a manifest that belongs to another `:app`, or one that does not
;; record an app at all. These checks apply even when the manifest is otherwise
;; up to date.

;; ## Verifying without the key

;; The manifest header's `:ciphertext-sha` also enables a check that does not
;; need any secret material. When `verify` cannot find an identity, it compares
;; the recorded hash with the actual ciphertext. This allows a CI job with no
;; key, and without even `age` installed, to detect that a ciphertext changed
;; without its manifest being regenerated. First regenerate the manifest, then
;; verify with a missing key:

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

;; `:ok-keyless` passes with exit 0. This checks freshness, but checking the
;; values still requires a key. The
;; [production chapter](secrets_book.production.html) turns both modes into
;; CI jobs.

;; Neither mode proves who wrote the ciphertext. age does not sign files, and
;; `verify` reports drift rather than authorship. The
;; [caveats chapter](secrets_book.caveats.html#no-signatures-the-repository-is-the-boundary)
;; explains what this means for trusting the repository.

;; ## Format versioning

;; Every manifest records `:version 2`. The version identifies the encoding
;; used to hash values, and it is mixed into the HMAC key. This prevents a hash
;; written by one version from being read as if it belonged to another.
;;
;; Version 2 recursively frames each value as
;; `<type-tag>:<code-unit-count>:<payload>`. Since every field includes its own
;; length, a `=` or `;` *inside* a secret cannot be mistaken for punctuation in
;; the encoding. Every field also includes its type tag, so `[[1]]` and `[(1)]`
;; hash differently. The framed string is hashed as raw UTF-16 code units
;; instead of passing through a charset encoder. A charset encoder would
;; substitute a replacement character for an unpaired surrogate and could
;; collapse two distinct secrets into the same hash. `verify` reports any other
;; version, including a legacy `:version 1` file, as drift and asks you to
;; regenerate the file with `reencrypt` or upgrade the library.

;; ## What the manifest leaks, and how to turn it off

;; Anyone with repository access can see key names, value types, and collection
;; counts. In single-key mode they can also see which values are equal and when
;; a value changes: equal values at different paths, or in different
;; environments that share a key, have equal hashes, and a value that returns to
;; an earlier one shows up in the history. Team manifests carry no hashes. Key
;; paths through nested maps are public at every depth, so secret values must
;; not be used as map keys. If even the existence of a key is sensitive, disable the manifest
;; for that environment with `:manifest false`. Its ciphertext diff will then
;; be opaque.

^:kindly/hide-code
(doseq [f (reverse (file-seq (io/file dir)))]
  (.delete f))
