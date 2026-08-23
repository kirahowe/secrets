;; # Reference

^:kindly/hide-code
(ns secrets-book.reference
  (:require [clojure.string :as str]
            [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.aero :as secrets-aero]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.cli :as cli]
            [com.kirahowe.secrets.manifest :as manifest]
            [scicloj.kindly.v4.kind :as kind]))

;; The signatures and docstrings below come from var metadata at render time.

^:kindly/hide-code
(defn- doc-section
  "Renders Vars' signatures and docstrings as a Markdown section."
  [& vars]
  (kind/md
   (str/join
    "\n\n"
    (for [v vars
          :let [{:keys [arglists doc] var-name :name} (meta v)]]
      (str "#### `" var-name "`\n\n"
           (str/join "  \n"
                     (map #(str "`" (pr-str (cons var-name %)) "`") arglists))
           "\n\n"
           (str/replace (or doc "") #"(?m)^  " ""))))))

;; ## com.kirahowe.secrets

;; Runtime loading. This is the namespace your application code requires.

(doc-section #'secrets/load-secrets
             #'secrets/get-secret
             #'secrets/reader-literals
             #'secrets/merge-readers
             #'secrets/identity-from-env
             #'secrets/resolve-identity-file
             #'secrets/identity-available?
             #'secrets/expand-home
             #'secrets/owner-only-temp-file!)

;; ## com.kirahowe.secrets.aero

;; Optional Aero integration. Requiring this namespace registers the reader
;; methods; Aero must already be present in the consuming application.

(doc-section #'secrets-aero/register!
             #'secrets-aero/reset-cache!)

;; ## com.kirahowe.secrets.age

;; The wrapper over the `age` binary. Use it directly when you script your
;; own workflows; the CLI and runtime namespaces build on it.

(doc-section #'age/installed?
             #'age/ensure-installed!
             #'age/keygen!
             #'age/public-key
             #'age/valid-recipient?
             #'age/encrypt-file!
             #'age/decrypt
             #'age/decrypt-bytes
             #'age/decrypt-to-file!)

;; ## com.kirahowe.secrets.manifest

;; Pure functions behind the committed manifest. Nothing here touches the
;; filesystem or the `age` binary.

(doc-section #'manifest/entries
             #'manifest/value-type
             #'manifest/hmac-key
             #'manifest/render
             #'manifest/diff)

;; ## com.kirahowe.secrets.cli

;; The management task. `run!` is the entry point a `bb.edn` wires up; the
;; command functions are callable from a REPL and return data instead of
;; exiting.

(doc-section #'cli/run!
             #'cli/normalize-config
             #'cli/keygen!
             #'cli/new!
             #'cli/edit!
             #'cli/set-secret!
             #'cli/remove-secret!
             #'cli/verify!
             #'cli/show-key!
             #'cli/add-recipient!
             #'cli/recipients!
             #'cli/reencrypt!
             #'cli/encrypt!
             #'cli/decrypt!)

;; ## Configuration keys

;; The map passed to `cli/run!` and `cli/normalize-config`:

;; | Key | Required | Meaning |
;; |-----|----------|---------|
;; | `:app` | yes | names the default key path `~/.config/<app>/key.txt`; recorded in the manifest |
;; | `:default-environment` | no | environment keyword used when a command omits `[env]` |
;; | `:environments` | yes | map of environment keyword to environment config |

;; Per environment:

;; | Key | Required | Meaning |
;; |-----|----------|---------|
;; | `:secrets-file` | yes | path to the ciphertext; must end in `.age` unless both `:template` and `:manifest` are explicit |
;; | `:key-file` | no | durable key path; default `~/.config/<app>/key.txt` |
;; | `:template` | no | seed for `new`; default `<secrets-file>` with `.example` |
;; | `:manifest` | no | manifest path, or `false` to disable; default `<secrets-file>` with `.manifest` |
;; | `:recipients-file` | no | committed list of age public keys; enables team mode |

;; Normalization also computes `:identity-file` per environment: the
;; `SECRETS_AGE_IDENTITY*` environment variables when set, otherwise `:key-file`.

;; ## Environment variables

;; | Variable | Contents |
;; |----------|----------|
;; | `SECRETS_AGE_IDENTITY_FILE` | path to the key file |
;; | `SECRETS_AGE_IDENTITY` | raw key file contents, used verbatim |
;; | `SECRETS_AGE_IDENTITY_B64` | base64 of the key file contents; invalid base64 throws |

;; ## Reader tags

;; | Tag | Present | Missing key, file, or identity | Decryption failure |
;; |-----|---------|--------------------------------|--------------------|
;; | `#secret/req` | the value | throws | throws |
;; | `#secret/opt` | the value | nil | throws |

;; ## Exit codes

;; `bb secrets verify` exits 0 when every environment checks out (including
;; keyless freshness passes), 1 on any drift, and 2 when an artifact is missing
;; or a keyless run cannot check an older manifest with no ciphertext hash.
;; Other commands exit 0 on success and 1 on failure.

;; ## File conventions

;; | File | Committed | Contents |
;; |------|-----------|----------|
;; | `secrets.edn.age` | yes | the encrypted secrets |
;; | `secrets.edn.manifest` | by default | value-free shape, updated by secrets-writing commands |
;; | `secrets.edn.example` | when used | optional template for `bb secrets new` |
;; | `recipients.txt` | yes | age public keys, one per line, team mode |
;; | `~/.config/<app>/key.txt` | never | the private key |
