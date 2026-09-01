;; # Reference

^:kindly/hide-code
(ns secrets-book.reference
  (:require [clojure.string :as str]
            [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.aero :as secrets-aero]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.cli :as cli]
            [com.kirahowe.secrets.fs :as fs]
            [com.kirahowe.secrets.init :as init]
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
           (-> (or doc "")
               (str/replace #"\[\[([^\]]+)\]\]"
                            (fn [[_ var-name]] (str "`" var-name "`")))
               (str/replace #"(?m)^  " "")))))))

;; ## com.kirahowe.secrets

;; Runtime loading. This is the namespace your application code requires.

(doc-section #'secrets/load-secrets
             #'secrets/get-secret
             #'secrets/reader-literals
             #'secrets/merge-readers
             #'secrets/default-limits
             #'secrets/identity-from-env
             #'secrets/resolve-identity-file
             #'secrets/identity-available?
             #'secrets/with-identity
             #'secrets/reset-identity-cache!
             #'secrets/expand-home)

;; `load-secrets` accepts local filesystem sources, local `file:` locators, and
;; `jar:file:` classpath resources. It deliberately rejects HTTP(S), remote or
;; nested jars, and arbitrary input-stream values.

;; ## com.kirahowe.secrets.fs

;; Owner-only temporary-file creation for callers that must materialize
;; sensitive bytes without a default-permission window.

(doc-section #'fs/owner-only-temp-file!)

;; ## com.kirahowe.secrets.aero

;; Optional Aero integration. Requiring this namespace registers the reader
;; methods; Aero must already be present in the consuming application.

(doc-section #'secrets-aero/register!
             #'secrets-aero/reset-cache!)

;; ## com.kirahowe.secrets.age

;; The wrapper over the `age` binary. Use it directly when you script your
;; own workflows; the CLI and runtime namespaces build on it.

;; ### Path arguments

;; The positional input is passed behind an option terminator (`--`), so a
;; filename can never be read as an option, and every path-valued argument —
;; that input, the `-o` output, the `-i` identity, the `-R` recipients file — is
;; normalized so a dash-leading path becomes `./-name`: age reads a bare `-`
;; from standard input even behind the terminator, so the prefix is what keeps
;; a filename a filename. A blank or nil path throws instead of quietly falling
;; back to standard input. Recipient strings passed as `:recipients` are values
;; rather than paths, and are used as given.

(doc-section #'age/version
             #'age/installed?
             #'age/ensure-installed!
             #'age/keygen!
             #'age/public-key
             #'age/valid-recipient?
             #'age/encrypt-file!
             #'age/decrypt
             #'age/decrypt-bytes
             #'age/decrypt-to-stream!
             #'age/decrypt-to-file!
             #'age/default-max-plaintext-bytes)

;; ## com.kirahowe.secrets.manifest

;; Pure functions behind the committed manifest. Nothing here touches the
;; filesystem or the `age` binary.

(doc-section #'manifest/entries
             #'manifest/value-type
             #'manifest/hmac-key
             #'manifest/render
             #'manifest/diff)

;; ## com.kirahowe.secrets.init

;; The one-shot Babashka project initializer. `-main` is the command-line entry
;; point; the other functions are available to tools that want to preview or
;; apply the same scaffold programmatically.

(doc-section #'init/init!
             #'init/proposed-config
             #'init/task-spec
             #'init/merge-bb-edn
             #'init/root-trust
             #'init/filesystem-capability)

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
             #'cli/doctor!
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
;; | `:limits` | no | positive integer bounds merged over the CLI defaults for every environment |

;; Per environment:

;; | Key | Required | Meaning |
;; |-----|----------|---------|
;; | `:secrets-file` | yes | path to the ciphertext; must end in `.age` unless both `:template` and `:manifest` are explicit |
;; | `:key-file` | no | durable key path; default `~/.config/<app>/key.txt` |
;; | `:identity-file` | no | explicit decrypt-side identity; environment variables still win |
;; | `:template` | no | seed for `new`; default `<secrets-file>` with `.example` |
;; | `:manifest` | no | manifest path, or `false` to disable; default `<secrets-file>` with `.manifest` |
;; | `:recipients-file` | no | committed list of age public keys; enables team mode |

;; Normalization also computes `:identity-file` per environment: the
;; `SECRETS_AGE_IDENTITY*` environment variables when set, otherwise `:key-file`.

;; ### Configuration limits

;; | Key | Default | Meaning |
;; |-----|---------|---------|
;; | `:max-plaintext-bytes` | 8 MiB | decrypted store size |
;; | `:max-edn-depth` | 100 | nested EDN collection depth |
;; | `:max-recipients` | 256 | recipient entries in one file |
;; | `:max-recipient-chars` | 1,024 | characters in one recipient entry |
;; | `:max-recipients-bytes` | 256 KiB | total recipients-file size |
;; | `:max-manifest-bytes` | 1 MiB | manifest file size |
;; | `:max-manifest-entries` | 10,000 | key entries in one manifest |

;; The separate runtime `secrets/default-limits` also includes
;; `:max-source-bytes` (16 MiB) for local file and jar-resource loading.

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
;; keyless freshness passes), 1 on drift, and 2 when an artifact is missing or a
;; keyless run cannot check an older manifest with no ciphertext hash. `doctor`
;; exits 0 when healthy, 1 when action is needed, and 2 for invalid
;; configuration. Other commands exit 0 on success and 1 on failure.

;; ## File conventions

;; | File | Committed | Contents |
;; |------|-----------|----------|
;; | `secrets.edn.age` | yes | the encrypted secrets |
;; | `secrets.edn.manifest` | by default | value-free shape, updated by secrets-writing commands |
;; | `secrets.edn.example` | when used | optional template for `bb secrets new` |
;; | `recipients.txt` | yes | age public keys, one per line, team mode |
;; | `~/.config/<app>/key.txt` | never | the private key |
