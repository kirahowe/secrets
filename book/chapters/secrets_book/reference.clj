;; # Reference

^:kindly/hide-code
(ns secrets-book.reference
  (:require [clojure.string :as str]
            [com.kirahowe.secrets]
            [com.kirahowe.secrets.aero]
            [com.kirahowe.secrets.cli]
            [com.kirahowe.secrets.init]
            [scicloj.kindly.v4.kind :as kind]))

;; The signatures and docstrings below come from var metadata at render time.
;; Each listing is checked against the namespace when the book is built, so it
;; names every public var and nothing else.

;; Four namespaces are the public API: `com.kirahowe.secrets`,
;; `com.kirahowe.secrets.aero`, `com.kirahowe.secrets.cli`, and
;; `com.kirahowe.secrets.init`. They are listed below.
;;
;; `com.kirahowe.secrets.age`, `com.kirahowe.secrets.manifest`,
;; `com.kirahowe.secrets.fs`, `com.kirahowe.secrets.safe-edn`, and
;; `com.kirahowe.secrets.source` are implementation namespaces. Their vars are
;; public so the other namespaces can use them. They are not listed here and
;; can change without notice.
;;
;; The library is in alpha, so the public API can still change between
;; releases too.

^:kindly/hide-code
(defn- doc-section
  "Renders the public vars of namespace `ns-sym` named by `var-names`, in that
  order, as a Markdown section of signatures and docstrings. Throws unless
  `var-names` is exactly the namespace's public vars."
  [ns-sym var-names]
  (let [publics (ns-publics ns-sym)]
    (when-not (= (set var-names) (set (keys publics)))
      (throw (ex-info (str "The listing for " ns-sym " does not match its public vars.")
                      {:missing (remove (set var-names) (keys publics))
                       :unknown (remove (set (keys publics)) var-names)})))
    (kind/md
     (str/join
      "\n\n"
      (for [var-name var-names
            :let [{:keys [arglists doc]} (meta (publics var-name))]]
        (str "#### `" var-name "`\n\n"
             (when arglists
               (str (str/join "  \n"
                              (map #(str "`" (pr-str (cons var-name %)) "`") arglists))
                    "\n\n"))
             (-> (or doc "")
                 (str/replace #"\[\[([^\]]+)\]\]"
                              (fn [[_ linked]] (str "`" linked "`")))
                 (str/replace #"(?m)^  " ""))))))))

;; ## com.kirahowe.secrets

;; Application code requires this namespace to load secrets at runtime.

(doc-section 'com.kirahowe.secrets
             '[load-secrets
               get-secret
               reader-literals
               merge-readers
               with-identity
               expand-home
               default-key-file])

;; ## com.kirahowe.secrets.aero

;; The optional Aero integration. Aero must already be a dependency
;; of the consuming application.

(doc-section 'com.kirahowe.secrets.aero
             '[read-config])

;; ## com.kirahowe.secrets.cli

;; This namespace implements the management task. `run!` is the entry point
;; wired up by `bb.edn`. The command functions can also be called from a REPL
;; and return data instead of exiting.

(doc-section 'com.kirahowe.secrets.cli
             '[run!
               normalize-config
               keygen!
               new!
               edit!
               set-secret!
               remove-secret!
               verify!
               doctor!
               show-key!
               add-recipient!
               recipients!
               reencrypt!])

;; ## com.kirahowe.secrets.init

;; The project initializer. `-main` is the command-line entry point, and the
;; other functions let a tool preview or apply the same plan.

(doc-section 'com.kirahowe.secrets.init
             '[-main
               init!
               plan
               apply-plan!
               parse-args
               proposed-config
               task-spec
               library-dependency])

;; ## Configuration keys

;; The map passed to `cli/run!` and `cli/normalize-config`. A key that is not
;; in these tables is an error.

;; | Key | Required | Meaning |
;; |-----|----------|---------|
;; | `:app` | yes | names the default key path `~/.config/<app>/key.txt`; recorded in the manifest |
;; | `:default-environment` | no | environment keyword used when a command omits `[env]` |
;; | `:environments` | yes | map of environment keyword to environment config |

;; Per environment:

;; | Key | Required | Meaning |
;; |-----|----------|---------|
;; | `:secrets-file` | yes | path to the ciphertext; must end in `.age` unless both `:template` and `:manifest` are explicit |
;; | `:key-file` | no | where `keygen` writes and `show-key` reads, and the identity used when nothing else is named; default `~/.config/<app>/key.txt` |
;; | `:identity-file` | no | explicit identity for commands that decrypt; used before the environment variables |
;; | `:template` | no | what `new` opens; default `<secrets-file>` with `.example` in place of `.age` |
;; | `:manifest` | no | manifest path, or `false` to keep none; default `<secrets-file>` with `.manifest` in place of `.age` |
;; | `:recipients-file` | no | committed list of age public keys; enables team mode |

;; Path values are strings, and `:environments` is a map of maps. An
;; `:identity-file` you set has to exist when a command that needs an identity
;; runs.

;; ## Size bounds

;; These are fixed. A file or value past one is refused.

;; | Bound | Applies to |
;; |-------|------------|
;; | 16 MiB | ciphertext read by `load-secrets` and the reader literals |
;; | 8 MiB | plaintext of a store or template |
;; | 100 | nested EDN collections |
;; | 256 KiB | a recipients file |
;; | 1 MiB | a manifest |

;; ## Environment variables

;; | Variable | Contents |
;; |----------|----------|
;; | `SECRETS_AGE_IDENTITY_FILE` | path to the key file; the file has to exist |
;; | `SECRETS_AGE_IDENTITY` | raw key file contents, used verbatim |
;; | `SECRETS_AGE_IDENTITY_B64` | base64 of the key file contents; invalid base64 throws |

;; They are checked in that order, after an explicit identity path and before
;; the key file. A variable that is set but empty is an error. `VISUAL` and
;; `EDITOR` choose the editor for `new` and `edit`.

;; ## Reader tags

;; | Situation | `#secret/req` | `#secret/opt` |
;; |-----------|---------------|---------------|
;; | key present | the value | the value |
;; | key missing, no secrets file, or no identity available | throws | nil |
;; | a named identity file does not exist | throws | throws |
;; | decryption fails | throws | throws |

;; ## Exit codes

;; | Command | 0 | 1 | 2 |
;; |---------|---|---|---|
;; | `verify` | every manifest agrees with its ciphertext | drift | a ciphertext or manifest is missing, or an environment could not be checked |
;; | `doctor` | healthy | a warning | the setup is invalid |
;; | every other command | success | failure | |

;; For `verify`, drift decides the exit code before a missing file does.

;; ## File conventions

;; | File | Committed | Contents |
;; |------|-----------|----------|
;; | `secrets.edn.age` | yes | the encrypted secrets |
;; | `secrets.edn.manifest` | by default | key paths, types, and keyed value hashes; updated by every write |
;; | `secrets.edn.example` | when used | optional template for `bb secrets new` |
;; | `recipients.txt` | yes | age public keys, one per line, team mode |
;; | `~/.config/<app>/key.txt` | never | the private key |
