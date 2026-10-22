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
;; `com.kirahowe.secrets.age`, `com.kirahowe.secrets.identity`,
;; `com.kirahowe.secrets.keychain`,
;; `com.kirahowe.secrets.manifest`,
;; `com.kirahowe.secrets.store`, `com.kirahowe.secrets.fs`,
;; `com.kirahowe.secrets.safe-edn`, and `com.kirahowe.secrets.source` are
;; implementation namespaces. Their vars are
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
               resolve-identity
               identity-available?])

;; ## com.kirahowe.secrets.aero

;; The optional Aero integration. Aero must already be a dependency
;; of the consuming application.

(doc-section 'com.kirahowe.secrets.aero
             '[read-config])

;; ## com.kirahowe.secrets.cli

;; This namespace implements the management task. `run!` is the entry point
;; of a process, wired up by `bb.edn` or called from a JVM `-main`. The
;; command functions are for a REPL or a program: they return data and never
;; exit.

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

;; The project initializer. `-main` is the command-line entry point, and
;; `init!` does the same from a program.

(doc-section 'com.kirahowe.secrets.init
             '[-main
               init!])

;; ## Configuration keys

;; The map passed to `cli/run!` and `cli/normalize-config`. It is validated
;; before a command runs, and a key that is not in these tables is an error.

;; | Key | Required | Meaning |
;; |-----|----------|---------|
;; | `:app` | yes | names the app's macOS Keychain item (service `com.kirahowe.secrets`, account `<app>`); recorded in the manifest |
;; | `:default-environment` | no | environment keyword used when a command omits `[env]`; it has to name a configured environment |
;; | `:environments` | yes | map of environment keyword to environment config, itself a map |

;; Per environment:

;; | Key | Required | Meaning |
;; |-----|----------|---------|
;; | `:secrets-file` | yes | path to the ciphertext; must end in `.age` unless both `:template` and `:manifest` are explicit |
;; | `:key-command` | no | a vector of a program and its arguments, run without a shell, whose standard output is the key; commands read the key with it when no identity variable is set, and `keygen` refuses to run; no default |
;; | `:key-file` | no | a file that holds the key: `keygen` writes it, `show-key` reads it, and commands use it when no identity variable is set; no default |
;; | `:template` | no | what `new` opens; default `<secrets-file>` with `.example` in place of `.age` |
;; | `:manifest` | no | manifest path, or `false` to keep none; default `<secrets-file>` with `.manifest` in place of `.age` |
;; | `:recipients-file` | no | committed list of age public keys; enables team mode |

;; Every environment setting except `:key-command` is a string holding a local
;; filesystem path, with a leading `~` expanded, and `:manifest` may also be
;; `false`. `:key-command` is a vector of non-blank strings, and an
;; environment sets at most one of `:key-command` and `:key-file`. A
;; URI-shaped path is refused with `:invalid-config` (`:disallowed-identity`
;; for `:key-file`). A command's identity comes from the
;; `SECRETS_AGE_IDENTITY*` variables, then `:key-command`, then `:key-file`,
;; then on macOS the Keychain item for the app. `:identity-file` is a runtime
;; option, not a config key. No file may serve two purposes across the
;; environments. They may share a template, a key or identity file, or a
;; recipients file, and two of them may name the same secrets file or manifest
;; only when they name both the same.

;; ## Size bounds

;; These are fixed. A file or value past one is refused.

;; | Bound | Applies to |
;; |-------|------------|
;; | 16 MiB | a ciphertext that `load-secrets`, the reader literals, or a command reads |
;; | 8 MiB | the plaintext a command writes, and a template |
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
;; a `:key-command`, a `:key-file`, and the Keychain. The two that carry the
;; key itself reach `age` on standard input and are never written to a file.
;; A variable that is set but empty is an error
;; (`:invalid-identity`). `VISUAL` and
;; `EDITOR` choose the editor for `new` and `edit`.

;; ## Reader tags

;; | Situation | `#secret/req` | `#secret/opt` |
;; |-----------|---------------|---------------|
;; | key present | the value | the value |
;; | key missing, no secrets file, or no identity named and the app's key (its `:key-file` or Keychain item) absent | throws | nil |
;; | a named identity file does not exist | throws | throws |
;; | decryption fails | throws | throws |

;; Read through `com.kirahowe.secrets.aero/read-config` without a `:secrets`
;; option, `#secret/req` throws `:invalid-config` and `#secret/opt` reads nil.

;; ## Exit codes

;; | Command | 0 | 1 | 2 |
;; |---------|---|---|---|
;; | `verify` | every manifest agrees with its ciphertext | the only problem is drift | anything else stopped it: a missing file, an identity or decryption failure, an unknown environment, an invalid configuration |
;; | `doctor` | healthy | a warning: `age`, the secrets file, the manifest, the recipients file, or the key is not there | an invalid configuration, identity, or recipients file, or it could not run |
;; | every other command | success | any failure | |

;; For `verify`, a 2 from one environment wins over drift in another.

;; ## Failure reasons

;; Every `ex-info` the library throws has a `:reason` keyword in its data.
;; These are the ones a caller can usefully branch on:

;; | Reasons | Meaning |
;; |---------|---------|
;; | `:no-identity`, `:invalid-identity`, `:disallowed-identity` | no identity is available, or a named identity file is missing; an identity variable is blank or not base64, or a `:key-command` is malformed or printed nothing; an identity path is URI-shaped or holds key contents |
;; | `:key-command-failed`, `:keychain-failed` | the `:key-command` could not start or exited with an error; the macOS Keychain could not be read or written |
;; | `:no-file`, `:disallowed-source`, `:source-too-large` | the source is nil, blank, absent, a directory, or unreadable, or a file the CLI needs cannot be read; it is not a local path or a classpath resource; the ciphertext is past 16 MiB, at runtime or in the CLI |
;; | `:decrypt-failed`, `:age-not-installed` | `age` could not decrypt with this identity; the `age` binary is not on the `PATH` |
;; | `:edn-empty`, `:edn-extra-values`, `:edn-malformed`, `:edn-too-deep` | the plaintext is not exactly one well-formed EDN value |
;; | `:missing-key` | `#secret/req` named a key the store does not have |
;; | `:invalid-config`, `:unknown-config-key` | the CLI config, or the options of the Aero `read-config`, cannot be used; a URI-shaped path in the config is `:invalid-config` |
;; | `:usage` | a command line the CLI cannot place: an unknown command, option, or environment, or a missing or surplus argument |
;; | `:invalid-store`, `:secrets-not-a-map`, `:reserved-key`, `:path-not-a-map`, `:no-such-key`, `:blank-value` | a write the CLI refused, and why |
;; | `:input-too-large`, `:invalid-recipient`, `:no-recipients`, `:no-recipients-file` | a recipients file, manifest, template, or plaintext the CLI was given is too large; the recipients file holds an invalid line, or nobody; `add-recipient` was run for an environment with no `:recipients-file` |
;; | `:manifest-stale` | the ciphertext was replaced and the manifest was not; run `reencrypt` |
;; | `:private-file-remains` | a private temporary file could not be deleted; `:remaining-file` holds its path |

;; ## File conventions

;; | File | Committed | Contents |
;; |------|-----------|----------|
;; | `secrets.edn.age` | yes | the encrypted secrets |
;; | `secrets.edn.manifest` | by default | key paths, types, and keyed value hashes; updated by every write |
;; | `secrets.edn.example` | when used | optional template for `bb secrets new` |
;; | `recipients.txt` | yes | age public keys, one per line, team mode |
;; | a `:key-file`, if you set one | never | the private key, in plaintext; by default the key lives in the macOS Keychain or a password manager instead |
;; | `.<name>.<uuid>.tmp` | never | a staging file a killed command left behind; safe to delete |
