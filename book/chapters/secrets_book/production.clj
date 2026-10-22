;; # Production and CI

^:kindly/hide-code
(ns secrets-book.production
  (:require [clojure.java.io :as io]
            [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.age :as age]))

;; A deployment needs both the ciphertext and a matching identity. The
;; ciphertext can ship with the code in an image or jar, while the identity
;; comes from the deployment platform's secret mechanism.

;; ## Injecting the key

;; When no explicit identity path is supplied, you can provide the key through
;; one of three environment variables. They are checked in this order:

;; | Variable | Contents | Use it when |
;; |----------|----------|-------------|
;; | `SECRETS_AGE_IDENTITY_FILE` | a path to the key file | the platform mounts secret files |
;; | `SECRETS_AGE_IDENTITY` | the raw key file contents | the platform stores secret strings |
;; | `SECRETS_AGE_IDENTITY_B64` | base64 of the contents | the platform mangles newlines |

;; `SECRETS_AGE_IDENTITY` is used verbatim and is never decoded.
;; `SECRETS_AGE_IDENTITY_B64` is always decoded, and invalid base64 is an
;; error. Spaces, tabs, and line breaks inside the base64 are allowed, so a
;; wrapped value works. Using separate variables means the library doesn't
;; have to guess whether a value is encoded.

;; The two variables that carry contents keep the key in memory. The library
;; hands it to `age` on standard input (`age -i -`), so the key is never
;; written to a file, not even a temporary one.

;; `SECRETS_AGE_IDENTITY_FILE` has to name a file that exists. A path to a
;; missing file is an error that names the variable and the path. The library
;; does not fall back to another key, and it does not treat the store as
;; having no key. A leading `~` in the path is expanded.

;; If one of these variables is **set but empty**, the library throws an error
;; that names it instead of treating it as unset. This matters in CI. The
;; workflow later in this chapter maps a repository secret to
;; `SECRETS_AGE_IDENTITY`; if that secret is missing or misspelled, the runner
;; expands it to an empty string rather than leaving it unset. Falling through
;; to the next variable, and eventually to the app's own key in the macOS
;; Keychain, could make a broken deployment appear to work on a developer's
;; machine with the wrong key. If you want fallback behaviour, leave the
;; variable unset.

;; With the key in the macOS Keychain, it can go from there to the platform
;; without passing through a file. On Fly, for example, that is one command:

;; ```sh
;; flyctl secrets set SECRETS_AGE_IDENTITY="$(security find-generic-password -s com.kirahowe.secrets -a myapp -w)"
;; ```

;; If the store mangles newlines, use the base64 variable instead:

;; ```sh
;; some-platform set SECRETS_AGE_IDENTITY_B64="$(security find-generic-password -s com.kirahowe.secrets -a myapp -w | base64)"
;; ```

;; With the key in a password manager, use its read command in place of
;; `security`, the same command an environment's `:key-command` runs.

;; ## The image

;; The container needs the `age` binary, because decryption shells out to it:

;; ```dockerfile
;; RUN apt-get update && apt-get install -y age && rm -rf /var/lib/apt/lists/*
;; ```

;; The encrypted file itself needs no special handling. If
;; `env/prod/resources` is on the classpath, `secrets.edn.age` will be included
;; in the uberjar with everything else.

;; ## Runtimes without `age`

;; Decryption shells out to the `age` binary, so every runtime that decrypts
;; needs it on `PATH`: a container, a VM, a CI runner, or a laptop. Some
;; serverless and edge runtimes do not allow application code to start
;; subprocesses.

;; Because this library wraps a CLI tool, it can't decrypt in those runtimes.
;; You can still use it in development and CI, then provide the required values
;; through the runtime's own secret store in production.

;; | Where | How the identity gets there |
;; |-------|------------------------------|
;; | Laptop | the macOS Keychain, or a password manager through `:key-command` |
;; | GitHub Actions | `SECRETS_AGE_IDENTITY` repository secret |
;; | Container / VM | env var, `age` installed in the image |
;; | Runtime without subprocess support | platform secret store; use this library in dev and CI |

;; ## Loading from inside a jar, demonstrated

;; The following example builds a jar containing an encrypted resource, then
;; loads it through the `jar:` URL form returned by `io/resource` inside a jar:

(def dir
  (str (java.nio.file.Files/createTempDirectory
        "secrets-prod-"
        (into-array java.nio.file.attribute.FileAttribute []))))

^:kindly/hide-code
(def key-file (str dir "/key.txt"))

^:kindly/hide-code
(age/keygen! key-file)

(let [plain (str dir "/p.edn")
      enc (str dir "/secrets.edn.age")
      jar (str dir "/app.jar")]
  (spit plain (pr-str {:from :inside-the-jar}))
  (age/encrypt-file! {:identity-file key-file} plain enc)
  (with-open [zos (java.util.zip.ZipOutputStream. (io/output-stream jar))]
    (.putNextEntry zos (java.util.zip.ZipEntry. "secrets.edn.age"))
    (io/copy (io/file enc) zos)
    (.closeEntry zos))
  (secrets/load-secrets
   (java.net.URL. (str "jar:file:" jar "!/secrets.edn.age"))
   key-file))

;; The library recognizes a resource inside a local jar, streams it to an
;; owner-only temporary copy, passes that file to `age`, and then deletes it.
;; The copy stops at the fixed 16 MiB bound on ciphertext. A remote URL is
;; refused, and a nested jar URL is not found (`:no-file`), so loading secrets
;; at runtime never makes a network request.

;; ## Startup wiring

;; Application code can pass `{:app "myapp"}`, as the
;; [runtime chapter](secrets_book.runtime.html#reading-values) shows for an
;; Integrant component. An explicit identity path wins, followed by the
;; environment variables, then the project's own key: a `:key-command`, a
;; `:key-file`, or on macOS the Keychain item for `myapp`. The application
;; code can stay the same in a laptop and a container while the deployment
;; supplies an injected identity.

;; The component decrypts the secrets during startup. `load-secrets` has no
;; cache and nothing reloads the store, so changing a secret normally requires
;; a commit, deploy, and restart. The
;; [caveats chapter](secrets_book.caveats.html#rotation-goes-through-a-deploy)
;; discusses what that means for emergency rotation.

;; ## CI: gate the manifest

;; CI can run a keyless freshness check or a full check with an identity.

;; The keyless job checks that each enabled manifest matches its ciphertext.
;; It needs neither an identity nor `age`, because it doesn't decrypt anything:

;; ```yaml
;; verify-secrets-freshness:
;;   runs-on: ubuntu-latest
;;   permissions:
;;     contents: read
;;   steps:
;;     - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6.1.0
;;     - uses: actions/setup-java@b6effb05e454b25005698d916606bdc6ffcbf961 # v5.7.0
;;       with: {distribution: temurin, java-version: '21'}
;;     - uses: DeLaGuardo/setup-clojure@4c7a6f613e5089821bb3bb2a33a3ee115578580d # v13.6.1
;;       with: {bb: 1.13.219}
;;     - run: bb secrets verify
;; ```

;; When no identity is available, `verify` checks that each manifest is
;; complete and that its recorded `:ciphertext-sha` is the digest of the file.
;; It exits with 0, 1, or 2. Exit 1 means the only problem is drift, and
;; should fail the build. Exit 2 means something else stopped the check: a
;; missing ciphertext or manifest, an identity or decryption failure, an
;; unknown environment, or an invalid configuration. In a new repository, a 2
;; usually means someone forgot to commit the manifest. The
;; [team-ci example](https://github.com/kirahowe/secrets/tree/main/examples/team-ci)
;; commits such a fixture and uses it as a gate.

;; The keyless check runs when no identity was named and the project's own key
;; is not there, which is the normal state of a CI runner. A configured
;; `:key-file`, like the Keychain item, only says where the key normally lives,
;; so an environment can set one and still be checked keyless on a machine
;; that doesn't have the file. An
;; identity you name has to exist: a job that sets `SECRETS_AGE_IDENTITY_FILE`
;; to a path that isn't there, or sets an identity variable to an empty
;; string, exits 2 instead of passing keyless.
;;
;; With no environment argument, `verify` checks every environment and keeps
;; going past one it can't check, so one misconfigured environment doesn't
;; hide the state of the others.

;; Since this job holds no secret, it doesn't need a gate based on the event
;; that triggered it: an untrusted pull request has no secret to take. It still
;; pins each action to a commit and requests only enough permission to check out
;; the repository. Even without a secret, the job runs third-party code with a
;; token.

;; The full job also decrypts the store and compares every key path, type, and
;; value hash with the manifest, for solo and team stores alike. In a team
;; store it reports a recipients file that changed without a `reencrypt` as
;; drift too. Give the runner a dedicated deploy identity and install `age`:

;; ```yaml
;; verify-secrets:
;;   runs-on: ubuntu-latest
;;   if: >-
;;     github.event_name != 'pull_request' ||
;;     github.event.pull_request.head.repo.full_name == github.repository
;;   permissions:
;;     contents: read
;;   steps:
;;     - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6.1.0
;;     - uses: actions/setup-java@b6effb05e454b25005698d916606bdc6ffcbf961 # v5.7.0
;;       with: {distribution: temurin, java-version: '21'}
;;     - uses: DeLaGuardo/setup-clojure@4c7a6f613e5089821bb3bb2a33a3ee115578580d # v13.6.1
;;       with: {bb: 1.13.219}
;;     - run: sudo apt-get update && sudo apt-get install -y age
;;     - run: bb secrets verify
;;       env:
;;         SECRETS_AGE_IDENTITY: ${{ secrets.SECRETS_AGE_IDENTITY }}
;; ```

;; This full check gives CI an identity that can decrypt the file, so only use
;; it when that access is appropriate. The keyless job can still detect a
;; ciphertext that no longer matches its committed manifest.

;; The example declares the identity on the verify step rather than on the
;; whole job. Checkout, the `apt-get` install, and the Babashka setup action all
;; run in this job, but none of them needs the key. A job-level `env:` would
;; give the identity to every step, which means a change in any one of them
;; would change the code that runs with the private key available. For the same
;; reason, every `uses:` points to a full commit SHA, with the version noted
;; beside it. An upstream project can move a tag, allowing the action's code to
;; change without producing a diff in this repository, while that code still
;; runs beside the credential.

;; The `if:` keeps untrusted code out of the job that has the key. GitHub does
;; not provide repository secrets to a `pull_request` from a fork, so today the
;; job could not leak the identity to one anyway. The condition makes that
;; restriction explicit. Otherwise, someone trying to fix an empty variable
;; later might switch the job to `pull_request_target`, which provides secrets
;; while a contributor's unreviewed code is checked out. The `permissions:`
;; block applies the same care to the job's token. Without it, the job inherits
;; the repository or organization default, while verification only needs
;; `contents: read`.

;; ## A job that reads secrets

;; Verification does not pass secret values to application code. A job that
;; does need them, such as an evaluation that calls an external API, needs
;; `age` and the identity in its environment. Put the identity on the step that
;; runs the evaluation and use the same gate and permissions, since this job
;; holds the same key:

;; ```yaml
;; evals:
;;   runs-on: ubuntu-latest
;;   if: >-
;;     github.event_name != 'pull_request' ||
;;     github.event.pull_request.head.repo.full_name == github.repository
;;   permissions:
;;     contents: read
;;   steps:
;;     - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6.1.0
;;     - uses: actions/setup-java@b6effb05e454b25005698d916606bdc6ffcbf961 # v5.7.0
;;       with: {distribution: temurin, java-version: '21'}
;;     - uses: DeLaGuardo/setup-clojure@4c7a6f613e5089821bb3bb2a33a3ee115578580d # v13.6.1
;;       with: {bb: 1.13.219}
;;     - name: Install age
;;       run: sudo apt-get update && sudo apt-get install -y age
;;     - name: Run evaluations
;;       run: bb evals
;;       env:
;;         SECRETS_AGE_IDENTITY: ${{ secrets.SECRETS_AGE_IDENTITY }}
;; ```

;; The repository secret's value is the key itself, the `AGE-SECRET-KEY-1…`
;; line, rather than a path. It decrypts the ciphertext already committed to
;; the repository. GitHub therefore receives an identity that can decrypt the
;; ciphertext in the checkout, so protect the repository secret accordingly.
;; With the key in the macOS Keychain, set it with:

;; ```sh
;; security find-generic-password -s com.kirahowe.secrets -a myapp -w | \
;;   gh secret set SECRETS_AGE_IDENTITY
;; ```

;; These precautions apply to the private identity. The lines in
;; `recipients.txt` are age *public* keys: encryption needs them, decryption
;; does not, and they are meant to be committed and read. A pull request from a
;; fork learns nothing from having one. Keep the private identity limited to
;; the steps that need it, keep untrusted code out, and pin third-party actions.
;; A public recipient is ordinary repository content.

;; ## Back up the identity

;; The identity is one short line of text that is not stored in git. If every
;; copy is lost, you will have to recover or replace each secret value at its source.
;; Back it up in the team's approved secret storage when you create it.

^:kindly/hide-code
(doseq [f (reverse (file-seq (io/file dir)))]
  (.delete f))
