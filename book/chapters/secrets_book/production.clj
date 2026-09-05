;; # Production and CI

^:kindly/hide-code
(ns secrets-book.production
  (:require [clojure.java.io :as io]
            [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.age :as age]))

;; A deployment needs the ciphertext and a matching identity. The ciphertext
;; can ship with the code in an image or jar. Supply the identity through the
;; deployment platform's secret mechanism.

;; ## Injecting the key

;; Three environment variables provide the key, checked in this order:

;; | Variable | Contents | Use it when |
;; |----------|----------|-------------|
;; | `SECRETS_AGE_IDENTITY_FILE` | a path to the key file | the platform mounts secret files |
;; | `SECRETS_AGE_IDENTITY` | the raw key file contents | the platform stores secret strings |
;; | `SECRETS_AGE_IDENTITY_B64` | base64 of the contents | the platform mangles newlines |

;; `SECRETS_AGE_IDENTITY` is used verbatim, never decoded.
;; `SECRETS_AGE_IDENTITY_B64` is always decoded, and invalid base64 is an error
;; rather than a silent fallback. Separate variables avoid guessing whether a
;; value is encoded. Key contents are written to an owner-only temp file once
;; per distinct value because this wrapper passes the identity to `age` as a
;; file path.

;; A long-running process can call `secrets/reset-identity-cache!` once its
;; configuration has loaded, so that materialized copy does not stay on disk.
;; The [runtime chapter](secrets_book.runtime.html#retiring-injected-identities)
;; describes what it deletes and what it leaves alone.

;; A variable that is **set but empty** throws, naming itself, rather than
;; being treated as unset. This matters in CI: the workflow snippet later in
;; this chapter maps a repository secret into
;; `SECRETS_AGE_IDENTITY`, and if that secret is missing or misnamed the
;; runner expands it to the empty string rather than leaving it unset. Falling
;; through to the next variable — and eventually to the local
;; `~/.config/<app>/key.txt` — would let a broken deployment succeed on a
;; developer machine using the wrong key. Unset the variable to allow fallback.

;; On Fly, that means one command:

;; ```sh
;; flyctl secrets set SECRETS_AGE_IDENTITY="$(cat ~/.config/myapp/key.txt)"
;; ```

;; and for a store that eats newlines:

;; ```sh
;; some-platform set SECRETS_AGE_IDENTITY_B64="$(base64 < ~/.config/myapp/key.txt)"
;; ```

;; ## The image

;; The container needs the `age` binary, because decryption shells out to it:

;; ```dockerfile
;; RUN apt-get update && apt-get install -y age && rm -rf /var/lib/apt/lists/*
;; ```

;; The encrypted file itself needs no special handling. If
;; `env/prod/resources` is on the classpath, `secrets.edn.age` rides along
;; into the uberjar with everything else.

;; ## Runtimes without `age`

;; Decryption shells out to the `age` binary, so every runtime that decrypts
;; needs it on `PATH` — a container, a VM, a CI runner, or a laptop. Some
;; serverless and edge runtimes do not allow application code to start
;; subprocesses.

;; This library cannot decrypt in those runtimes because it wraps a CLI tool.
;; You can still use it in development and CI, then supply the required values
;; through the runtime's own secret store in production.

;; | Where | How the identity gets there |
;; |-------|------------------------------|
;; | Laptop | `~/.config/<app>/key.txt` |
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
  (age/encrypt-file! key-file plain enc)
  (with-open [zos (java.util.zip.ZipOutputStream. (io/output-stream jar))]
    (.putNextEntry zos (java.util.zip.ZipEntry. "secrets.edn.age"))
    (io/copy (io/file enc) zos)
    (.closeEntry zos))
  (secrets/load-secrets
   (java.net.URL. (str "jar:file:" jar "!/secrets.edn.age"))
   key-file))

;; The library recognizes the local `jar:file:` source, streams it out to an
;; owner-only temp copy under the configured 16 MiB source limit, hands that to
;; `age`, and deletes the copy. Remote and nested jar URLs are refused; runtime
;; secret loading never performs a network request.

;; ## Startup wiring

;; Application code passes `{:app "myapp"}`, as the
;; [runtime chapter](secrets_book.runtime.html#reading-values) shows for an
;; Integrant component, and lets the environment variables win when they are
;; present. On a laptop that resolves to `~/.config/myapp/key.txt`; in the
;; container, `SECRETS_AGE_IDENTITY` overrides it. Same code, no branches.

;; The component decrypts during startup. `load-secrets` has no global cache
;; or hot reload, so changing a secret normally means a commit, deploy, and
;; restart. The
;; [caveats chapter](secrets_book.caveats.html#rotation-goes-through-a-deploy)
;; discusses what that means for emergency rotation.

;; ## CI: gate the manifest

;; CI can run a keyless freshness check or a full check with an identity.

;; The keyless job checks that each enabled manifest matches its ciphertext.
;; It holds no secret material and does not need `age`:

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

;; With no identity available, `verify` compares the manifest's recorded
;; `:ciphertext-sha` against the file and exits 0, 1, or 2. Exit 1 means
;; drift and should fail the build. Exit 2 means an artifact is missing or an
;; older manifest has no ciphertext hash for a keyless check. On a fresh repo,
;; this usually means someone forgot to commit the manifest.

;; This job holds no secret, so it needs no gate on which event triggered it —
;; there is nothing here for an untrusted pull request to take. It still pins
;; each action to a commit and asks for the least permission that can check a
;; repository out, because a job with no secret is still a job running
;; third-party code with a token.

;; The full job decrypts and regenerates the manifest entries. In single-key
;; mode this includes the keyed value hashes; in team mode it checks structure.
;; Give the runner a dedicated deploy identity and install `age`:

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

;; The full job makes CI a holder of an identity that can decrypt the file.
;; Use it only when that access is appropriate. The keyless job still detects
;; a ciphertext that no longer matches its committed manifest.

;; The identity is declared on the verify step rather than on the job. Checkout,
;; the `apt-get` install, and the Babashka setup action all run in this job and
;; none of them needs a key; a job-level `env:` would hand the identity to every
;; one of them, so a change in any of them would be a change in code holding a
;; private key. Every `uses:` is a full commit SHA with the version that commit
;; is beside it, for the same reason: a tag is a name upstream can move, so a
;; tagged action can become different code with no diff here — and that code
;; would be the code running beside the credential.

;; The `if:` keeps untrusted code out of the keyed path. A `pull_request` from a
;; fork receives no repository secrets, so this job cannot leak the identity to
;; one today; the condition says so explicitly anyway, because a job that looks
;; like it grants a key to a pull request invites the next person to "fix" the
;; empty variable by moving to `pull_request_target`, which runs with the
;; secrets available and a contributor's unreviewed code checked out. The
;; `permissions:` block is the other half of the same argument: without one the
;; job inherits the repository or organization default, and `contents: read` is
;; all a verification job needs.

;; ## A job that reads secrets

;; Verification does not pass secret values to application code. A job that
;; needs them, such as an evaluation that calls an external API, also needs
;; `age` and the identity in its environment — on the step that runs the
;; evaluation, under the same gate and permissions, because this job holds the
;; same key:

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

;; The repository secret's value is the *contents* of `~/.config/<app>/key.txt`,
;; not a path — and the ciphertext it decrypts is the one already committed to
;; the repo. GitHub receives an identity that can decrypt the ciphertext in the
;; checkout, so protect that repository secret accordingly. Set it with:

;; ```sh
;; gh secret set SECRETS_AGE_IDENTITY < ~/.config/myapp/key.txt
;; ```

;; None of this applies to a recipients file. The lines in `recipients.txt` are
;; age *public* keys: they are what encryption needs rather than what decryption
;; needs, they are meant to be committed and read, and a fork's pull request
;; learns nothing from holding one. Scope, gate, and pin around the private
;; identity — a public recipient is ordinary repository content.

;; ## Back up the identity

;; The identity is a small text file that is not stored in git. Losing every
;; copy means recovering or replacing each secret value at its source. Back it
;; up in the team's approved secret storage when it is created.

^:kindly/hide-code
(doseq [f (reverse (file-seq (io/file dir)))]
  (.delete f))
