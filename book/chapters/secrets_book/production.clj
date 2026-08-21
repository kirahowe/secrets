;; # Production and CI

^{:kindly/hide-code true}
(ns secrets-book.production
  (:require [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.age :as age]
            [clojure.java.io :as io]))

;; A deployment of this library has two moving parts. The ciphertext travels
;; with your code, inside the image or the jar, like any other resource. The
;; key travels alone, as a single secret in whatever your platform provides.
;; Everything in this chapter is a variation on that sentence.

;; ## Injecting the key

;; Three environment variables provide the key, checked in this order:

;; | Variable | Contents | Use it when |
;; |----------|----------|-------------|
;; | `SECRETS_AGE_IDENTITY_FILE` | a path to the key file | the platform mounts secret files |
;; | `SECRETS_AGE_IDENTITY` | the raw key file contents | the platform stores secret strings |
;; | `SECRETS_AGE_IDENTITY_B64` | base64 of the contents | the platform mangles newlines |

;; `SECRETS_AGE_IDENTITY` is used verbatim, never decoded. `SECRETS_AGE_IDENTITY_B64` is
;; always decoded, and invalid base64 is an error rather than a silent
;; fallback. The split exists because guessing whether a value is encoded is
;; how keys get corrupted quietly; here nothing guesses. Key contents are
;; written to an owner-only temp file once per process, since the `age`
;; binary wants a file.

;; A variable that is **set but empty** throws, naming itself, rather than
;; being treated as unset. This is the CI case worth knowing about: the
;; workflow snippet later in this chapter maps a repository secret into
;; `SECRETS_AGE_IDENTITY`, and if that secret is missing or misnamed the
;; runner expands it to the empty string rather than leaving it unset. Falling
;; through to the next variable — and eventually to the local
;; `~/.config/<app>/key.txt` — would let a broken deployment succeed on a
;; developer machine using the wrong key. Unset the variable when you want the
;; fallback.

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
;; needs it on `PATH` — a container, a VM, a CI runner, your laptop. Some
;; platforms can't offer that at all: Cloudflare Workers, Deno Deploy, and
;; edge runtimes generally run your code somewhere that can't exec a
;; subprocess, `age` or otherwise.

;; That's not a gap in this library, it's a boundary of the design — it wraps
;; a CLI tool, so anywhere a CLI tool can't run, it can't run either. The
;; answer isn't to work around it; it's to use this library for what it's
;; good at (development and CI, where the ciphertext and the manifest still
;; do their job) and let the edge platform hold the one secret value itself
;; in production.

;; | Where | How the identity gets there |
;; |-------|------------------------------|
;; | Laptop | `~/.config/<app>/key.txt` |
;; | GitHub Actions | `SECRETS_AGE_IDENTITY` repository secret |
;; | Container / VM | env var, `age` installed in the image |
;; | Edge runtime (Workers, Deno Deploy) | **it doesn't** — use the platform's own secret store; this library covers dev and CI |

;; ## Loading from inside a jar, demonstrated

;; This is the part that must not break on a Friday deploy, so the book
;; proves it rather than promising it. Build an actual jar containing an
;; encrypted secrets entry, then load through a `jar:` URL, which is exactly
;; what `io/resource` returns inside an uberjar:

(def dir (str (java.nio.file.Files/createTempDirectory
               "secrets-prod-" (into-array java.nio.file.attribute.FileAttribute []))))

^{:kindly/hide-code true}
(def key-file (str dir "/key.txt"))

^{:kindly/hide-code true}
(age/keygen! key-file)

(let [plain (str dir "/p.edn")
      enc   (str dir "/secrets.edn.age")
      jar   (str dir "/app.jar")]
  (spit plain (pr-str {:from :inside-the-jar}))
  (age/encrypt-file! key-file plain enc)
  (with-open [zos (java.util.zip.ZipOutputStream. (io/output-stream jar))]
    (.putNextEntry zos (java.util.zip.ZipEntry. "secrets.edn.age"))
    (io/copy (io/file enc) zos)
    (.closeEntry zos))
  (secrets/load-secrets (java.net.URL. (str "jar:file:" jar "!/secrets.edn.age"))
                        key-file))

;; The library detects that the source is not a plain file, streams it out to
;; an owner-only temp copy, hands that to `age`, and deletes the copy.

;; ## Startup wiring

;; Application code passes `{:app "myapp"}` and lets the environment
;; variables win when they are present:

;; ```clojure
;; (defmethod ig/init-key ::secrets [_ {:keys [resource]}]
;;   (secrets/load-secrets (io/resource resource) {:app "myapp"}))
;; ```

;; On a laptop, that resolves to `~/.config/myapp/key.txt`. In the container,
;; `SECRETS_AGE_IDENTITY` overrides it. Same code, no branches.

;; Secrets decrypt once, at startup. Changing a secret means a commit and a
;; deploy, and a restart picks it up. There is no hot reload, and the
;; [caveats chapter](secrets_book.caveats.html) discusses what that means
;; for emergency rotation.

;; ## CI: gate the manifest

;; Two useful jobs, in increasing order of trust required.

;; The keyless job checks that nobody committed a ciphertext without its
;; manifest. It holds no secrets at all, and does not even need `age`:

;; ```yaml
;; verify-secrets-freshness:
;;   runs-on: ubuntu-latest
;;   steps:
;;     - uses: actions/checkout@v4
;;     - uses: turtlequeue/setup-babashka@v1
;;       with: {babashka-version: 1.12.208}
;;     - run: bb secrets verify
;; ```

;; With no identity available, `verify` compares the manifest's recorded
;; `:ciphertext-sha` against the file and exits 0, 1, or 2. Exit 1 means
;; drift and should fail the build. Exit 2 means an artifact is missing,
;; which on a fresh repo usually means someone forgot to commit the manifest.

;; The full job decrypts and checks values too. Give the runner the deploy
;; key (as a CI secret, not a person's key) and install `age`:

;; ```yaml
;; verify-secrets:
;;   runs-on: ubuntu-latest
;;   env:
;;     SECRETS_AGE_IDENTITY: ${{ secrets.SECRETS_AGE_IDENTITY }}
;;   steps:
;;     - uses: actions/checkout@v4
;;     - run: sudo apt-get install -y age
;;     - uses: turtlequeue/setup-babashka@v1
;;       with: {babashka-version: 1.12.208}
;;     - run: bb secrets verify
;; ```

;; Whether to run the full job is a judgment call: it makes CI a holder of
;; your production key. The keyless job catches the common failure for free,
;; so start there and add the keyed job only if you need value-level checks
;; on every merge.

;; ## A job that reads secrets

;; The two jobs above only ever check freshness or shape — neither one
;; decrypts a value into something that runs. A job that actually needs the
;; secrets, an eval run hitting a real API, say, needs `age` installed and the
;; identity in its environment, the same as the container does:

;; ```yaml
;; evals:
;;   runs-on: ubuntu-latest
;;   steps:
;;     - uses: actions/checkout@v4
;;     - name: Install age
;;       run: sudo apt-get update && sudo apt-get install -y age
;;     - name: Run the thing
;;       run: bb evals
;;       env:
;;         SECRETS_AGE_IDENTITY: ${{ secrets.SECRETS_AGE_IDENTITY }}
;; ```

;; The repository secret's value is the *contents* of `~/.config/<app>/key.txt`,
;; not a path — and the ciphertext it decrypts is the one already committed to
;; the repo. That's the whole point of the design: the secret Actions holds is
;; small and rotatable, and the thing it unlocks travels with the code. It
;; still feels backwards the first time, though — you are not sending secrets
;; to GitHub, you are giving GitHub the one key that reads the secrets already
;; sitting in the checkout. Set it with:

;; ```sh
;; gh secret set SECRETS_AGE_IDENTITY < ~/.config/myapp/key.txt
;; ```

;; ## Back up the key like you mean it

;; The key is two lines of text, it is not in git, and it does not regenerate.
;; Losing every copy means re-creating every secret value from the upstream
;; services. Put it in the team password manager the day you generate it, and
;; treat "where is the key backed up?" as a deploy checklist item, not an
;; afterthought.

^{:kindly/hide-code true}
(doseq [f (reverse (file-seq (io/file dir)))]
  (.delete f))
