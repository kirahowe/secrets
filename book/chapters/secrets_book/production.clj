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
;; | `AGE_IDENTITY_FILE` | a path to the key file | the platform mounts secret files |
;; | `AGE_IDENTITY` | the raw key file contents | the platform stores secret strings |
;; | `AGE_IDENTITY_B64` | base64 of the contents | the platform mangles newlines |

;; `AGE_IDENTITY` is used verbatim, never decoded. `AGE_IDENTITY_B64` is
;; always decoded, and invalid base64 is an error rather than a silent
;; fallback. The split exists because guessing whether a value is encoded is
;; how keys get corrupted quietly; here nothing guesses. Key contents are
;; written to an owner-only temp file once per process, since the `age`
;; binary wants a file.

;; On Fly, that means one command:

;; ```sh
;; flyctl secrets set AGE_IDENTITY="$(cat ~/.config/myapp/key.txt)"
;; ```

;; and for a store that eats newlines:

;; ```sh
;; some-platform set AGE_IDENTITY_B64="$(base64 < ~/.config/myapp/key.txt)"
;; ```

;; ## The image

;; The container needs the `age` binary, because decryption shells out to it:

;; ```dockerfile
;; RUN apt-get update && apt-get install -y age && rm -rf /var/lib/apt/lists/*
;; ```

;; The encrypted file itself needs no special handling. If
;; `env/prod/resources` is on the classpath, `secrets.edn.age` rides along
;; into the uberjar with everything else.

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
;; `AGE_IDENTITY` overrides it. Same code, no branches.

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
;;     AGE_IDENTITY: ${{ secrets.AGE_IDENTITY }}
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

;; ## Back up the key like you mean it

;; The key is two lines of text, it is not in git, and it does not regenerate.
;; Losing every copy means re-creating every secret value from the upstream
;; services. Put it in the team password manager the day you generate it, and
;; treat "where is the key backed up?" as a deploy checklist item, not an
;; afterthought.

^{:kindly/hide-code true}
(doseq [f (reverse (file-seq (io/file dir)))]
  (.delete f))
