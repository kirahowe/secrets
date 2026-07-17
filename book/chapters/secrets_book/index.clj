;; # Preface {.unnumbered}

^{:kindly/hide-code true}
(ns secrets-book.index
  (:require [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.age :as age]
            [clojure.java.io :as io]))

;; This is the book for [com.kirahowe/secrets](https://github.com/kirahowe/secrets),
;; a small Clojure library that keeps application secrets in a single
;; version-controlled, age-encrypted EDN file instead of a pile of environment
;; variables. One private key decrypts the file. Everything else lives in git:
;; the ciphertext, the structure, and a committed manifest that makes changes
;; reviewable.

;; The library is deliberately small. It has no dependencies beyond Clojure
;; itself, it runs the same under JVM Clojure and [babashka](https://babashka.org),
;; and it wraps [age](https://age-encryption.org), a file encryption tool whose
;; whole specification fits in one readable page. If you run one app or a
;; handful, and your current secrets story is a dozen env vars in a deploy
;; platform's web UI, this library is for you. If you need dynamic secrets,
;; per-secret access control, or an audit trail, it is not, and the
;; [caveats chapter](secrets_book.caveats.html) says so plainly.

;; ## How this book works

;; Every chapter is a Clojure namespace, rendered with
;; [Clay](https://scicloj.github.io/clay/). The code blocks were evaluated
;; against the real library when the book was built, and the results shown
;; below each block are real output, not transcripts. When a chapter generates
;; a key or encrypts a file, that actually happened, in a throwaway temp
;; directory, with the actual `age` binary.

;; Here is the shape of the thing. Make a key:

(def dir (str (java.nio.file.Files/createTempDirectory
               "secrets-book-" (into-array java.nio.file.attribute.FileAttribute []))))

(age/keygen! (str dir "/key.txt"))

;; That return value is the public key. Encrypt a map to it:

(do (spit (str dir "/plain.edn")
          (pr-str {:database/url "jdbc:postgresql://localhost/app"
                   :auth/admins  #{"kira@example.com"}}))
    (age/encrypt-file! (str dir "/key.txt")
                       (str dir "/plain.edn")
                       (str dir "/secrets.edn.age")))

;; Load it back:

(secrets/load-secrets (str dir "/secrets.edn.age")
                      (str dir "/key.txt"))

;; That map is the whole idea. Your secrets are plain Clojure data: sets,
;; keywords, nested maps, numbers. They live encrypted in your repo, they
;; decrypt at startup with one key, and nothing about them is a string you
;; have to parse.

;; ## What the chapters cover

;; The [quick start](secrets_book.quick_start.html) goes from nothing to
;; working secrets in a few minutes. [Design](secrets_book.design.html)
;; explains why the library exists and what it borrows from Rails credentials,
;; SOPS, and git-crypt. [Runtime](secrets_book.runtime.html) covers loading
;; secrets in your app, [the CLI chapter](secrets_book.cli.html) covers
;; managing them from the terminal, [teams](secrets_book.teams.html) covers
;; multi-recipient encryption, and [the manifest](secrets_book.manifest.html)
;; covers the committed file that makes encrypted changes reviewable.
;; [Production](secrets_book.production.html) shows deployment and CI,
;; [caveats](secrets_book.caveats.html) lists the trade-offs without varnish,
;; and the [reference](secrets_book.reference.html) documents the full API.

;; ## Building this book

;; The book lives in the library repo under `book/chapters`. Three babashka
;; tasks drive it:

;; ```sh
;; bb book:build     # render everything into book/rendered
;; bb book:preview   # serve the rendered book locally
;; bb book:watch     # re-render chapters as you edit them
;; ```

;; Building needs a JDK, the `quarto` CLI, and the `age` binary, because the
;; chapters really do run their examples.

^{:kindly/hide-code true}
(doseq [f (reverse (file-seq (io/file dir)))]
  (.delete f))
