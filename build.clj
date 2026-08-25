(ns build
  "Build and install the library, and cut the artifact a release publishes.

    clojure -T:build jar       ; development build of target/secrets-<version>.jar
    clojure -T:build install   ; jar + install to ~/.m2 (resolves :mvn/version locally)
    clojure -T:build release   ; guarded build from the release tag + a receipt

  `jar` builds from the live working tree and is a development artifact only.
  Publishing goes through `release`, which builds from a snapshot of the release
  tag and records the resulting bytes, and then `clojure -M:deploy`, which
  uploads exactly those bytes. The upload is deliberately not a task here: it is
  the only step holding a credential, so it runs from `:deploy`'s own replaced
  classpath — this namespace, and tools.build with it, is not on it. The guards
  live in `com.kirahowe.secrets.release`, under `build/`, where they are tested.

  Consumers depend on the published coordinate:  com.kirahowe/secrets {:mvn/version \"…\"}."
  (:require [clojure.java.io :as io]
            [clojure.tools.build.api :as b]
            [com.kirahowe.secrets.release :as release]))

(def class-dir "target/classes")
(def basis (delay (b/create-basis {:project "deps.edn"})))
(def jar-file (format "target/%s-%s.jar" (name release/lib) release/version))
(def pom-file (b/pom-path {:lib release/lib :class-dir class-dir}))
(def scm-url "https://github.com/kirahowe/secrets")

(def pom-data
  [[:description
    (str "Manage application secrets as a version-controlled, "
         "age-encrypted EDN file.")]
   [:licenses
    [:license
     [:name "MIT"]
     [:url "https://opensource.org/license/mit"]]]])

(defn clean [_]
  (b/delete {:path "target"}))

(defn jar
  "Builds a development jar from the live working tree.

  This is not publishable and makes no provenance claim: CI runs it on every
  push, including dirty trees and refs that are not release tags, so the pom
  records the repository URL without an `:scm` `:tag`. Use `release` to build
  something that can be uploaded."
  [_]
  (clean nil)
  (b/write-pom {:class-dir class-dir
                :lib release/lib
                :version release/version
                :basis @basis
                :src-dirs ["src"]
                :scm {:url scm-url}
                :pom-data pom-data})
  (b/copy-dir {:src-dirs ["src"]
               :target-dir class-dir})
  (b/jar {:class-dir class-dir
          :jar-file jar-file})
  (println "Wrote" jar-file))

(defn install
  "Builds the development `jar` and installs it to `~/.m2`.

  A local convenience so a sibling project can resolve `:mvn/version` without a
  published artifact. It installs the unguarded development build, so it is not
  a release."
  [_]
  (jar nil)
  (b/install {:basis @basis
              :lib release/lib
              :version release/version
              :jar-file jar-file
              :class-dir class-dir})
  (println "Installed" release/lib release/version "to ~/.m2"))

(defn- release-jar!
  "Builds the pom and jar from the verified export at `source-dir`.

  The basis and the copied sources come from the export, so the artifact holds
  the tag's bytes rather than whatever the working tree says now. The pom's
  `:src-dirs` stays the in-project `\"src\"`, because tools.build writes it
  verbatim as `<sourceDirectory>` and the export path is a build-time detail."
  [source-dir tag]
  (b/write-pom {:class-dir class-dir
                :lib release/lib
                :version release/version
                :basis (b/create-basis {:project (str (io/file source-dir "deps.edn"))})
                :src-dirs ["src"]
                ;; :tag lets cljdoc (and anyone reading the pom) find the exact
                ;; revision the artifact was built from.
                :scm {:url scm-url :tag tag}
                :pom-data pom-data})
  (b/copy-dir {:src-dirs [(str (io/file source-dir "src"))]
               :target-dir class-dir})
  (b/jar {:class-dir class-dir
          :jar-file jar-file}))

(defn release
  "Builds the release artifact once, from the verified release tag, with a receipt.

  Refuses a dirty or untracked working tree, a `HEAD` that is not exactly the tag
  naming the authoritative version, and a version the CHANGELOG does not
  document. The jar is then built from a `git worktree` export of that tag — not
  from live files, which can change after the guards pass — its embedded metadata
  and tag are checked against the version, and the jar, the pom that ships beside
  it, the commit, and the jar's SHA-256 are recorded in `target/release.edn` for
  `clojure -M:deploy` to re-verify. Inspect the printed digest before uploading."
  [_]
  (release/clean-tree!)
  (let [{:keys [tag commit]} (release/exact-tag!)]
    (release/changelog-entry!)
    (clean nil)
    (try
      (release-jar! (release/verified-source!) tag)
      (release/verify-artifact-metadata! jar-file)
      (let [receipt (release/receipt {:tag tag :commit commit :jar jar-file :pom pom-file})]
        (release/verify-pom! receipt)
        (release/write-receipt! receipt)
        (println "Wrote" jar-file "from" tag "at" commit)
        (println "SHA-256" (:sha256 receipt))
        (println "Pom" pom-file)
        (println "Receipt" (str (release/receipt-path)))
        receipt)
      (finally
        (release/release-source-cleanup!)))))
