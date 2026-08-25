(ns com.kirahowe.secrets.release-test
  "Focused checks on the release guards, against disposable repositories.

  Every repository here is created under a temp directory and thrown away; none
  of these tests reads or writes the state of the repository they run in."
  (:require [clojure.java.io :as io]
            [clojure.java.shell :as sh]
            [clojure.string :as str]
            [clojure.test :refer [are deftest is testing use-fixtures]]
            [com.kirahowe.secrets.release :as release])
  (:import [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]
           [java.util.zip ZipEntry ZipOutputStream]))

;;;; Fixtures

(def ^:dynamic ^:private *dir* nil)

(def ^:private tracked-file "src/com/kirahowe/secrets/thing.clj")

(def ^:private tagged-contents "(ns com.kirahowe.secrets.thing) ;; as tagged\n")

(defn- delete-tree! [file]
  (doseq [child (reverse (file-seq (io/file (str file))))]
    (.delete child)))

(defn- with-temp-dir [test-fn]
  (let [dir (str (Files/createTempDirectory
                  "secrets-release-test"
                  (make-array FileAttribute 0)))]
    (binding [*dir* dir]
      (try
        (test-fn)
        (finally
          (delete-tree! dir))))))

(use-fixtures :each with-temp-dir)

(defn- git!
  "Runs `git` in `dir`, returning trimmed stdout and throwing on failure."
  [dir & args]
  (let [{:keys [exit out err]} (apply sh/sh "git" (concat args [:dir (io/file dir)]))]
    (when-not (zero? exit)
      (throw (ex-info (str "git " (str/join " " args) " failed: " err) {:args (vec args)})))
    (str/trim out)))

(defn- repo!
  "A disposable repository holding one commit tagged `v<version>`.

  The commit carries a `src` tree, a `deps.edn`, and a CHANGELOG documenting
  `version`, so every guard has something real to inspect. Signing is disabled
  locally so the fixture does not depend on the developer's git configuration."
  ([] (repo! "0.1.0"))
  ([version]
   (let [dir (io/file *dir* (str (gensym "repo")))]
     (.mkdirs (io/file dir "src/com/kirahowe/secrets"))
     (git! dir "init" "-q" "-b" "main")
     (doseq [[k v] {"user.email" "release-test@example.invalid"
                    "user.name" "Release Test"
                    "commit.gpgsign" "false"
                    "tag.gpgsign" "false"}]
       (git! dir "config" k v))
     (spit (io/file dir tracked-file) tagged-contents)
     (spit (io/file dir "deps.edn") "{:paths [\"src\"]}\n")
     (spit (io/file dir "CHANGELOG.md")
           (str "# Changelog\n\n## [" version "] - 2026-08-25\n"))
     (git! dir "add" "-A")
     (git! dir "commit" "-qm" "Release commit")
     (git! dir "tag" (str "v" version))
     dir)))

(defn- refusal
  "The `ex-data` of the failure `f` throws, with its message under `:message`.

  Returns nil when `f` returns normally, so a table can spell an accepted case
  as an expected reason of nil."
  [f]
  (try
    (f)
    nil
    (catch Exception e
      (assoc (ex-data e) :message (ex-message e)))))

(defn- jar!
  "Writes a jar named `jar-name` under `dir` containing `entries`.

  Constructed rather than built: these tests are about what the guards read out
  of an artifact, not about tools.build."
  [dir jar-name entries]
  (let [file (io/file dir "target" jar-name)]
    (io/make-parents file)
    (with-open [out (ZipOutputStream. (io/output-stream file))]
      (doseq [[entry text] entries]
        (.putNextEntry out (ZipEntry. entry))
        (.write out (.getBytes ^String text "UTF-8"))
        (.closeEntry out)))
    file))

(def ^:private pom-entry "META-INF/maven/com.kirahowe/secrets/pom.xml")

(defn- maven-entries
  "The embedded Maven descriptors a jar declaring `version` would carry.

  `tag` is the `<scm><tag>` the pom claims it was built from, defaulting to the
  tag for `version`; nil leaves the `<scm>` block out entirely."
  ([version] (maven-entries version (str "v" version)))
  ([version tag]
   {pom-entry
    (str "<project><groupId>com.kirahowe</groupId><artifactId>secrets</artifactId>\n  "
         "<version>" version "</version>\n  "
         (when tag (str "<scm><tag>" tag "</tag>"
                        "<url>https://github.com/kirahowe/secrets</url></scm>\n  "))
         "</project>\n")
    "META-INF/maven/com.kirahowe/secrets/pom.properties"
    (str "version=" version "\ngroupId=com.kirahowe\nartifactId=secrets\n")}))

(defn- pom!
  "Writes `text` where `release` leaves the pom it built, returning its path."
  [dir text]
  (let [file (io/file dir "target" "classes" pom-entry)]
    (io/make-parents file)
    (spit file text)
    file))

(defn- receipted-jar!
  "A `[jar pom receipt]` triple for a valid release artifact in `dir`.

  The pom on disk is the same text the jar carries, which is what `release`
  produces: `b/jar` copies the pom `b/write-pom` wrote into the artifact."
  [dir]
  (let [entries (maven-entries "0.1.0")
        jar (jar! dir "secrets-0.1.0.jar" entries)
        pom (pom! dir (get entries pom-entry))
        receipt (release/receipt (assoc (release/exact-tag! {:dir dir})
                                        :dir dir
                                        :jar jar
                                        :pom pom))]
    [jar pom receipt]))

(defn- flip-last-byte!
  "Changes exactly one byte of `file` in place: an artifact mutated after it was
  inspected."
  [file]
  (let [path (.toPath (io/file file))
        content (Files/readAllBytes path)
        i (dec (alength content))]
    (aset-byte content i (unchecked-byte (bit-xor (aget content i) 1)))
    (io/copy content (io/file file))))

;;;; The authoritative version

(deftest release-tag-refuses-a-malformed-version-test
  (testing "a version shape that could become a tag name"
    (are [version tag] (= tag (release/release-tag version))
      "0.1.0" "v0.1.0"
      "10.2.30" "v10.2.30"
      "0.2.0-alpha.1" "v0.2.0-alpha.1"))
  (testing "a typo is refused before it can name a tag"
    (are [version] (= ::release/malformed-version
                      (:reason (refusal #(release/release-tag version))))
      "0.1"
      "v0.1.0"
      "0.1.0 "
      "0.1.0-"
      "release"
      "")))

;;;; Repository state

(deftest guards-pass-at-the-exact-release-tag-test
  (let [dir (repo!)]
    (testing "a clean tree at the tag satisfies every guard"
      (is (= dir (release/clean-tree! {:dir dir})))
      (is (= {:tag "v0.1.0" :commit (git! dir "rev-parse" "HEAD")}
             (release/exact-tag! {:dir dir})))
      (is (= "## [0.1.0] - 2026-08-25" (release/changelog-entry! {:dir dir}))))))

(deftest clean-tree-refuses-dirty-and-untracked-inputs-test
  (testing "modified and untracked files alike"
    (are [file contents] (= ::release/dirty-tree
                            (:reason (refusal #(let [dir (repo!)]
                                                 (spit (io/file dir file) contents)
                                                 (release/clean-tree! {:dir dir})))))
      tracked-file "(ns com.kirahowe.secrets.thing) ;; edited\n"
      "extra.clj" "(ns extra)\n"))
  (testing "the refusal says untracked content counts"
    (let [dir (repo!)]
      (spit (io/file dir "extra.clj") "(ns extra)\n")
      (let [{:keys [message status]} (refusal #(release/clean-tree! {:dir dir}))]
        (is (str/includes? message "untracked files count as dirty"))
        (is (= "?? extra.clj" status))))))

(deftest exact-tag-refuses-a-missing-tag-and-a-later-head-test
  (testing "the tag does not exist"
    (let [dir (repo!)]
      (git! dir "tag" "-d" "v0.1.0")
      (is (= ::release/missing-tag (:reason (refusal #(release/exact-tag! {:dir dir})))))))
  (testing "HEAD is one commit past the tag"
    (let [dir (repo!)
          tagged (git! dir "rev-parse" "HEAD")]
      (spit (io/file dir tracked-file) "(ns com.kirahowe.secrets.thing) ;; later\n")
      (git! dir "commit" "-qam" "After the tag")
      (let [{:keys [reason expected found]} (refusal #(release/exact-tag! {:dir dir}))]
        (is (= ::release/head-not-tag reason)
            "a descendant of the tag is a failure, not a pass")
        (is (= tagged expected))
        (is (= (git! dir "rev-parse" "HEAD") found))
        (is (not= expected found))))))

(deftest exact-tag-refuses-a-tag-for-another-version-test
  (let [dir (repo! "0.2.0")]
    (testing "the declared version has no tag of its own"
      (is (= ::release/missing-tag
             (:reason (refusal #(release/exact-tag! {:dir dir :version "0.1.0"}))))))
    (testing "the version the repository actually tagged passes"
      (is (= "v0.2.0" (:tag (release/exact-tag! {:dir dir :version "0.2.0"})))))))

(deftest changelog-entry-requires-a-heading-for-the-version-test
  (testing "no heading for the version being released"
    (let [dir (repo! "0.2.0")
          {:keys [reason heading changelog-exists?]}
          (refusal #(release/changelog-entry! {:dir dir :version "0.1.0"}))]
      (is (= ::release/missing-changelog-entry reason))
      (is (= "## [0.1.0]" heading))
      (is (true? changelog-exists?))))
  (testing "no CHANGELOG at all"
    (let [dir (repo!)]
      (.delete (io/file dir "CHANGELOG.md"))
      (is (false? (:changelog-exists? (refusal #(release/changelog-entry! {:dir dir}))))))))

;;;; The verified source snapshot

(deftest verified-source-exports-the-tag-not-the-worktree-test
  (let [dir (repo!)]
    (spit (io/file dir tracked-file) "(ns com.kirahowe.secrets.thing) ;; after the tag\n")
    (git! dir "commit" "-qam" "After the tag")
    (let [export (release/verified-source! {:dir dir})]
      (try
        (testing "the build input is the tagged tree, not the live one"
          (is (= tagged-contents (slurp (io/file export tracked-file))))
          (is (not= tagged-contents (slurp (io/file dir tracked-file)))))
        (finally
          (release/release-source-cleanup! {:dir dir})))
      (is (not (.exists (io/file export))) "cleanup removes the export"))
    (testing "cleanup is safe when nothing was exported"
      (is (string? (release/release-source-cleanup! {:dir dir}))))))

;;;; Artifact identity

(deftest verify-artifact-metadata-refuses-mismatched-identity-test
  (let [dir (repo!)]
    (testing "the name, both descriptors, and the pom's scm tag must agree"
      (are [jar-name entries reason]
           (= reason (:reason (refusal #(release/verify-artifact-metadata!
                                         (jar! dir jar-name entries) {:dir dir}))))
        "secrets-0.1.0.jar" (maven-entries "0.1.0") nil
        "secrets-0.1.0.jar" (maven-entries "0.2.0") ::release/artifact-metadata-mismatch
        "secrets-0.1.0.jar" {} ::release/artifact-metadata-mismatch
        "secrets-0.1.0.jar" (maven-entries "0.1.0" nil) ::release/artifact-metadata-mismatch
        "secrets-0.1.0.jar" (maven-entries "0.1.0" "v0.2.0") ::release/artifact-metadata-mismatch
        "secrets.jar" (maven-entries "0.1.0") ::release/artifact-name-mismatch))
    (testing "a release that claims no provenance is refused, and says so"
      (is (= {:pom-xml "0.1.0" :scm-tag :absent :pom-properties "0.1.0"}
             (:found (refusal #(release/verify-artifact-metadata!
                                (jar! dir "secrets-0.1.0.jar" (maven-entries "0.1.0" nil))
                                {:dir dir}))))))
    (testing "an absent descriptor is reported as absent, not as a version"
      (is (= {:pom-xml :absent :scm-tag :absent :pom-properties :absent}
             (:found (refusal #(release/verify-artifact-metadata!
                                (jar! dir "secrets-0.1.0.jar" {}) {:dir dir}))))))
    (testing "a jar that declares the version and its tag everywhere is accepted"
      (is (= {:pom-xml "0.1.0" :scm-tag "v0.1.0" :pom-properties "0.1.0"}
             (release/verify-artifact-metadata!
              (jar! dir "secrets-0.1.0.jar" (maven-entries "0.1.0")) {:dir dir}))))))

(deftest verify-pom-requires-the-descriptor-inside-the-artifact-test
  (let [dir (repo!)
        [jar pom receipt] (receipted-jar! dir)]
    (testing "the pom that will be uploaded is the jar's own descriptor"
      (is (= (str pom) (release/verify-pom! receipt))))
    (testing "an artifact carrying no descriptor cannot vouch for a pom"
      (is (= :absent
             (:embedded (refusal #(release/verify-pom!
                                   (assoc receipt :jar (jar! dir "bare-0.1.0.jar" {}))))))))
    (testing "a pom changed after inspection is refused"
      (spit pom (str/replace (slurp pom) "0.1.0" "0.2.0"))
      (is (= ::release/pom-mismatch (:reason (refusal #(release/verify-pom! receipt))))))
    (testing "a missing pom is refused"
      (.delete (io/file pom))
      (is (= ::release/missing-pom (:reason (refusal #(release/verify-pom! receipt))))))
    (testing "the receipt names the pom, so no path can be recomputed instead"
      (is (= (str pom) (:pom receipt)))
      (is (= (str jar) (:jar receipt))))))

(deftest verify-receipt-refuses-an-artifact-changed-after-inspection-test
  (let [dir (repo!)
        [jar _ receipt] (receipted-jar! dir)]
    (testing "an untouched artifact still matches its receipt"
      (is (= receipt (release/verify-receipt! receipt {:dir dir})))
      (is (= (release/sha256-file jar) (:sha256 receipt))))
    (testing "a receipt that describes another commit is refused"
      (is (= ::release/receipt-mismatch
             (:reason (refusal #(release/verify-receipt!
                                 (assoc receipt :commit (str/reverse (:commit receipt)))
                                 {:dir dir}))))))
    (testing "one changed byte is refused"
      (flip-last-byte! jar)
      (let [{:keys [reason expected found]} (refusal #(release/verify-receipt! receipt
                                                                               {:dir dir}))]
        (is (= ::release/digest-mismatch reason))
        (is (= (:sha256 receipt) expected))
        (is (not= expected found))))))

;;;; The publisher boundary

;;; The publisher lives in `com.kirahowe.secrets.publish`, whose `-M:deploy`
;;; alias supplies maven-resolver; it is therefore not loadable from the test
;;; classpath. What it decides before uploading is `verified-artifact!` — the
;;; receipt it reads, the checks it runs, and the `:jar` and `:pom` it hands on
;;; — and that is what is covered here. The upload itself is covered by
;;; `com.kirahowe.secrets.publish-policy-test`, which runs the real publisher
;;; against a local recorder.

(deftest the-publisher-is-handed-the-inspected-artifact-test
  (let [dir (repo!)
        [jar pom receipt] (receipted-jar! dir)]
    (release/write-receipt! receipt {:dir dir})
    (testing "the upload consumes exactly the receipted files"
      (is (= {:jar (str jar) :pom (str pom)}
             (select-keys (release/verified-artifact! {:dir dir}) [:jar :pom])))
      (is (= receipt (release/read-receipt! {:dir dir}))))
    (testing "a pom changed after inspection is refused"
      (spit pom (str (slurp pom) "\n"))
      (is (= ::release/pom-mismatch
             (:reason (refusal #(release/verified-artifact! {:dir dir})))))
      (pom! dir (get (maven-entries "0.1.0") pom-entry)))
    (testing "a changed artifact is refused before any credential is used"
      (flip-last-byte! jar)
      (is (= ::release/digest-mismatch
             (:reason (refusal #(release/verified-artifact! {:dir dir}))))))
    (testing "a missing receipt refuses rather than rebuilding"
      (.delete (release/receipt-path {:dir dir}))
      (let [{:keys [reason message]} (refusal #(release/verified-artifact! {:dir dir}))]
        (is (= ::release/missing-receipt reason))
        (is (str/includes? message "clojure -T:build release"))))))
