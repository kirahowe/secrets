(ns com.kirahowe.secrets.coordinate-test
  "The library's coordinates are written once, in
  `src/com/kirahowe/secrets/coordinate.edn`, and every other copy has to agree
  with it: what the release guards read, what the initializer scaffolds, and
  what the README shows.

  The commit the initializer pins is not in that file. It is asked of the
  checkout the initializer runs from, so the tests of that lookup drive
  `library-dependency` with a fake git, and the repository tests read the
  repository they run in, on purpose: the README is the copy most likely to
  drift, and this checkout is the one the initializer would pin."
  (:require [clojure.edn :as edn]
            [clojure.java.shell :as sh]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [com.kirahowe.secrets.init :as init]
            [com.kirahowe.secrets.release :as release]))

(def ^:private default-dependency @@#'init/default-dependency)
(def ^:private known-coordinates @#'init/known-coordinates)

;;;; Locating the running library

(def ^:private coordinates
  {:lib 'com.kirahowe/secrets :version "0.1.0" :git-lib 'io.github.kirahowe/secrets})

(def ^:private checkout-url
  (java.net.URL. "file:/checkout/src/com/kirahowe/secrets/coordinate.edn"))

(def ^:private jar-url
  (java.net.URL. (str "jar:file:/m2/com/kirahowe/secrets/0.1.0/secrets-0.1.0.jar"
                      "!/com/kirahowe/secrets/coordinate.edn")))

(def ^:private commit "89ded34ce8bd146754cc3ec9971d1ea1fd25da28")

(defn- fake-git
  "A git whose `HEAD` is `commit` with `tags` pointing at it, recording in
  `asked` every directory it is run in."
  [asked commit tags]
  (fn [dir & args]
    (swap! asked conj (str dir))
    (case (vec args)
      ["rev-parse" "HEAD"] {:exit 0 :out (str commit "\n") :err ""}
      ["tag" "--points-at" "HEAD"] {:exit 0 :out (str/join "\n" tags) :err ""})))

(defn- no-repository [& _]
  {:exit 128 :out "" :err "fatal: not a git repository\n"})

(deftest a-checkout-at-the-release-tag-is-pinned-by-tag-and-commit-test
  (let [asked (atom [])]
    (is (= {'io.github.kirahowe/secrets {:git/tag "v0.1.0" :git/sha commit}}
           (init/library-dependency checkout-url coordinates
                                    (fake-git asked commit ["latest" "v0.1.0"]))))
    (is (= ["/checkout/src/com/kirahowe/secrets"] (distinct @asked))
        "git is asked in the directory the resource was loaded from")))

(deftest a-checkout-off-the-release-tag-is-pinned-by-commit-alone-test
  (testing "no tag at all"
    (is (= {'io.github.kirahowe/secrets {:git/sha commit}}
           (init/library-dependency checkout-url coordinates (fake-git (atom []) commit [])))))
  (testing "a tag for some other version is not the release tag"
    (is (= {'io.github.kirahowe/secrets {:git/sha commit}}
           (init/library-dependency checkout-url coordinates
                                    (fake-git (atom []) commit ["v0.0.9"]))))))

(deftest the-jar-is-pinned-by-its-maven-version-test
  (is (= {'com.kirahowe/secrets {:mvn/version "0.1.0"}}
         (init/library-dependency jar-url coordinates
                                  (fn [& _] (throw (AssertionError. "git must not run")))))))

(deftest a-source-tree-outside-git-is-refused-test
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #"not a git repository"
                        (init/library-dependency checkout-url coordinates no-repository))))

;;;; This repository

(def ^:private written (release/read-coordinates "."))

(defn- git-here
  "Trimmed stdout of `git` in the repository these tests run in."
  [& args]
  (str/trim (:out (apply sh/sh "git" args))))

(deftest the-coordinate-file-carries-no-commit-test
  (is (= #{:lib :version :git-lib} (set (keys written)))
      "a commit written here could only ever name the release before this one"))

(deftest guards-and-initializer-read-the-same-coordinates-test
  (is (= (:lib written) release/lib))
  (is (= (:version written) release/version))
  (is (= #{(:lib written) (:git-lib written)} known-coordinates)
      "the initializer recognizes both names the library is declared under"))

(deftest the-initializer-pins-this-checkout-test
  (let [[lib pin] (first default-dependency)
        tag (release/release-tag)
        tagged? (contains? (set (str/split-lines (git-here "tag" "--points-at" "HEAD"))) tag)]
    (is (= (:git-lib written) lib))
    (is (= (git-here "rev-parse" "HEAD") (:git/sha pin))
        "the pin is the commit these tests run from")
    (is (= (when tagged? tag) (:git/tag pin))
        "the release tag is written exactly when it names HEAD")))

(defn- readme-coordinates
  "Every `<lib> {…}` coordinate for `lib` the README shows, as maps, in order
  of appearance. A coordinate map is flat, so the match stops at its first
  closing brace."
  [lib]
  (let [pattern (re-pattern (str "(?s)" (java.util.regex.Pattern/quote (str lib))
                                 "\\s*(\\{[^{}]*\\})"))]
    (mapv (fn [[_ m]] (edn/read-string m))
          (re-seq pattern (slurp "README.md")))))

(deftest readme-shows-the-coordinates-the-initializer-writes-test
  (let [git-copies (readme-coordinates (:git-lib written))
        maven-copies (filter #(contains? % :mvn/version) (readme-coordinates release/lib))]
    (testing "every git coordinate in the README names the release tag and no commit"
      (is (seq git-copies) "the README shows the git coordinate at least once")
      (doseq [copy git-copies]
        (is (= #{:git/tag :git/sha} (set (keys copy))))
        (is (= (release/release-tag) (:git/tag copy)))
        (is (not (re-matches #"[0-9a-f]{7,40}" (:git/sha copy)))
            "the commit is the initializer's to fill in; a copy here would go stale")))
    (testing "every Maven coordinate in the README names the release version"
      (is (seq maven-copies) "the README shows the Maven coordinate at least once")
      (doseq [copy maven-copies]
        (is (= {:mvn/version release/version} copy))))))
