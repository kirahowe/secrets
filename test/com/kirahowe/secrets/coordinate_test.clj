(ns com.kirahowe.secrets.coordinate-test
  "The library's coordinates are written once, in
  `src/com/kirahowe/secrets/coordinate.edn`, and every other copy has to agree
  with it: what the release guards read, what the initializer scaffolds, and
  what the README shows.

  These tests read the repository they run in, on purpose: the README is the
  copy most likely to drift."
  (:require [clojure.edn :as edn]
            [clojure.test :refer [deftest is testing]]
            [com.kirahowe.secrets.init :as init]
            [com.kirahowe.secrets.release :as release]))

(def ^:private default-dependency @#'init/default-dependency)
(def ^:private known-coordinates @#'init/known-coordinates)

(defn- readme-coordinates
  "Every `<lib> {…}` coordinate for `lib` the README shows, as maps, in order
  of appearance. A coordinate map is flat, so the match stops at its first
  closing brace."
  [lib]
  (let [pattern (re-pattern (str "(?s)" (java.util.regex.Pattern/quote (str lib))
                                 "\\s*(\\{[^{}]*\\})"))]
    (mapv (fn [[_ m]] (edn/read-string m))
          (re-seq pattern (slurp "README.md")))))

(deftest guards-and-initializer-read-the-same-coordinates-test
  (let [written (release/read-coordinates ".")
        {git-lib :lib :keys [tag sha]} (:git written)]
    (is (= (:lib written) release/lib))
    (is (= (:version written) release/version))
    (is (= (:git written) release/git-coordinate))
    (is (= {git-lib {:git/tag tag :git/sha sha}} default-dependency)
        "the initializer scaffolds the pin as written")
    (is (= #{(:lib written) git-lib} known-coordinates)
        "the initializer recognizes both names the library is declared under")))

(deftest readme-shows-the-coordinates-the-initializer-writes-test
  (let [[git-lib pin] (first default-dependency)
        git-copies (readme-coordinates git-lib)
        maven-copies (filter #(contains? % :mvn/version) (readme-coordinates release/lib))]
    (testing "every git coordinate in the README is the initializer's pin"
      (is (seq git-copies) "the README shows the git coordinate at least once")
      (doseq [copy git-copies]
        (is (= pin copy))))
    (testing "every Maven coordinate in the README names the release version"
      (is (seq maven-copies) "the README shows the Maven coordinate at least once")
      (doseq [copy maven-copies]
        (is (= {:mvn/version release/version} copy))))))
