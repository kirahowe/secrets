(ns com.kirahowe.secrets.workflow-policy-test
  "Checks on the workflow pinning policy, and on this repository's own workflows.

  The first test is the enforcement: it discovers every workflow file rather than
  naming them, so a workflow added later is covered without anyone remembering to
  extend this file. The rest pin down what the policy accepts and rejects, and
  the shapes it has to read a reference out of."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [are deftest is testing]]
            [com.kirahowe.secrets.workflow-policy :as policy]))

;;;; Fixtures

(defn- workflow-files
  "Returns every workflow file in this repository, discovered rather than named."
  []
  (->> (file-seq (io/file ".github" "workflows"))
       (filter #(str/ends-with? (str %) ".yml"))
       (sort-by str)))

(defn- yaml
  "Joins `lines` into workflow text, so a fixture's line numbers are visible."
  [& lines]
  (str (str/join "\n" lines) "\n"))

;; One line per YAML line, so the 1-based line numbers asserted below are the
;; positions in this vector: 4 is the image, 6 and 8 are `- uses:` steps, 7 is a
;; comment that names a reference without being one, and 10 is a quoted `uses:`.
(def ^:private shapes-yaml
  (yaml "jobs:"
        "  build:"
        "    container:"
        "      image: babashka/babashka:1.13.219"
        "    steps:"
        "      - uses: actions/checkout@v6"
        "      # uses: actions/checkout@v5 - prose, not a step"
        "      - uses: actions/cache@v4 # v4.3.0"
        "      - name: A quoted reference"
        "        uses: \"actions/setup-java@v5\""))

;; A real commit SHA, used only for its shape.
(def ^:private pinned-sha "d23441a48e516b6c34aea4fa41551a30e30af803")

(def ^:private babashka-digest
  "sha256:bac7033becd44e73225c2684312066034d6ad9b9a2d5d1100f89a71863074830")

;;;; This repository's workflows

(deftest repository-workflows-are-pinned-test
  (let [files (workflow-files)]
    (testing "the workflows were found at all, so a pass cannot be vacuous"
      (is (seq files)))
    (doseq [file files]
      (testing (str file)
        (let [found (policy/violations (str file) (slurp file))]
          (is (empty? found)
              (str/join "\n" (map policy/finding-message found))))))))

;;;; What the policy refuses

(deftest policy-rejects-mutable-references-test
  (testing "a reference that upstream can retarget is refused, saying which problem it is"
    (are [reason text] (= [reason] (map :reason (policy/violations "fixture.yml" text)))
      ::policy/mutable-action-reference (yaml "      - uses: actions/checkout@v6")
      ::policy/mutable-action-reference (yaml "      - uses: actions/checkout@main")
      ::policy/mutable-action-reference (yaml "      - uses: actions/checkout@d23441a")
      ::policy/unlabelled-action-reference (yaml (str "      - uses: actions/checkout@"
                                                      pinned-sha))
      ::policy/mutable-image-reference (yaml "      image: babashka/babashka:1.13.219")
      ::policy/unsupported-action-reference (yaml "      - uses: docker://alpine:3.20")
      ::policy/unsupported-action-reference (yaml "      - uses: ./.github/actions/build"))))

;;;; What the policy accepts

(deftest policy-accepts-pinned-references-test
  (testing "a full SHA with a version comment, a subdirectory action, and a digest all pass"
    (are [text] (empty? (policy/violations "fixture.yml" text))
      (yaml (str "      - uses: actions/checkout@" pinned-sha " # v6.1.0"))
      (yaml (str "      - uses: quarto-dev/quarto-actions/setup@" pinned-sha " # v2.2.0"))
      (yaml (str "      image: babashka/babashka@" babashka-digest)))))

;;;; Reading references out of real workflow text

(deftest reference-parsing-handles-real-workflow-shapes-test
  (testing "the `- uses:` and `uses:` forms, a quoted value, and an inline comment"
    (is (= [{:line 6 :reference "actions/checkout@v6" :comment nil}
            {:line 8 :reference "actions/cache@v4" :comment "v4.3.0"}
            {:line 10 :reference "actions/setup-java@v5" :comment nil}]
           (policy/action-references shapes-yaml))))
  (testing "a `#` comment line mentioning a reference is not one; line 7 is absent above"
    (is (empty? (filter (comp #{7} :line) (policy/action-references shapes-yaml)))))
  (testing "an indented image reference is read the same way"
    (is (= [{:line 4 :reference "babashka/babashka:1.13.219" :comment nil}]
           (policy/image-references shapes-yaml)))))
