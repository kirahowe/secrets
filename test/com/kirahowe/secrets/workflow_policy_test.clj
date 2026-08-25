(ns com.kirahowe.secrets.workflow-policy-test
  "Checks on the workflow policy, on this repository's workflows, and on its docs.

  Two tests are the enforcement: one over every workflow file, one over every
  documented example. Both discover their sources rather than naming them, so a
  workflow or a chapter added later is covered without anyone remembering to
  extend this file, and both assert they found something, because a check that
  silently stops matching passes. The rest pin down what the policy accepts and
  rejects, the shapes it has to read a reference out of, and the extraction that
  turns a chapter's prose back into workflow text."
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

(defn- documentation-files
  "Returns the documentation that carries workflow examples.
  The chapters are globbed, so a chapter added later is checked; the root README
  is named, because there is exactly one of it."
  []
  (conj (->> (file-seq (io/file "book" "chapters"))
             (filter #(str/ends-with? (str %) ".clj"))
             (sort-by str)
             vec)
        (io/file "README.md")))

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

(defn- job-scoped-identity
  "Workflow text granting `variable` to a whole job, before any step runs."
  [variable]
  (yaml "verify-secrets:"
        "  runs-on: ubuntu-latest"
        "  env:"
        (str "    " variable ": ${{ secrets.SECRETS_AGE_IDENTITY }}")
        "  steps:"
        (str "    - uses: actions/checkout@" pinned-sha " # v6.1.0")
        "    - run: bb secrets verify"))

(defn- step-scoped-identity
  "Workflow text granting `variable` to the one step that consumes it."
  [variable]
  (yaml "verify-secrets:"
        "  runs-on: ubuntu-latest"
        "  steps:"
        (str "    - uses: actions/checkout@" pinned-sha " # v6.1.0")
        "    - run: bb secrets verify"
        "      env:"
        (str "        " variable ": ${{ secrets.SECRETS_AGE_IDENTITY }}")))

;; A literate chapter in miniature, one line per line, so the line numbers
;; asserted below are the positions in this vector: 4 and 5 are the first YAML
;; example, 11 is a shell example that is not one, and 15 is the second.
(def ^:private literate-chapter
  (yaml ";; # A chapter"
        ";;"
        ";; ```yaml"
        ";; verify:"
        ";;   runs-on: ubuntu-latest"
        ";; ```"
        ""
        "(def answer 42)"
        ""
        ";; ```sh"
        ";; bb secrets verify"
        ";; ```"
        ";;"
        ";; ```yaml"
        (str ";; - uses: actions/checkout@" pinned-sha)
        ";; ```"))

(defn- as-identity
  "Renames every secret-bearing `env:` key in workflow `text` to the identity.
  The placement rule knows only the age identity variables, so this is how a
  workflow's real declarations get asked the question: whatever a secret holds,
  this repository should be injecting it at step scope."
  [text]
  (str/replace text #"(?m)^(\s*)[A-Z_]+(: \$\{\{ secrets\.)" "$1SECRETS_AGE_IDENTITY$2"))

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

(deftest repository-workflows-have-no-job-scoped-identity-test
  (testing "no workflow grants an age identity wider than the step that uses it"
    (doseq [file (workflow-files)]
      (is (empty? (filter (comp #{:wider} :scope)
                          (policy/identity-env-references (slurp file))))
          (str file))))
  (let [declarations (mapcat (comp policy/identity-env-references as-identity slurp)
                             (workflow-files))]
    (testing "the secrets these workflows do inject are injected at step scope"
      (is (seq declarations))
      (is (every? (comp #{:step} :scope) declarations)))))

;;;; The documented examples

(deftest documentation-workflow-examples-are-pinned-test
  (let [examples (for [file (documentation-files)
                       block (policy/documentation-yaml-blocks (slurp file))]
                   [(str file) block])]
    (testing "the documented examples were found, so a pass cannot be vacuous"
      (is (seq examples)))
    (doseq [[source block] examples]
      (testing source
        (let [found (policy/violations source block)]
          (is (empty? found)
              (str/join "\n" (map policy/finding-message found))))))))

(deftest literate-yaml-extraction-test
  (let [blocks (policy/documentation-yaml-blocks literate-chapter)]
    (testing "every fenced yaml block is extracted, and nothing in another language"
      (is (= 2 (count blocks)))
      (is (not-any? #(str/includes? % "bb secrets verify") blocks)))
    (testing "the comment prefix comes off and the example's own indentation stays"
      (is (= "verify:\n  runs-on: ubuntu-latest" (str/trim (first blocks)))))
    (testing "a block holds its position, so a finding names the chapter's own line"
      (is (= [15] (map :line (policy/violations "chapter.clj" (second blocks))))))
    (testing "prose and code with no fence yield no block"
      (is (empty? (policy/documentation-yaml-blocks
                   (yaml ";; Just prose." "(def answer 42)")))))))

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

(deftest policy-rejects-job-scoped-identity-test
  (testing "an identity granted to a whole job is refused, in each of its spellings"
    (are [variable] (= [::policy/widely-scoped-identity]
                       (map :reason (policy/violations "fixture.yml"
                                                       (job-scoped-identity variable))))
      "SECRETS_AGE_IDENTITY"
      "SECRETS_AGE_IDENTITY_B64"
      "SECRETS_AGE_IDENTITY_FILE"))
  (testing "the same variable on the step that consumes it is the shape wanted"
    (are [variable] (empty? (policy/violations "fixture.yml"
                                               (step-scoped-identity variable)))
      "SECRETS_AGE_IDENTITY"
      "SECRETS_AGE_IDENTITY_B64"
      "SECRETS_AGE_IDENTITY_FILE"))
  (testing "the finding names the line the credential is declared on"
    (is (= [{:source "fixture.yml" :kind :env :line 4
             :reference "SECRETS_AGE_IDENTITY"
             :reason ::policy/widely-scoped-identity}]
           (policy/violations "fixture.yml"
                              (job-scoped-identity "SECRETS_AGE_IDENTITY"))))))

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
