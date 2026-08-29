(ns com.kirahowe.secrets.dependency-audit-test
  "Policy checks for exact dependency-graph advisory auditing."
  (:require [clojure.edn :as edn]
            [clojure.set :as set]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [com.kirahowe.secrets.dependency-audit :as audit]))

(def ^:private config
  (edn/read-string (slurp ".github/dependency-audit.edn")))

(def ^:private deps
  (edn/read-string (slurp "deps.edn")))

(def ^:private reviewed-advisories
  #{"GHSA-72hv-8253-57qq"
    "GHSA-r7wm-3cxj-wff9"
    "GHSA-3pjw-73gf-8qr5"
    "GHSA-5gvw-p9qm-jgwh"
    "GHSA-5jmj-h7xm-6q6v"
    "GHSA-hgj6-7826-r7m5"
    "GHSA-j3rv-43j4-c7qm"
    "GHSA-mhm7-754m-9p8w"
    "GHSA-rmj7-2vxq-3g9f"
    "GHSA-vv7r-c36w-3prj"
    "GHSA-7p3p-8qv8-m2vh"
    "GHSA-f4v5-65jj-pcr2"
    "GHSA-xxh7-fcf3-rj7f"
    "GHSA-355h-qmc2-wpwf"
    "GHSA-wjpw-4j6x-6rwh"
    "GHSA-w7x5-g22v-xqhr"
    "GHSA-2fvj-hgj9-j2gr"
    "GHSA-6fmv-xxpf-w3cw"
    "GHSA-qh8g-58pp-2wxh"})

(deftest exact-graph-record-test
  (let [libs {'direct/lib {:mvn/version "1.2.3" :parents #{[]}}
              'transitive/lib {:mvn/version "4.5.6"
                               :parents #{['direct/lib]}}}
        record (audit/graph-record libs)]
    (testing "exact versions and full root-to-package paths are retained"
      (is (= {:packages
              [{:coordinate ["direct/lib" "1.2.3"]
                :dependency-paths [["direct/lib"]]}
               {:coordinate ["transitive/lib" "4.5.6"]
                :dependency-paths [["direct/lib" "transitive/lib"]]}]}
             record)))
    (testing "the scanner receives Maven package names and those exact versions"
      (is (= {:results
              [{:packages
                [{:package {:name "direct:lib"
                            :version "1.2.3"
                            :ecosystem "Maven"}}
                 {:package {:name "transitive:lib"
                            :version "4.5.6"
                            :ecosystem "Maven"}}]}]}
             (audit/scanner-input record))))))

(deftest unscannable-coordinate-is-refused-test
  (testing "a git dependency cannot silently disappear from an all-graph audit"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo
                          #"coordinates OSV cannot scan"
                          (audit/graph-record
                           {'owner/project {:git/sha "0123456789abcdef"}})))))

(deftest every-dependency-alias-is-configured-test
  (let [configured (set (map (comp first :aliases) (:graphs config)))
        configured-names (set (map :name (:graphs config)))
        aliases (set (keys (:aliases deps)))]
    (testing "the default graph and every alias are named exactly once"
      (is (= (inc (count aliases)) (count (:graphs config))))
      (is (= aliases (disj configured nil)))
      (is (contains? configured-names "default"))
      (is (= (count configured-names) (count (:graphs config)))))
    (testing "release preflight can select the credential-bearing graph explicitly"
      (is (= [:deploy]
             (:aliases (first (filter (comp #{"deploy"} :name)
                                      (:graphs config)))))))))

(deftest scanner-pin-is-reproducible-test
  (let [{:keys [version base-url assets]} (:scanner config)]
    (testing "the release URL is immutable in repository configuration"
      (is (= "2.5.1" version))
      (is (str/ends-with? base-url (str "/v" version "/"))))
    (testing "every supported CI/developer asset has an exact checksum"
      (is (= #{"darwin-amd64" "darwin-arm64"
               "linux-amd64" "linux-arm64"
               "windows-amd64" "windows-arm64"}
             (set (keys assets))))
      (is (every? #(re-matches #"[0-9a-f]{64}" (:sha256 %)) (vals assets)))
      (is (every? #(str/starts-with? (:file %) "osv-scanner_") (vals assets))))
    (testing "there is no advisory ignore mechanism in the configuration"
      (is (not-any? #(contains? config %)
                    [:ignore :ignores :allow :allowlist])))))

(deftest prior-matches-have-complete-dispositions-test
  (let [reviews (:reviews config)
        actual-advisories (set (mapcat :advisories reviews))
        required #{:graph :coordinate :dependency-path :advisories :surface
                   :repository-input :fixed-version :disposition :reachability
                   :review-date}]
    (testing "every package match that prompted issue 033 remains owner-visible"
      (is (= reviewed-advisories actual-advisories))
      (is (every? #(set/subset? required (set (keys %))) reviews))
      (is (every? (comp seq :dependency-path) reviews))
      (is (every? (comp seq :surface) reviews))
      (is (every? (comp seq :repository-input) reviews))
      (is (every? (comp seq :fixed-version) reviews))
      (is (every? (comp #{:not-demonstrated} :reachability) reviews))
      (is (every? #(re-matches #"\d{4}-\d{2}-\d{2}" (:review-date %)) reviews)))
    (testing "a raw package match is never recorded as proven exploitation"
      (is (not-any? #(contains? % :exploitable) reviews)))))

(deftest affected-tooling-lines-are-overridden-test
  (let [book-overrides (get-in deps [:aliases :book :override-deps])
        lint-overrides (get-in deps [:aliases :lint :override-deps])
        reviewed (set (map (juxt :graph :coordinate) (:reviews config)))]
    (testing "the EE9 integration moves with Jetty's fixed security line"
      (is (= "12.1.10"
             (get-in book-overrides
                     ['org.eclipse.jetty.ee9/jetty-ee9-security :mvn/version])))
      (is (contains?
           reviewed
           [:book ['org.eclipse.jetty.ee9/jetty-ee9-security "12.1.8"]])))
    (testing "lint moves Cheshire's Jackson core and dataformats as one line"
      (is (= #{'com.fasterxml.jackson.core/jackson-core
               'com.fasterxml.jackson.dataformat/jackson-dataformat-cbor
               'com.fasterxml.jackson.dataformat/jackson-dataformat-smile}
             (set (keys lint-overrides))))
      (is (= #{"2.18.9"}
             (set (map :mvn/version (vals lint-overrides)))))
      (is (contains?
           reviewed
           [:lint ['com.fasterxml.jackson.core/jackson-core "2.17.0"]])))))

(deftest build-only-dependencies-stay-isolated-test
  (let [runtime-libs (set (keys (:deps deps)))
        deploy-libs (set (keys (get-in deps [:aliases :deploy :replace-deps])))
        book-libs (set (concat (keys (get-in deps [:aliases :book :extra-deps]))
                               (keys (get-in deps [:aliases :book :override-deps]))))
        build-libs (set (keys (get-in deps [:aliases :build :deps])))
        tooling-libs (set/union book-libs build-libs)]
    (testing "the published library basis contains only runtime dependencies"
      (is (= #{'org.clojure/clojure 'org.babashka/cli} runtime-libs))
      (is (= "0.12.86" (get-in deps [:deps 'org.babashka/cli :mvn/version])))
      (is (= ["src"] (:paths deps)))
      (is (empty? (set/intersection runtime-libs tooling-libs))))
    (testing "the credential-bearing deploy replacement excludes book/build tooling"
      (is (contains? deploy-libs 'org.clojure/clojure))
      (is (empty? (set/intersection deploy-libs tooling-libs)))
      (is (= ["build"] (get-in deps [:aliases :deploy :replace-paths]))))))

(deftest alpha-release-workflows-enforce-the-audit-test
  (let [ci (slurp ".github/workflows/ci.yml")
        release (slurp ".github/workflows/release.yml")
        ci-command "clojure -M:audit"
        release-command "clojure -M:audit deploy"
        audit-step "- name: Audit the credential-bearing deploy graph"
        publish-step "- name: Publish the receipted artifact to Clojars"
        audit-index (str/index-of release audit-step)
        publish-index (str/index-of release publish-step)
        credential-index (str/index-of
                          release "CLOJARS_USERNAME: ${{ secrets.CLOJARS_USERNAME }}")]
    (testing "CI scans the default graph and every configured alias"
      (is (str/includes? ci ci-command))
      (is (str/includes? ci "dependency-advisory-audit")))
    (testing "Pages deployment cannot outrun the build/book audit"
      (is (str/includes? ci "- dependency-advisory-audit")))
    (testing "release scans only the exact deploy graph before credentials exist"
      (is (str/includes? release release-command))
      (is (and audit-index publish-index credential-index
               (< audit-index publish-index credential-index)))
      (is (and audit-index publish-index
               (not (str/includes?
                     (subs release (+ audit-index (count audit-step)) publish-index)
                     "- name:")))))))
