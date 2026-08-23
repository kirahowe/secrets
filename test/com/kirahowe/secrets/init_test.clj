(ns com.kirahowe.secrets.init-test
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [are deftest is testing use-fixtures]]
            [com.kirahowe.secrets.cli :as cli]
            [com.kirahowe.secrets.init :as init])
  (:import [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]))

;;;; Fixtures

(def ^:dynamic ^:private *dir* nil)

(defn- delete-tree! [file]
  (doseq [child (reverse (file-seq (io/file (str file))))]
    (.delete child)))

(defn- with-temp-dir [test-fn]
  (let [dir (str (Files/createTempDirectory
                  "secrets-init-test"
                  (make-array FileAttribute 0)))]
    (binding [*dir* dir]
      (try
        (test-fn)
        (finally
          (delete-tree! dir))))))

(use-fixtures :each with-temp-dir)

;;;; Argument Parsing and Configuration

(deftest parses-required-options-and-defaults-test
  (testing "default and explicit options"
    (is (= {:app "reader" :env "dev" :layout :tracked}
           (init/parse-args ["--app" "reader"])))
    (is (= {:app "reader"
            :env "prod"
            :layout :disposable
            :team? true
            :keygen? true
            :apply? true}
           (init/parse-args ["--app" "reader"
                             "--env" "prod"
                             "--layout" "disposable"
                             "--team"
                             "--keygen"
                             "--apply"]))))
  (testing "required values"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo
                          #"required"
                          (init/parse-args [])))
    (are [option following]
         (thrown-with-msg? clojure.lang.ExceptionInfo
                           #"needs"
                           (init/parse-args [option following]))
      "--app" "--team"
      "--env" "--keygen"
      "--layout" "--apply"))
  (testing "standalone help"
    (is (= {:env "dev" :layout :tracked :help? true}
           (init/parse-args ["--help"]))
        "help must not demand an app name")
    (is (str/includes? (with-out-str (init/-main "--help")) "Usage:")
        "the standalone entry point also accepts --help without --app")))

(deftest layouts-are-safe-and-normalizable-test
  (let [tracked (init/proposed-config {:app "reader"})
        disposable (init/proposed-config
                    {:app "reader" :layout :disposable :team? true})]
    (testing "tracked layout"
      (is (= "secrets/secrets.edn.age"
             (get-in tracked [:environments :dev :secrets-file])))
      (is (nil? (get-in tracked [:environments :dev :key-file]))
          "tracked stores keep the default private identity external"))
    (testing "disposable team layout"
      (is (= ".local/secrets/key.txt"
             (get-in disposable [:environments :dev :key-file])))
      (is (= ".local/secrets/recipients.txt"
             (get-in disposable [:environments :dev :recipients-file])))
      (is (= "secrets/secrets.edn.example"
             (get-in disposable [:environments :dev :template])))
      (is (map? (cli/normalize-config disposable))))))

;;;; bb.edn Integration

(deftest merge-preserves-comments-and-unrelated-forms-test
  (let [source (str "; keep me\n"
                    "{:paths [\"src\"]\n"
                    " :deps {acme/lib {:mvn/version \"1\"}}\n"
                    " :tasks {lint {:task (println :lint)}}}\n")
        result (init/merge-bb-edn source (init/proposed-config {:app "reader"}))]
    (is (re-find #"; keep me" (:content result)))
    (is (re-find #"acme/lib" (:content result)))
    (is (re-find #"lint" (:content result)))
    (is (re-find #"io.github.kirahowe/secrets" (:content result)))
    (is (re-find #"secrets" (:content result))))
  (testing "new dependencies precede new tasks"
    (let [content (:content
                   (init/merge-bb-edn
                    "{}\n"
                    (init/proposed-config {:app "reader"})))]
      (is (< (str/index-of content ":deps")
             (str/index-of content ":tasks"))))))

(deftest merge-reuses-known-dependency-and-rejects-task-conflict-test
  (let [config (init/proposed-config {:app "reader"})
        reused (init/merge-bb-edn
                "{:deps {com.kirahowe/secrets {:local/root \"../secrets\"}} :tasks {}}"
                config)]
    (testing "known dependency coordinates are reused"
      (is (= 'com.kirahowe/secrets (:dependency reused)))
      (is (not (:added-dependency? reused))))
    (testing "an existing conflicting task is rejected"
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo
           #"conflicting"
           (init/merge-bb-edn
            "{:deps {} :tasks {secrets {:task (println :other)}}}"
            config))))))

;;;; Preview and Interaction

(deftest noninteractive-preview-and-manual-cancel-do-not-mutate-test
  (testing "non-TTY without --apply is strictly preview-only"
    (is (= :preview
           (:status (init/init! {:root *dir* :app "reader" :tty? false}))))
    (is (not (.exists (io/file *dir* "bb.edn")))))
  (testing "manual and cancel do not write or generate a key"
    (let [called (atom false)]
      (with-redefs [cli/keygen! (fn [& _] (reset! called true))]
        (is (= :manual
               (:status
                (init/init! {:root *dir*
                             :app "reader"
                             :tty? true
                             :choice :manual
                             :keygen? true}))))
        (is (= :cancelled
               (:status
                (init/init! {:root *dir*
                             :app "reader"
                             :tty? true
                             :choice :cancel
                             :keygen? true})))))
      (is (false? @called))
      (is (not (.exists (io/file *dir* "bb.edn")))))))

(deftest preview-shows-before-and-after-content-test
  (let [out (with-out-str
              (init/print-preview!
               {:changes
                [{:path "bb.edn"
                  :old "{:paths [\"src\"]}\n"
                  :content "{:paths [\"src\"] :deps {x/y {}}}\n"}
                 {:path "secrets/secrets.edn.example"
                  :old nil
                  :content "{:example/api-key \"replace-me\"}\n"}]}))]
    (is (str/includes? out "--- a/bb.edn"))
    (is (str/includes? out "-{:paths [\"src\"]}"))
    (is (str/includes? out "+{:paths [\"src\"] :deps {x/y {}}}"))
    (is (str/includes? out "--- /dev/null"))
    (is (str/includes? out "+{:example/api-key \"replace-me\"}"))))

(deftest injected-choice-function-is-invoked-test
  (is (= :manual
         (:status
          (init/init! {:root *dir*
                       :app "reader"
                       :tty? true
                       :input (fn [] "m")}))))
  (is (not (.exists (io/file *dir* "bb.edn")))))

(deftest manual-integration-is-copyable-pretty-edn-test
  (let [out (with-out-str
              (init/init! {:root *dir*
                           :app "reader"
                           :tty? true
                           :choice :manual}))]
    (is (str/includes? out "io.github.kirahowe/secrets")
        "do not print a namespace-map shorthand coordinate")
    (is (str/includes? out "\n :tasks\n {secrets")
        "task configuration is formatted over readable lines")))

;;;; Scaffold Safety and Application

(deftest existing-public-artifacts-are-preserved-when-safe-test
  (let [template (io/file *dir* "secrets/secrets.edn.example")
        recipients (io/file *dir* "secrets/recipients.txt")]
    (.mkdirs (.getParentFile template))
    (spit template "{:custom/value 42}\n")
    (spit recipients "# Alice\nage1existing\n")
    (let [proposal (init/proposed-changes
                    {:root *dir* :app "reader" :team? true})]
      (is (not-any? #(= "secrets/secrets.edn.example" (:path %))
                    (:changes proposal)))
      (is (not-any? #(= "secrets/recipients.txt" (:path %))
                    (:changes proposal))))
    (init/init! {:root *dir*
                 :app "reader"
                 :team? true
                 :apply? true
                 :tty? false})
    (is (= "{:custom/value 42}\n" (slurp template)))
    (is (= "# Alice\nage1existing\n" (slurp recipients)))))

(deftest invalid-existing-template-and-symlinked-ancestor-are-rejected-test
  (testing "invalid existing templates"
    (let [template (io/file *dir* "secrets/secrets.edn.example")]
      (.mkdirs (.getParentFile template))
      (spit template "not an edn map")
      (is (thrown-with-msg? clojure.lang.ExceptionInfo
                            #"must contain an EDN map"
                            (init/proposed-changes {:root *dir* :app "reader"})))
      (spit template "{")
      (is (thrown-with-msg? clojure.lang.ExceptionInfo
                            #"not valid EDN"
                            (init/proposed-changes {:root *dir* :app "reader"})))))
  (testing "symlinked ancestors"
    (let [link (.toPath (io/file *dir* "secrets"))]
      (delete-tree! link)
      (spit (io/file *dir* "symlink-target") "not a directory")
      (Files/createSymbolicLink
       link
       (.toPath (io/file *dir* "symlink-target"))
       (make-array FileAttribute 0))
      (is (thrown-with-msg? clojure.lang.ExceptionInfo
                            #"symbolic link"
                            (init/proposed-changes {:root *dir* :app "reader"}))))))

(deftest apply-writes-public-layout-and-keygen-runs-afterwards-test
  (let [seen (atom nil)]
    (with-redefs [cli/keygen!
                  (fn [config env]
                    (reset! seen
                            {:config config
                             :env env
                             :template? (.exists
                                         (io/file
                                          *dir*
                                          "secrets/secrets.edn.example"))
                             :bb? (.exists (io/file *dir* "bb.edn"))})
                    :key)]
      (is (= :applied
             (:status
              (init/init! {:root *dir*
                           :app "reader"
                           :layout :disposable
                           :team? true
                           :keygen? true
                           :apply? true
                           :tty? false})))))
    (testing "public scaffold bytes"
      (is (.exists (io/file *dir* "bb.edn")))
      (is (.exists (io/file *dir* "secrets/secrets.edn.example")))
      (is (= "{:example/api-key \"replace-me\"}\n"
             (slurp (io/file *dir* "secrets/secrets.edn.example"))))
      (is (.exists (io/file *dir* ".local/secrets/recipients.txt")))
      (is (= "/.local/secrets/\n"
             (slurp (io/file *dir* ".gitignore")))))
    (testing "key generation runs after scaffold writes"
      (is (and (:template? @seen) (:bb? @seen))
          "keygen follows successful scaffold writes")
      (is (= "dev" (:env @seen))))))
