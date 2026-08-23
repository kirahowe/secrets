(ns com.kirahowe.secrets.init-test
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [com.kirahowe.secrets.cli :as cli]
            [com.kirahowe.secrets.init :as init]))

(def ^:dynamic *dir* nil)

(defn- delete-tree! [f]
  (doseq [child (reverse (file-seq (io/file (str f))))] (.delete child)))

(use-fixtures :each
  (fn [f]
    (let [dir (str (java.nio.file.Files/createTempDirectory
                    "secrets-init-test"
                    (make-array java.nio.file.attribute.FileAttribute 0)))]
      (binding [*dir* dir]
        (try (f) (finally (delete-tree! dir)))))))

(deftest parses-required-options-and-defaults
  (is (= {:app "reader" :env "dev" :layout :tracked}
         (init/parse-args ["--app" "reader"])))
  (is (= {:app "reader" :env "prod" :layout :disposable :team? true :keygen? true :apply? true}
         (init/parse-args ["--app" "reader" "--env" "prod" "--layout" "disposable"
                           "--team" "--keygen" "--apply"])))
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #"required"
                        (init/parse-args [])))
  (doseq [[option following] [["--app" "--team"]
                            ["--env" "--keygen"]
                            ["--layout" "--apply"]]]
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"needs"
                          (init/parse-args [option following]))
        (str option " must not consume " following " as its value")))
  (is (= {:env "dev" :layout :tracked :help? true}
         (init/parse-args ["--help"]))
      "help must not demand an app name")
  (is (str/includes? (with-out-str (init/-main "--help")) "Usage:")
      "the standalone entry point also accepts --help without --app"))

(deftest layouts-are-safe-and-normalizable
  (let [tracked (init/proposed-config {:app "reader"})
        disposable (init/proposed-config {:app "reader" :layout :disposable :team? true})]
    (is (= "secrets/secrets.edn.age" (get-in tracked [:environments :dev :secrets-file])))
    (is (nil? (get-in tracked [:environments :dev :key-file]))
        "tracked stores keep the default private identity external")
    (is (= ".local/secrets/key.txt" (get-in disposable [:environments :dev :key-file])))
    (is (= ".local/secrets/recipients.txt" (get-in disposable [:environments :dev :recipients-file])))
    (is (= "secrets/secrets.edn.example" (get-in disposable [:environments :dev :template])))
    (is (map? (cli/normalize-config disposable)))))

(deftest merge-preserves-comments-and-unrelated-forms
  (let [source "; keep me\n{:paths [\"src\"]\n :deps {acme/lib {:mvn/version \"1\"}}\n :tasks {lint {:task (println :lint)}}}\n"
        result (init/merge-bb-edn source (init/proposed-config {:app "reader"}))]
    (is (re-find #"; keep me" (:content result)))
    (is (re-find #"acme/lib" (:content result)))
    (is (re-find #"lint" (:content result)))
    (is (re-find #"io.github.kirahowe/secrets" (:content result)))
    (is (re-find #"secrets" (:content result)))))

(deftest merge-reuses-known-dependency-and-rejects-task-conflict
  (let [config (init/proposed-config {:app "reader"})
        reused (init/merge-bb-edn "{:deps {com.kirahowe/secrets {:local/root \"../secrets\"}} :tasks {}}" config)]
    (is (= 'com.kirahowe/secrets (:dependency reused)))
    (is (not (:added-dependency? reused)))
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"conflicting"
                          (init/merge-bb-edn "{:deps {} :tasks {secrets {:task (println :other)}}}" config)))))

(deftest noninteractive-preview-and-manual-cancel-do-not-mutate
  (testing "non-TTY without --apply is strictly preview-only"
    (is (= :preview (:status (init/init! {:root *dir* :app "reader" :tty? false}))))
    (is (not (.exists (io/file *dir* "bb.edn")))))
  (testing "manual and cancel do not write or generate a key"
    (let [called (atom false)]
      (with-redefs [cli/keygen! (fn [& _] (reset! called true))]
        (is (= :manual (:status (init/init! {:root *dir* :app "reader" :tty? true :choice :manual :keygen? true}))))
        (is (= :cancelled (:status (init/init! {:root *dir* :app "reader" :tty? true :choice :cancel :keygen? true})))))
      (is (false? @called))
      (is (not (.exists (io/file *dir* "bb.edn")))))))

(deftest preview-shows-before-and-after-content
  (let [out (with-out-str
              (init/print-preview! {:changes [{:path "bb.edn" :old "{:paths [\"src\"]}\n"
                                                :content "{:paths [\"src\"] :deps {x/y {}}}\n"}
                                               {:path "secrets/secrets.edn.example" :old nil
                                                :content "{:example/api-key \"replace-me\"}\n"}]}))]
    (is (str/includes? out "--- a/bb.edn"))
    (is (str/includes? out "-{:paths [\"src\"]}"))
    (is (str/includes? out "+{:paths [\"src\"] :deps {x/y {}}}"))
    (is (str/includes? out "--- /dev/null"))
    (is (str/includes? out "+{:example/api-key \"replace-me\"}"))))

(deftest injected-choice-function-is-invoked
  (is (= :manual (:status (init/init! {:root *dir* :app "reader" :tty? true
                                        :input (fn [] "m")}))))
  (is (not (.exists (io/file *dir* "bb.edn")))))

(deftest manual-integration-is-copyable-pretty-edn
  (let [out (with-out-str
              (init/init! {:root *dir* :app "reader" :tty? true :choice :manual}))]
    (is (str/includes? out "io.github.kirahowe/secrets")
        "do not print a namespace-map shorthand coordinate")
    (is (str/includes? out "\n :tasks\n {secrets")
        "task configuration is formatted over readable lines")))

(deftest existing-public-artifacts-are-preserved-when-safe
  (let [template (io/file *dir* "secrets/secrets.edn.example")
        recipients (io/file *dir* "secrets/recipients.txt")]
    (.mkdirs (.getParentFile template))
    (spit template "{:custom/value 42}\n")
    (spit recipients "# Alice\nage1existing\n")
    (let [proposal (init/proposed-changes {:root *dir* :app "reader" :team? true})]
      (is (not-any? #(= "secrets/secrets.edn.example" (:path %)) (:changes proposal)))
      (is (not-any? #(= "secrets/recipients.txt" (:path %)) (:changes proposal))))
    (init/init! {:root *dir* :app "reader" :team? true :apply? true :tty? false})
    (is (= "{:custom/value 42}\n" (slurp template)))
    (is (= "# Alice\nage1existing\n" (slurp recipients)))))

(deftest invalid-existing-template-and-symlinked-ancestor-are-rejected
  (let [template (io/file *dir* "secrets/secrets.edn.example")]
    (.mkdirs (.getParentFile template))
    (spit template "not an edn map")
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"must contain an EDN map"
                          (init/proposed-changes {:root *dir* :app "reader"})))
    (spit template "{")
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"not valid EDN"
                          (init/proposed-changes {:root *dir* :app "reader"}))))
  (let [link (.toPath (io/file *dir* "secrets"))]
    (delete-tree! link)
    (spit (io/file *dir* "symlink-target") "not a directory")
    (java.nio.file.Files/createSymbolicLink link (.toPath (io/file *dir* "symlink-target"))
                                               (make-array java.nio.file.attribute.FileAttribute 0))
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"symbolic link"
                          (init/proposed-changes {:root *dir* :app "reader"})))))

(deftest apply-writes-public-layout-and-keygen-runs-afterwards
  (let [seen (atom nil)]
    (with-redefs [cli/keygen! (fn [config env]
                                (reset! seen {:config config :env env
                                              :template? (.exists (io/file *dir* "secrets/secrets.edn.example"))
                                              :bb? (.exists (io/file *dir* "bb.edn"))})
                                :key)]
      (is (= :applied (:status (init/init! {:root *dir* :app "reader" :layout :disposable
                                             :team? true :keygen? true :apply? true :tty? false})))))
    (is (.exists (io/file *dir* "bb.edn")))
    (is (.exists (io/file *dir* "secrets/secrets.edn.example")))
    (is (= "{:example/api-key \"replace-me\"}\n"
           (slurp (io/file *dir* "secrets/secrets.edn.example"))))
    (is (.exists (io/file *dir* ".local/secrets/recipients.txt")))
    (is (= "/.local/secrets/\n" (slurp (io/file *dir* ".gitignore"))))
    (is (and (:template? @seen) (:bb? @seen)) "keygen follows successful scaffold writes")
    (is (= "dev" (:env @seen)))))
