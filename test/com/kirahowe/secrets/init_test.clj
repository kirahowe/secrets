(ns com.kirahowe.secrets.init-test
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [are deftest is testing use-fixtures]]
            [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.cli :as cli]
            [com.kirahowe.secrets.init :as init])
  (:import [java.nio.file Files LinkOption]
           [java.nio.file.attribute FileAttribute PosixFilePermissions]))

;;;; Fixtures

(def ^:dynamic ^:private *dir* nil)

(defn- with-temp-dir [test-fn]
  (let [dir (str (Files/createTempDirectory "secrets-init-test" (make-array FileAttribute 0)))]
    (binding [*dir* dir]
      (try
        (test-fn)
        (finally
          (run! #(.delete ^java.io.File %) (reverse (file-seq (io/file dir)))))))))

(use-fixtures :each with-temp-dir)

(def ^:private default-dependency @@#'init/default-dependency)
(def ^:private coordinates
  (edn/read-string (slurp (io/resource "com/kirahowe/secrets/coordinate.edn"))))

(defn- file [path] (io/file *dir* path))

(defn- files
  "Every file under the test directory, as sorted relative paths."
  []
  (let [root (.toPath (io/file *dir*))]
    (sort (for [^java.io.File f (file-seq (io/file *dir*))
                :when (.isFile f)]
            (str (.relativize root (.toPath f)))))))

(defn- permissions [path]
  (PosixFilePermissions/toString
   (Files/getPosixFilePermissions (.toPath (file path)) (make-array LinkOption 0))))

(defn- run!!
  "Run the initializer in the test directory, returning its result under
  `:result` and what it printed under `:out`."
  [opts]
  (let [result (atom nil)
        out (with-out-str (reset! result (init/init! (merge {:root *dir* :app "reader"} opts))))]
    {:result @result :out out}))

(def ^:private reader-task (init/task-spec (init/proposed-config {:app "reader"})))

;;;; Options

(deftest parses-required-options-and-defaults-test
  (testing "default and explicit options"
    (is (= {:app "reader" :env "dev" :layout :tracked}
           (init/parse-args ["--app" "reader"])))
    (is (= {:app "reader" :env "prod" :layout :disposable
            :team? true :keygen? true :apply? true}
           (init/parse-args ["--app" "reader" "--env" "prod" "--layout" "disposable"
                             "--team" "--keygen" "--apply"]))))
  (testing "unknown options"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Unknown option: --aply"
                          (init/parse-args ["--app" "reader" "--aply"]))
        "a near miss for --apply is refused, never ignored"))
  (testing "required values"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"required" (init/parse-args [])))
    (are [option following]
         (thrown-with-msg? clojure.lang.ExceptionInfo #"Missing value"
                           (init/parse-args [option following]))
      "--app" "--team"
      "--env" "--keygen"
      "--layout" "--apply"))
  (testing "positional arguments are rejected"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Unexpected argument: extra"
                          (init/parse-args ["--app" "reader" "extra"]))))
  (testing "standalone help aliases"
    (doseq [flag ["-h" "--help"]]
      (is (= {:env "dev" :layout :tracked :help? true} (init/parse-args [flag]))
          "help must not demand an app name")
      (let [out (with-out-str (init/-main flag))]
        (is (str/includes? out "Usage: -m com.kirahowe.secrets.init --app NAME [options]"))
        (is (str/includes? out "--apply"))
        (is (str/includes? out "never modifies a file that already exists"))))))

(deftest names-must-be-plain-test
  (testing "the self dependency is keyed by the app name as is"
    (is (= {'my-app.v2/my-app.v2 {:local/root "."}} (init/self-dependency "my-app.v2"))))
  (testing "a name that would not read back as written is refused"
    (doseq [bad ["my app" "1app" "-app" "app/name" "app\"" "ap\u001b[31mp" ""]]
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"plain name"
                            (init/self-dependency bad)))
      ;; The option parser already takes a blank or dash-leading value itself.
      (when-not (or (empty? bad) (str/starts-with? bad "-"))
        (is (thrown-with-msg? clojure.lang.ExceptionInfo #"--app must be a plain name"
                              (init/parse-args ["--app" bad])))
        (is (thrown-with-msg? clojure.lang.ExceptionInfo #"--env must be a plain name"
                              (init/parse-args ["--app" "reader" "--env" bad]))))))
  (testing "the refusal does not echo the rejected value"
    (let [message (try (init/parse-args ["--app" "ap\u001b[31mp"])
                       (catch clojure.lang.ExceptionInfo e (ex-message e)))]
      (is (not (str/includes? message "\u001b"))))))

(deftest initializer-failures-print-help-guidance-test
  (let [err (java.io.StringWriter.)]
    (binding [*err* err]
      (#'init/print-init-error! (ex-info "--app <name> is required" {})))
    (is (str/includes? (str err) "secrets init: --app <name> is required"))
    (is (str/includes? (str err) "Run with --help for usage and options."))))

;;;; The proposed configuration

(deftest proposed-layouts-are-accepted-by-the-cli-test
  (doseq [layout [:tracked :disposable]
          team? [false true]]
    (let [opts {:root *dir* :app "reader" :layout layout :team? team? :keygen? true}
          {:keys [config key-file]} (init/plan opts)
          environment (get-in (cli/normalize-config config) [:environments :dev])]
      (is (= key-file (:key-file environment))
          "the identity the initializer generates is the one the task reads")
      (is (= team? (some? (:recipients-file environment))))
      (is (= (= layout :disposable) (str/starts-with? (:secrets-file environment) ".local/"))))))

;;;; Preview

(deftest preview-writes-nothing-test
  (let [{:keys [result out]} (run!! {:layout :disposable :team? true :keygen? true})]
    (is (= {:status :preview} result))
    (is (empty? (files)))
    (is (str/includes? out "Nothing is written without --apply."))
    (is (str/includes? out "Would create:"))
    (doseq [path ["bb.edn" ".gitignore" "secrets/secrets.edn.example"
                  ".local/secrets/recipients.txt" ".local/secrets/key.txt"]]
      (is (str/includes? out (str "\n  " path "\n")) path))
    (is (str/includes? out "Rerun with --apply"))))

(deftest preview-says-when-no-identity-is-generated-test
  (is (str/includes? (:out (run!! {}))
                     (str "Pass --keygen to generate one at "
                          (secrets/default-key-file "reader") ".")))
  (is (not (str/includes? (:out (run!! {:layout :disposable :keygen? true})) "Pass --keygen"))))

;;;; The printed coordinate

(deftest the-coordinate-is-the-running-library-test
  (let [[lib coordinate] (first default-dependency)
        text (str lib " " (binding [*print-namespace-maps* false] (pr-str coordinate)))
        note "is not a release tag"]
    (is (= (:git-lib coordinates) lib) "the tests run from a source checkout")
    (testing "a new bb.edn declares it"
      (let [{:keys [out]} (run!! {:apply? true})]
        (is (= default-dependency (:deps (edn/read-string (slurp (file "bb.edn"))))))
        (is (= (nil? (:git/tag coordinate)) (str/includes? out note))
            "an untagged commit is called out, a release tag is not")))
    (testing "an existing bb.edn gets it as a snippet"
      (spit (file "bb.edn") "{}\n")
      (is (str/includes? (:out (run!! {})) text)))
    (testing "a project that already declares it is told nothing about it"
      (spit (file "bb.edn") (pr-str {:deps {(:lib coordinates) {:mvn/version "0.0.1"}}}))
      (let [{:keys [out]} (run!! {})]
        (is (not (str/includes? out (str lib))))
        (is (not (str/includes? out note)))))))

;;;; Apply

(deftest apply-creates-exactly-the-planned-files-test
  (let [{:keys [result out]} (run!! {:layout :disposable :team? true :keygen? true :apply? true})
        planned ["bb.edn" ".gitignore" "secrets/secrets.edn.example"
                 ".local/secrets/recipients.txt" ".local/secrets/key.txt"]]
    (is (= {:status :applied :created planned} result))
    (is (= (sort planned) (files)))
    (testing "contents"
      (is (= {:deps default-dependency
              :tasks {'secrets (init/task-spec
                                (init/proposed-config
                                 {:app "reader" :layout :disposable :team? true}))}}
             (edn/read-string (slurp (file "bb.edn")))))
      (is (= "/.local/secrets/\n" (slurp (file ".gitignore"))))
      (is (= "{:example/api-key \"replace-me\"}\n" (slurp (file "secrets/secrets.edn.example"))))
      (is (= "# One age recipient per line.\n" (slurp (file ".local/secrets/recipients.txt"))))
      (is (str/includes? (slurp (file ".local/secrets/key.txt")) "AGE-SECRET-KEY-1")))
    (testing "permissions"
      (is (= "rw-------" (permissions ".local/secrets/key.txt")))
      (spit (file "ordinary") "")
      (doseq [path (butlast planned)]
        (is (= (permissions "ordinary") (permissions path)) path)))
    (testing "output"
      (is (str/includes? out "Created:"))
      (is (re-find #"Public key: age1\S+" out))
      (is (not (str/includes? out "AGE-SECRET-KEY"))))))

(deftest tracked-apply-creates-the-task-and-template-test
  (is (= {:status :applied :created ["bb.edn" "secrets/secrets.edn.example"]}
         (:result (run!! {:apply? true}))))
  (is (= ["bb.edn" "secrets/secrets.edn.example"] (files)))
  (is (= {:deps default-dependency :tasks {'secrets reader-task}}
         (edn/read-string (slurp (file "bb.edn")))))
  (testing "a second run finds nothing to do"
    (let [before (slurp (file "bb.edn"))
          {:keys [result out]} (run!! {:apply? true})]
      (is (= {:status :applied :created []} result))
      (is (str/includes? out "There is nothing to create and nothing to add."))
      (is (= before (slurp (file "bb.edn")))))))

;;;; Existing files

(def ^:private existing
  {"bb.edn" ";; mine\n{:tasks {lint {:task (shell \"lint\")}}}\n"
   "deps.edn" "{:paths [\"src\"] ; keep\n :deps {}}\n"
   ".gitignore" "target/\n"
   "secrets/secrets.edn.example" "{:mine \"placeholder\"}\n"
   ".local/secrets/recipients.txt" "# team\nage1example\n"})

(defn- write-existing! []
  (doseq [[path content] existing]
    (io/make-parents (file path))
    (spit (file path) content)))

(deftest existing-files-are-never-modified-test
  (write-existing!)
  (doseq [apply? [false true]]
    (let [{:keys [result out]} (run!! {:layout :disposable :team? true :apply? apply?})]
      (testing "every existing file keeps its bytes"
        (is (= (sort (keys existing)) (files)))
        (doseq [[path content] existing]
          (is (= content (slurp (file path))) path)))
      (when apply?
        (is (= {:status :applied :created []} result)))
      (testing "what each file lacks is printed with where it goes"
        (is (str/includes? out "The initializer does not edit existing files."))
        (is (str/includes? out (str "  deps.edn, under :deps:\n      "
                                    (ffirst default-dependency) " {")))
        (is (str/includes? out "  bb.edn, under :deps:\n      reader/reader {:local/root \".\"}"))
        (is (str/includes? out "  bb.edn, under :tasks:\n      secrets\n      {:doc "))
        (is (re-find #"  \.gitignore, as a new line[^\n]*:\n      /\.local/secrets/\n" out)))
      (testing "files that need nothing are listed as left alone"
        (is (str/includes? out (str "Already there, left as they are:\n"
                                    "  secrets/secrets.edn.example\n"
                                    "  .local/secrets/recipients.txt\n")))))))

(deftest only-missing-parts-are-printed-test
  (testing "a bb.edn that has the task and the dependency needs nothing"
    (spit (file "bb.edn") (pr-str {:deps default-dependency :tasks {'secrets reader-task}}))
    (spit (file ".gitignore") "  /.local/secrets/  \n")
    (let [{:keys [out]} (run!! {:layout :disposable})]
      (is (re-find #"Already there, left as they are:\n  bb.edn\n  .gitignore\n" out))
      (is (not (str/includes? out "Add these yourself")))))
  (testing "a bb.edn that declares the library keeps declaring it beside a deps.edn"
    (spit (file "deps.edn") "{}\n")
    (let [{:keys [out]} (run!! {})]
      (is (not (str/includes? out "deps.edn")))))
  (testing "a bb.edn with a self dependency under another name is not asked for one"
    (spit (file "bb.edn") "{:deps {acme/app {:local/root \".\"}}}\n")
    (let [{:keys [out]} (run!! {})]
      (is (str/includes? out "deps.edn, under :deps:"))
      (is (str/includes? out "bb.edn, under :tasks:"))
      (is (not (str/includes? out "bb.edn, under :deps:"))))))

(deftest a-file-that-does-not-read-as-a-map-gets-every-snippet-test
  (let [source "{:deps {password \"hunter2\"\n"]
    (spit (file "deps.edn") source)
    (let [{:keys [out]} (run!! {:apply? true})]
      (is (= source (slurp (file "deps.edn"))))
      (is (str/includes? out "deps.edn, under :deps:"))
      (is (not (str/includes? out "hunter2")) "nothing from the file is printed"))))

;;;; Files that appear after the plan

(deftest a-file-that-appears-after-the-plan-is-not-overwritten-test
  (testing "a public file"
    (let [proposal (init/plan {:root *dir* :app "reader"})]
      (io/make-parents (file "secrets/secrets.edn.example"))
      (spit (file "secrets/secrets.edn.example") "mine")
      (let [e (try (init/apply-plan! proposal) nil
                   (catch clojure.lang.ExceptionInfo e e))]
        (is (some? e))
        (is (str/includes? (ex-message e) "secrets/secrets.edn.example already exists"))
        (is (str/includes? (ex-message e) "Created before stopping: bb.edn."))
        (is (= {:path "secrets/secrets.edn.example" :created ["bb.edn"]} (ex-data e)))
        (is (= "mine" (slurp (file "secrets/secrets.edn.example")))))))
  (testing "a symbolic link is not written through"
    (let [proposal (init/plan {:root *dir* :app "reader" :team? true})
          outside (file "outside.txt")]
      (Files/createSymbolicLink (.toPath (file "secrets/recipients.txt")) (.toPath outside)
                                (make-array FileAttribute 0))
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"secrets/recipients.txt already exists"
                            (init/apply-plan! proposal)))
      (is (not (.exists outside)))))
  (testing "an identity"
    (let [proposal (init/plan {:root *dir* :app "reader" :layout :disposable :keygen? true})]
      (io/make-parents (file ".local/secrets/key.txt"))
      (spit (file ".local/secrets/key.txt") "my key")
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #".local/secrets/key.txt already exists"
                            (init/apply-plan! proposal)))
      (is (= "my key" (slurp (file ".local/secrets/key.txt")))))))

(deftest an-existing-identity-is-kept-test
  (io/make-parents (file ".local/secrets/key.txt"))
  (spit (file ".local/secrets/key.txt") "my key")
  (let [{:keys [out]} (run!! {:layout :disposable :keygen? true :apply? true})]
    (is (= "my key" (slurp (file ".local/secrets/key.txt"))))
    (is (re-find #"(?s)Already there, left as they are:.*\n  .local/secrets/key.txt\n" out))
    (is (not (str/includes? out "Public key:")))))
