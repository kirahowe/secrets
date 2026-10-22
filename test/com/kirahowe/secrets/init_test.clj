(ns com.kirahowe.secrets.init-test
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [are deftest is testing use-fixtures]]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.cli :as cli]
            [com.kirahowe.secrets.init :as init]
            [com.kirahowe.secrets.keychain :as keychain]
            [com.kirahowe.secrets.store :as store]
            [com.kirahowe.secrets.test-env :as test-env])
  (:import [java.nio.file Files LinkOption]
           [java.nio.file.attribute FileAttribute PosixFilePermissions]))

;;;; Fixtures

(def ^:dynamic ^:private *dir* nil)
(def ^:dynamic ^:private *keychain* nil)

(defn- with-temp-dirs
  "Give each test an empty project directory."
  [test-fn]
  (let [dir (str (Files/createTempDirectory "secrets-init-test" (make-array FileAttribute 0)))]
    (binding [*dir* dir]
      (try
        (test-fn)
        (finally
          (run! #(.delete ^java.io.File %) (reverse (file-seq (io/file dir)))))))))

(defn- with-fake-keychain
  "Give each test an empty fake Keychain, kept in `*keychain*` (an atom of app
  name to key) so a test can see what the initializer stored. Nothing reaches
  the real login Keychain. A key written to a file instead would be a
  regression, so `age/keygen!`, which writes one, fails the test."
  [test-fn]
  (let [items (atom {})]
    (binding [*keychain* items]
      (with-redefs-fn (merge (test-env/keychain-redefs items)
                             {#'age/keygen! (fn [path]
                                              (throw (AssertionError.
                                                      (str "a key file was written: " path))))})
        test-fn))))

(use-fixtures :each with-temp-dirs with-fake-keychain)

(def ^:private default-dependency @@#'init/default-dependency)
(def ^:private coordinates
  (edn/read-string (slurp (io/resource "com/kirahowe/secrets/coordinate.edn"))))

(def ^:private template "secrets/secrets.edn.example")
(def ^:private key-item
  "How the initializer names the reader app's Keychain item in its plan."
  "macOS Keychain item com.kirahowe.secrets, account reader")
(def ^:private reader-task (#'init/task-spec (#'init/proposed-config {:app "reader"})))

(defn- file [path] (io/file *dir* path))

(defn- files
  "Every file under the test project, as sorted relative paths."
  []
  (let [root (.toPath (io/file *dir*))]
    (sort (for [^java.io.File f (file-seq (io/file *dir*))
                :when (.isFile f)]
            (str (.relativize root (.toPath f)))))))

(defn- permissions [f]
  (PosixFilePermissions/toString
   (Files/getPosixFilePermissions (.toPath (io/file f)) (make-array LinkOption 0))))

(defn- run!!
  "Run the initializer in the test project, returning its result under
  `:result` and what it printed under `:out`."
  [opts]
  (let [result (atom nil)
        out (with-out-str (reset! result (init/init! (merge {:root *dir* :app "reader"} opts))))]
    {:result @result :out out}))

;;;; Options

(deftest parses-required-options-and-defaults-test
  (testing "default and explicit options"
    (is (= {:app "reader" :env "dev"} (#'init/parse-args ["--app" "reader"])))
    (is (= {:app "reader" :env "prod" :keygen? true :apply? true}
           (#'init/parse-args ["--app" "reader" "--env" "prod" "--keygen" "--apply"]))))
  (testing "unknown options"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"^Unknown option or argument\.$"
                          (#'init/parse-args ["--app" "reader" "--aply"]))
        "a near miss for --apply is refused, never ignored, and not repeated")
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"^Unknown option or argument\.$"
                          (#'init/parse-args ["--app=reader"]))))
  (testing "required values"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"required" (#'init/parse-args [])))
    (are [option following]
         (thrown-with-msg? clojure.lang.ExceptionInfo #"Missing value"
                           (#'init/parse-args (remove nil? [option following])))
      "--app" "--keygen"
      "--env" "--apply"
      "--app" nil))
  (testing "positional arguments are rejected"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"^Unknown option or argument\.$"
                          (#'init/parse-args ["--app" "reader" "extra"]))))
  (testing "standalone help aliases"
    (doseq [flag ["-h" "--help"]]
      (is (= {:env "dev" :help? true} (#'init/parse-args [flag]))
          "help must not demand an app name")
      (let [out (with-redefs-fn {#'store/exit! (fn [_])}
                  #(with-out-str (init/-main flag)))]
        (is (str/includes? out "Usage: -m com.kirahowe.secrets.init --app NAME [options]"))
        (doseq [line ["  --app NAME    Application name (required)"
                      "  --env NAME    Environment name (default: dev)"
                      "  --keygen      Also generate an age identity in the macOS Keychain"
                      "  --apply       Create the files instead of previewing"
                      "  -h, --help    Show this help"]]
          (is (str/includes? out (str line "\n"))))
        (is (str/includes? out "never modifies a file that already exists"))))))

(deftest names-must-be-plain-test
  (doseq [bad ["my app" "1app" "-app" "app/name" "app\"" "ap\u001b[31mp" ""]]
    (testing "a name that would not read back as written is refused before anything is written"
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"--app must be a plain name"
                            (run!! {:app bad :apply? true})))
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"--env must be a plain name"
                            (run!! {:env bad :apply? true})))
      (is (empty? (files)))))
  (testing "the refusal does not echo the rejected value"
    (let [message (try (#'init/proposed-config {:app "ap\u001b[31mp"})
                       (catch clojure.lang.ExceptionInfo e (ex-message e)))]
      (is (not (str/includes? message "\u001b"))))))

(deftest initializer-failures-print-help-guidance-test
  (let [err (java.io.StringWriter.)]
    (binding [*err* err]
      (#'init/print-init-error! (ex-info "--app <name> is required" {})))
    (is (str/includes? (str err) "secrets init: --app <name> is required"))
    (is (str/includes? (str err) "Run with --help for usage and options."))))

;;;; The proposed configuration

(deftest the-cli-derives-the-paths-the-initializer-uses-test
  (let [{:keys [config files] :as proposal} (#'init/plan {:root *dir* :app "reader" :keygen? true})
        environment (get-in (cli/normalize-config config) [:environments :dev])]
    (is (= {:app "reader"
            :default-environment :dev
            :environments {:dev {:secrets-file "secrets/secrets.edn.age"}}}
           config))
    (is (= template (:template environment))
        "the template the initializer creates is the one the CLI reads")
    (is (= "secrets/secrets.edn.manifest" (:manifest environment)))
    (is (not (contains? proposal :key-file)) "there is no key file to plan")
    (is (= {:path key-item :action :create :keychain-app "reader"} (last files)))
    (is (not (contains? environment :key-file)))
    (is (= "the macOS Keychain (com.kirahowe.secrets, account reader)"
           (store/key-location environment))
        "the identity the initializer generates is the one the CLI reads")))

;;;; Preview

(deftest preview-writes-nothing-test
  (let [{:keys [result out]} (run!! {:keygen? true})]
    (is (= {:status :preview} result))
    (is (empty? (files)))
    (is (empty? @*keychain*) "a preview stores no key")
    (is (str/includes? out "Nothing is written without --apply."))
    (is (str/includes? out "Would create:"))
    (doseq [path ["bb.edn" template key-item]]
      (is (str/includes? out (str "\n  " path "\n")) path))
    (is (str/includes? out (str key-item "\n      a new age identity, never written to disk\n")))
    (is (str/includes? out "Rerun with --apply"))))

(deftest preview-says-when-no-identity-is-generated-test
  (is (str/includes? (:out (run!! {}))
                     "Pass --keygen to store one in the macOS Keychain."))
  (is (not (str/includes? (:out (run!! {:keygen? true})) "Pass --keygen")))
  (testing "without the Keychain it points at :key-command and :key-file instead"
    (with-redefs [keychain/available? (constantly false)]
      (let [{:keys [out]} (run!! {})]
        (is (str/includes? out (str "No age identity is generated. Without the macOS Keychain,"
                                    " add :key-command")))
        (is (not (str/includes? out "--keygen")))))))

(deftest keygen-without-the-keychain-is-refused-test
  (with-redefs [keychain/available? (constantly false)]
    (doseq [apply? [false true]]
      (testing (if apply? "apply" "preview")
        (let [e (test-env/thrown #(run!! {:keygen? true :apply? apply?}))]
          (is (= {:reason :usage} (ex-data e)))
          (is (str/includes? (ex-message e) "--keygen stores the key in the macOS Keychain"))
          (is (str/includes? (ex-message e) ":key-command"))
          (is (empty? (files)) "nothing is written, the project files included")
          (is (empty? @*keychain*)))))))

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
  (let [{:keys [result out]} (run!! {:keygen? true :apply? true})]
    (is (= {:status :applied :created ["bb.edn" template key-item]} result))
    (is (= ["bb.edn" template] (files)) "the identity is not a file in the project")
    (testing "contents"
      (is (= {:deps default-dependency :tasks {'secrets reader-task}}
             (edn/read-string (slurp (file "bb.edn")))))
      (is (= "{:example/api-key \"replace-me\"}\n" (slurp (file template))))
      (is (= ["reader"] (keys @*keychain*)))
      (is (str/starts-with? (str (get @*keychain* "reader")) "AGE-SECRET-KEY-1")))
    (testing "permissions"
      (spit (file "ordinary") "")
      (doseq [path ["bb.edn" template]]
        (is (= (permissions (file "ordinary")) (permissions (file path))) path)))
    (testing "output"
      (is (str/includes? out "Created:"))
      (is (str/includes? out (str "Public key: "
                                  (age/public-key {:identity-contents (get @*keychain* "reader")})
                                  "\n"))
          "the public key printed is the stored key's")
      (is (str/includes? out (str "security find-generic-password"
                                  " -s com.kirahowe.secrets -a 'reader' -w"))
          "it says how to read the key back for a backup")
      (is (not (str/includes? out "AGE-SECRET-KEY"))))))

(deftest a-second-run-finds-nothing-to-do-test
  (run!! {:apply? true})
  (let [before (slurp (file "bb.edn"))
        {:keys [result out]} (run!! {:apply? true})]
    (is (= {:status :applied :created []} result))
    (is (str/includes? out "There is nothing to create and nothing to add."))
    (is (= before (slurp (file "bb.edn"))))))

;;;; Existing files

(def ^:private existing
  {"bb.edn" ";; mine\n{:tasks {lint {:task (shell \"lint\")}}}\n"
   "deps.edn" "{:paths [\"src\"] ; keep\n :deps {}}\n"
   "secrets/secrets.edn.example" "{:mine \"placeholder\"}\n"})

(deftest existing-files-are-never-modified-test
  (doseq [[path content] existing]
    (io/make-parents (file path))
    (spit (file path) content))
  (doseq [apply? [false true]]
    (let [{:keys [result out]} (run!! {:apply? apply?})]
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
        (is (str/includes? out "  bb.edn, under :tasks:\n      secrets\n      {:doc ")))
      (testing "a file that needs nothing is listed as left alone"
        (is (str/includes? out (str "Already there, left as they are:\n  " template "\n")))))))

(deftest only-missing-parts-are-printed-test
  (testing "a bb.edn that has the task and the dependency needs nothing"
    (spit (file "bb.edn") (pr-str {:deps default-dependency :tasks {'secrets reader-task}}))
    (let [{:keys [out]} (run!! {})]
      (is (str/includes? out "Already there, left as they are:\n  bb.edn\n"))
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
    (let [proposal (#'init/plan {:root *dir* :app "reader"})]
      (io/make-parents (file template))
      (spit (file template) "mine")
      (let [e (try (#'init/apply-plan! proposal) nil
                   (catch clojure.lang.ExceptionInfo e e))]
        (is (some? e))
        (is (str/includes? (ex-message e) (str template " already exists")))
        (is (str/includes? (ex-message e) "Created before stopping: bb.edn."))
        (is (= {:reason :file-exists :path template :created ["bb.edn"]} (ex-data e)))
        (is (= "mine" (slurp (file template)))))))
  (testing "a symbolic link is not written through"
    (.delete (file "bb.edn"))
    (let [proposal (#'init/plan {:root *dir* :app "reader"})
          outside (file "outside.edn")]
      (Files/createSymbolicLink (.toPath (file "bb.edn")) (.toPath outside)
                                (make-array FileAttribute 0))
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"bb.edn already exists"
                            (#'init/apply-plan! proposal)))
      (is (not (.exists outside)))))
  (testing "an identity"
    (let [proposal (#'init/plan {:root *dir* :app "reader" :keygen? true})]
      (swap! *keychain* assoc "reader" "my key")
      (is (thrown-with-msg? clojure.lang.ExceptionInfo
                            #"Keychain item com\.kirahowe\.secrets, account reader already exists"
                            (#'init/apply-plan! proposal)))
      (is (= {"reader" "my key"} @*keychain*)))))

;;;; Failures name a path and what was created

(deftest a-failure-part-way-names-the-path-and-the-files-created-test
  (testing "a directory that cannot be written to"
    (let [proposal (#'init/plan {:root *dir* :app "reader"})
          read-only (PosixFilePermissions/fromString "r-xr-xr-x")
          writable (PosixFilePermissions/fromString "rwxr-xr-x")]
      (Files/setPosixFilePermissions (.toPath (io/file *dir*)) read-only)
      (try
        (let [e (try (#'init/apply-plan! proposal) nil (catch Exception e e))
              line (with-out-str
                     (binding [*err* *out*] (#'init/print-init-error! e)))]
          (is (instance? clojure.lang.ExceptionInfo e))
          (is (= {:path "bb.edn" :created []} (ex-data e)))
          (is (str/includes? line "secrets init: java.nio.file.AccessDeniedException: "))
          (is (str/includes? line (str (file "bb.edn"))) "the line names the path")
          (is (not (str/includes? line "Unexpected failure"))))
        (finally
          (Files/setPosixFilePermissions (.toPath (io/file *dir*)) writable)))))
  (testing "a key that cannot be generated after the project files were written"
    (let [proposal (#'init/plan {:root *dir* :app "reader" :keygen? true})
          e (with-redefs [age/generate (fn []
                                         (throw (ex-info "age-keygen failed"
                                                         {:reason :keygen-failed})))]
              (try (#'init/apply-plan! proposal) nil (catch Exception e e)))]
      (is (= (str "age-keygen failed\nCreated before stopping: bb.edn, " template ".")
             (ex-message e)))
      (is (= {:reason :keygen-failed :path key-item :created ["bb.edn" template]}
             (ex-data e)))
      (is (= ["bb.edn" template] (files)) "what it names is what is there")
      (is (empty? @*keychain*)))))

(deftest an-existing-identity-is-kept-test
  (swap! *keychain* assoc "reader" "my key")
  (let [{:keys [out]} (run!! {:keygen? true :apply? true})]
    (is (= {"reader" "my key"} @*keychain*))
    (is (str/includes? out (str "\n  " key-item "\n")))
    (is (str/includes? out "Already there, left as they are:"))
    (is (not (str/includes? out "Public key:")))))
