(ns com.kirahowe.secrets.init-test
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.java.shell :as sh]
            [clojure.string :as str]
            [clojure.test :refer [are deftest is testing use-fixtures]]
            [com.kirahowe.secrets.cli :as cli]
            [com.kirahowe.secrets.init :as init])
  (:import [java.nio.file Files LinkOption]
           [java.nio.file.attribute FileAttribute PosixFilePermissions]))

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

(def ^:private no-link-options (make-array LinkOption 0))

(defn- running-as-root? []
  (= "root" (System/getProperty "user.name")))

(defn- real-path [file]
  (str (.toRealPath (.toPath (io/file (str file))) no-link-options)))

(defn- unix-mode [file]
  (get (Files/readAttributes (.toPath (io/file (str file))) "unix:mode" no-link-options)
       "mode"))

(defn- set-permissions! [file rwx]
  (Files/setPosixFilePermissions (.toPath (io/file (str file)))
                                 (PosixFilePermissions/fromString rwx)))

(def ^:private public-directory
  (into-array FileAttribute
              [(PosixFilePermissions/asFileAttribute
                (PosixFilePermissions/fromString "rwxr-xr-x"))]))

(defn- mkdirs!
  "Create `file` and its missing parents at an explicit 0755, so no test depends
  on the umask the suite happens to run under."
  [file]
  (let [f (io/file (str file))]
    (when-not (.isDirectory f)
      (mkdirs! (.getParentFile f))
      (Files/createDirectory (.toPath f) public-directory))
    f))

(defn- make-sticky! [file]
  ;; `PosixFilePermission` covers only the nine rwx bits, so the POSIX
  ;; permission API cannot express the sticky bit at all; chmod can.
  (let [{:keys [exit err]} (sh/sh "chmod" "+t" (str file))]
    (when-not (zero? exit)
      (throw (ex-info (str "chmod +t failed: " err) {:path (str file)})))))

(defn- symlink! [link target]
  (Files/createSymbolicLink (.toPath (io/file (str link)))
                            (.toPath (io/file (str target)))
                            (make-array FileAttribute 0)))

(defn- ancestry-refusal
  "Return the `:reason`/`:path` of the ancestry refusal for `root`, or nil."
  [root]
  (try
    (init/trusted-ancestry! (str root))
    nil
    (catch clojure.lang.ExceptionInfo e
      (select-keys (ex-data e) [:reason :path]))))

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
            :apply? true
            :show-contents? true}
           (init/parse-args ["--app" "reader"
                             "--env" "prod"
                             "--layout" "disposable"
                             "--team"
                             "--keygen"
                             "--apply"
                             "--show-contents"]))))
  (testing "unknown options"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo
                          #"Unknown option: --show-content"
                          (init/parse-args ["--app" "reader" "--show-content"]))
        "a near miss for the content opt-in is refused, never ignored"))
  (testing "required values"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo
                          #"required"
                          (init/parse-args [])))
    (are [option following]
         (thrown-with-msg? clojure.lang.ExceptionInfo
                           #"Missing value"
                           (init/parse-args [option following]))
      "--app" "--team"
      "--env" "--keygen"
      "--layout" "--apply"))
  (testing "positional arguments are rejected"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo
                          #"Unexpected argument: extra"
                          (init/parse-args ["--app" "reader" "extra"]))))
  (testing "standalone help aliases"
    (doseq [flag ["-h" "--help"]]
      (is (= {:env "dev" :layout :tracked :help? true}
             (init/parse-args [flag]))
          "help must not demand an app name")
      (let [out (with-out-str (init/-main flag))]
        (is (str/includes? out
                           "Usage: -m com.kirahowe.secrets.init --app NAME [options]"))
        (is (str/includes? out "Options:"))
        (is (str/includes? out "--apply"))
        (is (not (str/includes? out "<coordinate>"))
            "help describes initializer arguments without prescribing a launcher")))))

(deftest initializer-failures-print-help-guidance-test
  (let [err (java.io.StringWriter.)
        print-init-error! (ns-resolve 'com.kirahowe.secrets.init 'print-init-error!)]
    (binding [*err* err]
      (print-init-error! (ex-info "--app <name> is required" {})))
    (is (str/includes? (str err) "secrets init: --app <name> is required"))
    (is (str/includes? (str err) "Run with --help for usage and options."))))

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
    (let [result (atom nil)
          out (with-out-str
                (reset! result (init/init! {:root *dir* :app "reader" :tty? false})))]
      (is (= :preview (:status @result)))
      (is (not (.exists (io/file *dir* "bb.edn"))))
      (is (str/includes? out "Project path is trusted for safe writes."))
      (is (str/includes? out "No files changed. Rerun with --apply to apply this plan."))))
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

(defn- captured
  "Run `f`, returning everything it printed on both streams.

  A preview that moved a credential from stdout to stderr is not a fix, so
  every output assertion below sees both."
  [f]
  (let [err (java.io.StringWriter.)
        out (with-out-str (binding [*err* err] (f)))]
    {:out out :err (str err)}))

(defn- bb-edn-with! [entry]
  (spit (io/file *dir* "bb.edn") (str "{:paths [\"src\"]\n " entry "}\n")))

(defn- interactive-preview [entry]
  (bb-edn-with! entry)
  (:out (captured #(init/init! {:root *dir*
                                :app "reader"
                                :tty? true
                                :choice :cancel}))))

(defn- hidden-from-preview?
  "Does an interactive preview of `entry` hide `sentinel` while still reporting
  the change?"
  [entry sentinel]
  (let [out (interactive-preview entry)]
    (and (not (str/includes? out sentinel))
         (not (str/includes? out "\u001b"))
         (str/includes? out "bb.edn")
         (str/includes? out "@@"))))

(def ^:private long-token "kAT3xQ9pLm2ZbVn7RsW4YtE6uH1jG5dC")
(def ^:private age-identity
  (str "AGE-SECRET-KEY-1" "9QY7ZPTX4V2M6KLHW3RUJ8ND5SGAEF0C" "7XQ2VMTHKR"))
(def ^:private long-line-tail "TAIL-SENTINEL-PAST-THE-LIMIT")

(deftest apply-output-contains-no-file-bodies-test
  (bb-edn-with! (str ":db-password \"" long-token "\""))
  (let [{:keys [out err]} (captured #(init/init! {:root *dir*
                                                  :app "reader"
                                                  :apply? true
                                                  :tty? false}))
        bb (edn/read-string (slurp (io/file *dir* "bb.edn")))]
    (testing "neither stream carries a body of a file being replaced"
      (is (not (str/includes? out long-token)))
      (is (not (str/includes? err long-token))))
    (testing "every action is still named"
      (is (str/includes? out "bb.edn: merge into the existing file"))
      (is (str/includes? out "secrets/secrets.edn.example: create"))
      (is (str/includes? out "bb.edn: merged")))
    (testing "the merged file is still correct"
      (is (= long-token (:db-password bb)))
      (is (= ["src"] (:paths bb)))
      (is (contains? (:deps bb) 'io.github.kirahowe/secrets))
      (is (contains? (:tasks bb) 'secrets)))))

(deftest interactive-preview-redacts-and-escapes-test
  (testing "a planted sentinel never reaches an interactive preview verbatim"
    (are [entry sentinel] (hidden-from-preview? entry sentinel)
      (str ":build-id \"" long-token "\"") long-token
      (str ":identity \"" age-identity "\"") age-identity
      ":db-password \"hunter2-plaintext\"" "hunter2-plaintext"
      ":notes \"\u001b[2J\u001b[1;31mrepainted\"" "\u001b[2J"
      ":notes \"before\rafter\"" "\r"
      (str ":notes \"" (apply str (repeat 300 \x)) long-line-tail "\"")
      long-line-tail))
  (testing "a control sequence is rendered as text, never emitted"
    (let [out (interactive-preview ":notes \"\u001b[2Jrepainted\"")]
      (is (str/includes? out "\\x1b"))
      (is (str/includes? out "repainted")
          "escaping the sequence keeps the surrounding line readable")))
  (testing "a hidden value still says how much it hid"
    (is (str/includes? (interactive-preview (str ":build-id \"" long-token "\""))
                       (str "[redacted " (count long-token) " characters]"))))
  (testing "an over-long line is marked as truncated"
    (is (str/includes? (interactive-preview
                        (str ":notes \"" (apply str (repeat 300 \x)) "\""))
                       "more characters]"))))

(deftest full-contents-require-explicit-opt-in-test
  (let [entry (str ":db-password \"" long-token "\"")]
    (testing "the opt-in prints whole bodies, warning first"
      (bb-edn-with! entry)
      (let [{:keys [out]} (captured #(init/init! {:root *dir*
                                                  :app "reader"
                                                  :tty? true
                                                  :choice :cancel
                                                  :show-contents? true}))]
        (is (str/includes? out "--- a/bb.edn"))
        (is (str/includes? out "--- /dev/null"))
        (is (str/includes? out (str "- :db-password \"" long-token "\"}")))
        (is (str/includes? out "+{:example/api-key \"replace-me\"}"))
        (is (< (str/index-of out "WARNING") (str/index-of out "--- a/bb.edn"))
            "the warning precedes the first body line")))
    (testing "an interactive run without the flag prints no body"
      (is (not (str/includes? (interactive-preview entry) "--- a/bb.edn"))))
    (testing "--apply alone does not enable it"
      (bb-edn-with! entry)
      (let [{:keys [out]} (captured #(init/init! {:root *dir*
                                                  :app "reader"
                                                  :tty? true
                                                  :apply? true}))]
        (is (not (str/includes? out long-token))
            "an interactive apply gets the safe mode, not the interactive one")
        (is (not (str/includes? out "--- a/bb.edn")))))))

(deftest summaries-remain-auditable-test
  (testing "the tracked layout names every proposed path and action"
    (let [{:keys [out]} (captured #(init/init! {:root *dir*
                                                :app "reader"
                                                :tty? false}))]
      (is (str/includes? out "bb.edn: create"))
      (is (str/includes? out "secrets/secrets.edn.example: create"))
      (is (str/includes? out "2 files to write, 0 left as is."))))
  (testing "the disposable team layout names all four"
    (let [{:keys [out]} (captured #(init/init! {:root *dir*
                                                :app "reader"
                                                :layout :disposable
                                                :team? true
                                                :tty? false}))]
      (is (str/includes? out "bb.edn: create"))
      (is (str/includes? out ".gitignore: create"))
      (is (str/includes? out ".local/secrets/recipients.txt: create"))
      (is (str/includes? out "secrets/secrets.edn.example: create"))
      (is (str/includes? out "4 files to write, 0 left as is."))))
  (testing "a preserved file is reported rather than silently dropped"
    (let [template (io/file *dir* "secrets/secrets.edn.example")]
      (.mkdirs (.getParentFile template))
      (spit template "{:custom/value 42}\n")
      (let [{:keys [out]} (captured #(init/init! {:root *dir*
                                                  :app "reader"
                                                  :tty? false}))]
        (is (str/includes?
             out "secrets/secrets.edn.example: leave as is, existing file preserved"))
        (is (str/includes? out "1 file to write, 1 left as is."))))))

(deftest status-map-carries-no-file-bodies-test
  (bb-edn-with! (str ":db-password \"" long-token "\""))
  (let [applied (binding [*out* (java.io.StringWriter.)]
                  (init/init! {:root *dir*
                               :app "reader"
                               :apply? true
                               :tty? false}))]
    (is (not (str/includes? (pr-str applied) long-token))
        "a caller printing the status map is the same disclosure by another route")
    (is (= :applied (:status applied)))
    (is (true? (:trusted? (:trust applied))))
    (is (= [{:path "bb.edn" :action :merge}
            {:path "secrets/secrets.edn.example" :action :create}]
           (:actions applied)))))

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
      (spit template "not-an-edn-map")
      (is (thrown-with-msg? clojure.lang.ExceptionInfo
                            #"must contain an EDN map"
                            (init/proposed-changes {:root *dir* :app "reader"})))
      (let [sentinel "123SENTINELSECRET"
            _ (spit template sentinel)
            e (try
                (init/proposed-changes {:root *dir* :app "reader"})
                nil
                (catch Exception e e))
            rendered (pr-str [(ex-message e) (ex-data e) (ex-cause e)])]
        (is (some? e))
        (is (re-find #"not valid EDN" (ex-message e)))
        (is (= :edn-malformed (:reason (ex-data e))))
        (is (nil? (ex-cause e)))
        (is (not (str/includes? rendered sentinel))))))
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

;;;; Race Safety

(deftest trusted-ancestry-accepts-a-private-root-test
  (testing "a root under the system temp directory"
    (is (= (real-path *dir*) (str (init/trusted-ancestry! *dir*)))))
  (testing "a root under a sticky world-writable ancestor"
    ;; /tmp is mode 1777 on macOS and Linux alike, and on macOS it is also a
    ;; symlink to /private/tmp. A naive "nothing other-writable anywhere" rule
    ;; would refuse every root beneath it.
    (let [tmp (real-path "/tmp")
          mode (unix-mode tmp)
          root (Files/createTempDirectory (.toPath (io/file tmp))
                                          "secrets-init-sticky"
                                          (make-array FileAttribute 0))]
      (try
        (is (pos? (bit-and mode 022)) "premise: /tmp is writable by others")
        (is (pos? (bit-and mode 01000)) "premise: /tmp is sticky")
        (is (= (real-path root) (str (init/trusted-ancestry! (str root)))))
        (finally
          (delete-tree! root))))))

(deftest trusted-ancestry-refuses-an-untrusted-ancestor-test
  (if (running-as-root?)
    (is (running-as-root?)
        "skipped as root: root satisfies every ownership check by definition")
    (let [open (mkdirs! (io/file *dir* "open"))
          under-open (mkdirs! (io/file open "project"))
          private-project (mkdirs! (io/file *dir* "private" "project"))
          link (io/file open "link")]
      (set-permissions! open "rwxrwxrwx")
      (symlink! link private-project)
      (testing "an ancestor anyone may rename"
        (are [expected root] (= expected (ancestry-refusal root))
          {:reason :world-writable :path (str open)} under-open
          ;; This link resolves into a wholly private tree, so only the walk of
          ;; the path as written can see that anyone may repoint it.
          {:reason :world-writable :path (str open)} link))
      (testing "the same ancestor with the sticky bit set"
        (make-sticky! open)
        (are [root] (nil? (ancestry-refusal root))
          under-open
          link))
      (testing "group write"
        (let [shared (mkdirs! (io/file *dir* "shared"))
              under-shared (mkdirs! (io/file shared "project"))]
          (set-permissions! shared "rwxrwxr-x")
          ;; No portable API creates or chgrps to a group with a chosen name, so
          ;; both directions of this decision are simulated at the one read that
          ;; makes it. A fresh directory's real group happens to be user-private
          ;; on some hosts (e.g. GitHub's ubuntu runners, where a checkout's
          ;; owner and group are both `runner`) and not on others (macOS's
          ;; `staff`), so leaving this assertion to the real group would pass or
          ;; fail depending on the platform instead of the code under test.
          (with-redefs-fn {#'init/posix-group (constantly "secrets-shared-group")}
            (fn []
              (is (= {:reason :shared-group-writable :path (str shared)}
                     (ancestry-refusal under-shared))
                  "a group that holds more than the owner can rename the directory")))
          ;; The user-private group of Fedora, RHEL, and Debian is stood in for
          ;; the same way.
          (with-redefs-fn {#'init/posix-group (constantly (System/getProperty "user.name"))}
            (fn []
              (is (nil? (ancestry-refusal under-shared))
                  "a group holding nobody but the owner is not another principal"))))))))

(deftest directory-swap-between-plan-and-apply-changes-nothing-outside-test
  (let [root (mkdirs! (io/file *dir* "project"))
        outside (mkdirs! (io/file *dir* "outside"))
        sentinel (io/file outside "secrets.edn.example")
        swapped (io/file root "secrets")
        out (java.io.StringWriter.)]
    (spit sentinel "sentinel\n")
    (is (some #(= "secrets/secrets.edn.example" (:path %))
              (:changes (init/proposed-changes {:root (str root) :app "reader"})))
        "premise: the plan writes through the directory about to be swapped")
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo
         #"symbolic link"
         (binding [*out* out]
           (init/init! {:root (str root)
                        :app "reader"
                        :tty? true
                        ;; The plan is complete and every path in it validated by
                        ;; the time this runs, so the swap lands squarely between
                        ;; planning and applying without racing a timer.
                        :input (fn []
                                 (symlink! swapped outside)
                                 "a")}))))
    (is (= "sentinel\n" (slurp sentinel)))
    (is (= ["secrets.edn.example"]
           (mapv #(.getName ^java.io.File %) (.listFiles outside))))
    (is (not (.exists (io/file root "bb.edn")))
        "the refusal precedes every write, not only the redirected one")))

(deftest unsupported-filesystem-capability-fails-closed-test
  ;; Injecting at the probe is the deterministic way into this branch: no
  ;; filesystem here actually lacks the posix and unix attribute views.
  (let [out (java.io.StringWriter.)]
    (with-redefs [init/filesystem-capability
                  (constantly {:views #{"basic"}
                               :missing ["posix" "unix"]
                               :supported? false})]
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo
           #"cannot report its posix and unix file attributes"
           (binding [*out* out]
             (init/init! {:root *dir* :app "reader" :apply? true :tty? false}))))
      (is (str/includes? (str out) "--apply will be refused")))
    (is (not (.exists (io/file *dir* "bb.edn"))))))

(deftest staging-write-refuses-an-existing-entry-test
  ;; The staging name is random by design, so a fixed one is injected here to
  ;; plant an entry at it on purpose.
  (let [root (mkdirs! (io/file *dir* "project"))
        outside (mkdirs! (io/file *dir* "outside"))
        sentinel (io/file outside "planted")
        out (java.io.StringWriter.)]
    (spit sentinel "sentinel\n")
    (symlink! (io/file root ".secrets-init-fixed.tmp") sentinel)
    (with-redefs-fn
      {#'init/staging-path (fn [target]
                             (.resolve (.getParent target) ".secrets-init-fixed.tmp"))}
      (fn []
        (is (thrown-with-msg?
             clojure.lang.ExceptionInfo
             #"Initializer failed"
             (binding [*out* out]
               (init/init! {:root (str root)
                            :app "reader"
                            :apply? true
                            :tty? false}))))))
    (is (= "sentinel\n" (slurp sentinel))
        "CREATE_NEW refuses the planted entry instead of writing through the link")
    (is (not (.exists (io/file root "bb.edn"))))))

(deftest created-directories-satisfy-the-ancestry-rule-test
  ;; Directories are created with an explicit `rwxr-xr-x` the umask can only
  ;; narrow, never widen, so group and other write can never appear and the
  ;; verification that immediately follows creation cannot fail on the umask the
  ;; caller happened to have.
  (let [out (java.io.StringWriter.)]
    (binding [*out* out]
      (init/init! {:root *dir* :app "reader" :apply? true :tty? false}))
    (let [created (io/file *dir* "secrets")]
      (is (zero? (bit-and (unix-mode created) 022))
          "no umask can give a created directory group or other write")
      (is (nil? (ancestry-refusal created))
          "a directory the initializer created passes the rule it enforces"))))

(deftest preview-reports-whether-apply-would-be-refused-test
  (if (running-as-root?)
    (is (running-as-root?)
        "skipped as root: root satisfies every ownership check by definition")
    (let [open (mkdirs! (io/file *dir* "open"))
          project (mkdirs! (io/file open "project"))
          result (atom nil)]
      (set-permissions! open "rwxrwxrwx")
      (let [out (with-out-str
                  (reset! result (init/init! {:root (str project)
                                              :app "reader"
                                              :tty? false})))]
        (is (= :preview (:status @result)))
        (is (false? (:trusted? (:trust @result))))
        (is (= :world-writable (:reason (:trust @result))))
        (is (str/includes? out "--apply will be refused"))
        (is (not (str/includes? out "Rerun with --apply"))
            "an untrusted preview does not imply that applying this plan can succeed")
        (is (str/includes? out "secrets/secrets.edn.example: create")
            "the preview itself still runs")
        (is (not (.exists (io/file project "bb.edn"))))))))
