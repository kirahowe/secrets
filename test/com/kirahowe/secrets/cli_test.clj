(ns com.kirahowe.secrets.cli-test
  "Tests for the non-interactive CLI paths, exercising the real `age` binary
  like the core suite. Nothing here opens $EDITOR or prompts; command fns are
  called directly (they are REPL-safe — they return data and throw ex-info
  instead of exiting), plus `run!` for the dispatch/arg-order cases that don't
  exit on success.

  Tests that pin a specific key skip themselves when an SECRETS_AGE_IDENTITY* env var
  is set, because the env legitimately overrides :key-file."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.cli :as cli]
            [com.kirahowe.secrets.manifest :as manifest]))

(def ^:dynamic *dir* nil)
(def ^:dynamic *key* nil)

(defn with-tmp-key [f]
  (let [dir (str (java.nio.file.Files/createTempDirectory
                  "kira-secrets-cli-test"
                  (into-array java.nio.file.attribute.FileAttribute [])))
        key (str dir "/key.txt")]
    (age/keygen! key)
    (binding [*dir* dir *key* key]
      (try
        (f)
        (finally
          (doseq [p (reverse (file-seq (io/file dir)))] (.delete p)))))))

(use-fixtures :each with-tmp-key)

(def ^:private age-env-set?
  "SECRETS_AGE_IDENTITY* overrides :key-file in :identity-file resolution, so tests
  that must decrypt with the fixture's key can't run under it."
  (boolean (some #(System/getenv %) ["SECRETS_AGE_IDENTITY_FILE" "SECRETS_AGE_IDENTITY" "SECRETS_AGE_IDENTITY_B64"])))

(defn- test-config
  "A single-env config rooted in the fixture's temp dir, key pinned to *key*."
  ([] (test-config {}))
  ([env-overrides]
   {:app "cli-test"
    :default-environment :dev
    :environments {:dev (merge {:secrets-file (str *dir* "/secrets.edn.age")
                                :key-file     *key*}
                               env-overrides)}}))

(defn- encrypt-edn!
  "Encrypt `m` to the config's secrets file out-of-band (no manifest written),
  as a teammate bypassing the CLI would."
  [m]
  (let [plain (str *dir* "/plain.edn")
        enc   (str *dir* "/secrets.edn.age")]
    (spit plain (pr-str m))
    (age/encrypt-file! *key* plain enc)
    (.delete (io/file plain))
    enc))

(defn- verify
  "Run verify! with its chatter (stdout and stderr — drift goes to *err*)
  captured; return its result map."
  [config env-arg]
  (let [res (atom nil)]
    (binding [*err* (java.io.StringWriter.)]
      (with-out-str (reset! res (cli/verify! config env-arg))))
    @res))

(defn- file-bytes [path]
  (vec (java.nio.file.Files/readAllBytes (.toPath (io/file path)))))

(defn- cli-private [sym]
  (ns-resolve 'com.kirahowe.secrets.cli sym))

;; ---------- normalize-config ----------

(deftest normalize-config-defaults
  (let [cfg (cli/normalize-config
             {:app "myapp"
              :environments {:prod {:secrets-file "env/secrets.edn.age"}}})
        env (get-in cfg [:environments :prod])]
    (is (= "env/secrets.edn.example" (:template env)))
    (is (= "env/secrets.edn.manifest" (:manifest env)))
    (is (= (str (System/getProperty "user.home") "/.config/myapp/key.txt")
           (:key-file env)))
    (is (= :prod (:name env)))
    (is (= "myapp" (:app env)))
    (if age-env-set?
      (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
      (is (= (:key-file env) (:identity-file env))
          ":identity-file falls back to :key-file without SECRETS_AGE_IDENTITY*"))))

(deftest normalize-config-explicit-values-respected
  (let [cfg (cli/normalize-config
             {:app "myapp"
              :environments {:dev {:secrets-file "s.edn.age"
                                   :template     "tpl.edn"
                                   :manifest     false}}})
        env (get-in cfg [:environments :dev])]
    (is (= "tpl.edn" (:template env)))
    (is (false? (:manifest env)) ":manifest false survives normalization")))

(deftest normalize-config-validation
  (testing "no :environments"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #":environments"
                          (cli/normalize-config {:app "x"}))))
  (testing "missing :app — no default, so unrelated projects can't share a key path"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #":app"
                          (cli/normalize-config
                           {:environments {:dev {:secrets-file "s.edn.age"}}}))))
  (testing "missing :secrets-file"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #":secrets-file"
                          (cli/normalize-config {:app "x" :environments {:dev {}}}))))
  (testing "non-.age name would make derived template/manifest overwrite the ciphertext"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"\.age"
                          (cli/normalize-config
                           {:app "x" :environments {:dev {:secrets-file "secrets.enc"}}}))))
  (testing "non-.age accepted when :template and :manifest are both explicit"
    (let [env (-> {:app "x"
                   :environments {:dev {:secrets-file "secrets.enc"
                                        :template     "secrets.example"
                                        :manifest     false}}}
                  cli/normalize-config
                  (get-in [:environments :dev]))]
      (is (= "secrets.enc" (:secrets-file env)))))
  (testing "explicit ciphertext and manifest paths cannot be identical"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"colliding artifact paths"
                          (cli/normalize-config
                           {:app "x"
                            :environments {:dev {:secrets-file "s.age"
                                                 :manifest "s.age"}}}))))
  (testing "every pair of artifact paths is compared canonically"
    (let [fields [:secrets-file :manifest :template :key-file :recipients-file]
          env    {:secrets-file "ciphertext.age"
                  :manifest "manifest.edn"
                  :template "template.edn"
                  :key-file "key.txt"
                  :recipients-file "recipients.txt"}]
      (doseq [left-index (range (count fields))
              right-index (range (inc left-index) (count fields))]
        (let [left  (nth fields left-index)
              right (nth fields right-index)
              env   (assoc env right (str "./" (get env left)))]
          (is (thrown-with-msg? clojure.lang.ExceptionInfo #"colliding artifact paths"
                                (cli/normalize-config
                                 {:app "x" :environments {:dev env}}))
              (str left " and " right " alias the same canonical path")))))))

(deftest unknown-environment-throws
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Unknown environment"
                        (cli/recipients! (cli/normalize-config (test-config)) "nope"))))

;; ---------- validated, transactional saves ----------

(deftest new-rejects-invalid-edn-before-writing
  (let [config   (cli/normalize-config (test-config))
        encrypted (str *dir* "/secrets.edn.age")
        manifest  (str *dir* "/secrets.edn.manifest")]
    (doseq [invalid ["{:unfinished" "{:one 1} {:two 2}" ""]]
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo #"not valid EDN"
           (with-out-str
             (with-redefs-fn {(cli-private 'run-editor!) #(spit % invalid)}
               #(cli/new! config "dev")))))
      (is (not (.exists (io/file encrypted)))
          "invalid editor contents never create ciphertext")
      (is (not (.exists (io/file manifest)))
          "invalid editor contents never create a manifest"))))

(deftest edit-rejects-invalid-edn-without-replacing-valid-files
  (if age-env-set?
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config        (cli/normalize-config (test-config))
          encrypted     (str *dir* "/secrets.edn.age")
          manifest-path (str *dir* "/secrets.edn.manifest")]
      (encrypt-edn! {:valid true})
      (with-out-str (cli/reencrypt! config "dev"))
      (let [ciphertext-before (file-bytes encrypted)
            manifest-before   (slurp manifest-path)]
        (is (thrown-with-msg?
             clojure.lang.ExceptionInfo #"not valid EDN"
             (with-out-str
               (with-redefs-fn {(cli-private 'run-editor!) #(spit % "{:broken")}
                 #(cli/edit! config "dev")))))
        (is (= ciphertext-before (file-bytes encrypted)))
        (is (= manifest-before (slurp manifest-path)))))))

(deftest edit-stages-all-output-before-replacing-either-file
  (if age-env-set?
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config        (cli/normalize-config (test-config))
          encrypted     (str *dir* "/secrets.edn.age")
          manifest-path (str *dir* "/secrets.edn.manifest")]
      (encrypt-edn! {:version :old})
      (with-out-str (cli/reencrypt! config "dev"))
      (let [ciphertext-before (file-bytes encrypted)
            manifest-before   (slurp manifest-path)]
        (is (thrown-with-msg?
             clojure.lang.ExceptionInfo #"manifest rendering failed"
             (with-out-str
               (with-redefs-fn {(cli-private 'run-editor!) #(spit % "{:version :new}")
                                 #'manifest/render (fn [& _]
                                                     (throw (ex-info "manifest rendering failed" {})))}
                 #(cli/edit! config "dev")))))
        (is (= ciphertext-before (file-bytes encrypted)))
        (is (= manifest-before (slurp manifest-path)))))))

(deftest edit-rolls-back-an-interrupted-pair-commit
  (if age-env-set?
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config        (cli/normalize-config (test-config))
          encrypted     (str *dir* "/secrets.edn.age")
          manifest-path (str *dir* "/secrets.edn.manifest")]
      (encrypt-edn! {:version :old})
      (with-out-str (cli/reencrypt! config "dev"))
      (let [ciphertext-before (file-bytes encrypted)
            manifest-before   (slurp manifest-path)
            atomic-var        (cli-private 'atomic-replace!)
            atomic-replace!   @atomic-var
            moves             (atom 0)]
        (is (thrown-with-msg?
             clojure.lang.ExceptionInfo #"Could not commit"
             (with-out-str
               (with-redefs-fn {(cli-private 'run-editor!) #(spit % "{:version :new}")
                                 atomic-var
                                 (fn [source target]
                                   (if (= 2 (swap! moves inc))
                                     (throw (ex-info "simulated manifest move failure" {}))
                                     (atomic-replace! source target)))}
                 #(cli/edit! config "dev")))))
        (is (= 3 @moves) "ciphertext commit, failed manifest commit, ciphertext rollback")
        (is (= ciphertext-before (file-bytes encrypted)))
        (is (= manifest-before (slurp manifest-path)))))))

;; ---------- reencrypt / verify ----------

(deftest reencrypt-writes-manifest-and-verify-passes
  (if age-env-set?
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))]
      (encrypt-edn! {:database/url "jdbc:x" :auth/admins #{"a@b.com"}})
      (with-out-str (cli/reencrypt! config "dev"))
      (let [m (edn/read-string (slurp (str *dir* "/secrets.edn.manifest")))]
        (is (= 1 (:version m)))
        (is (string? (:ciphertext-sha m)) "manifest records the ciphertext hash")
        (is (contains? (:keys m) [:database/url]))
        (is (contains? (get-in m [:keys [:database/url]]) :vhash)
            "single-key mode keys the value hashes"))
      (let [{:keys [results exit]} (verify config "dev")]
        (is (= 0 exit))
        (is (= :ok (:dev results)))))))

(deftest verify-detects-drift
  (if age-env-set?
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))]
      (testing "shape change out-of-band"
        (encrypt-edn! {:a 1})
        (with-out-str (cli/reencrypt! config "dev"))
        (encrypt-edn! {:a 1 :b 2})
        (let [{:keys [results exit]} (verify config "dev")]
          (is (= 1 exit))
          (is (= :drift (:dev results)))))
      (testing "same content re-encrypted out-of-band still drifts (sha check)"
        (encrypt-edn! {:a 1})
        (with-out-str (cli/reencrypt! config "dev"))
        (encrypt-edn! {:a 1})
        (let [{:keys [results exit]} (verify config "dev")]
          (is (= 1 exit))
          (is (= :drift (:dev results))
              "entries match but :ciphertext-sha does not"))))))

(deftest verify-keyless-freshness
  (if age-env-set?
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config  (cli/normalize-config (test-config))
          keyless (cli/normalize-config
                   (test-config {:key-file (str *dir* "/no-such-key.txt")}))]
      (encrypt-edn! {:a 1})
      (with-out-str (cli/reencrypt! config "dev"))
      (testing "fresh manifest → freshness verified without any key"
        (let [{:keys [results exit]} (verify keyless "dev")]
          (is (= 0 exit))
          (is (= :ok-keyless (:dev results)))))
      (testing "tampered ciphertext → drift, still without any key"
        (encrypt-edn! {:a 2})
        (let [{:keys [results exit]} (verify keyless "dev")]
          (is (= 1 exit))
          (is (= :drift (:dev results))))))))

(deftest verify-version-gate
  (if age-env-set?
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))]
      (encrypt-edn! {:a 1})
      (spit (str *dir* "/secrets.edn.manifest")
            "{:version 2 :app \"cli-test\" :keys {}}")
      (let [{:keys [results exit]} (verify config "dev")]
        (is (= 1 exit))
        (is (= :drift (:dev results)) "an unsupported :version is reported, not misdiffed")))))

(deftest verify-missing-is-exit-2-and-repl-safe
  (let [config (cli/normalize-config (test-config))
        {:keys [results exit]} (verify config nil)]
    (is (= 2 exit) "no secrets file yet is missing (2), not drift (1)")
    (is (= :missing (:dev results)))
    (is true "and verify! returned instead of killing the process")))

;; ---------- encrypt / decrypt (env-first arg order) ----------

(deftest encrypt-decrypt-arg-order-and-binary-safety
  (if age-env-set?
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config  (test-config)
          f       (str *dir* "/note.txt")
          g       (str *dir* "/other.txt")
          payload "hello from the cli"]
      (spit f payload)
      (spit g payload)
      (testing "run! dispatches encrypt as [env] <file>"
        (with-out-str (cli/run! config ["encrypt" "dev" f]))
        (is (.exists (io/file (str f ".age")))))
      (testing "run! dispatches encrypt as <file> alone via the default env"
        (with-out-str (cli/run! config ["encrypt" g]))
        (is (.exists (io/file (str g ".age")))))
      (testing "decrypt streams the exact bytes to System/out"
        (let [baos (java.io.ByteArrayOutputStream.)
              orig System/out]
          (System/setOut (java.io.PrintStream. baos))
          (try
            (with-out-str (cli/run! config ["decrypt" "dev" (str f ".age")]))
            (finally (System/setOut orig)))
          (is (= payload (String. (.toByteArray baos) "UTF-8"))))))))

;; ---------- regressions ----------

(deftest keygen-overwrites-a-confirmed-existing-key
  (testing "age-keygen refuses an existing -o file, so keygen! stages and moves"
    (let [path (str *dir* "/regen.txt")
          pub1 (age/keygen! path)
          pub2 (age/keygen! path)]
      (is (some? pub1))
      (is (some? pub2))
      (is (not= pub1 pub2) "the second call really did replace the key")
      (is (= pub2 (age/public-key path)) "and the file on disk is the new one")
      (is (= #{"regen.txt"}
             (->> (.list (io/file *dir*)) (filter #(= "regen.txt" %)) set))
          "no staging leftovers beside the key")
      (is (empty? (filter #(re-find #"\.regen\.txt\.keygen" %) (.list (io/file *dir*))))
          "the temp staging directory is cleaned up"))))
