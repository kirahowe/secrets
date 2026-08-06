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
            [com.kirahowe.secrets.cli :as cli]))

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
      (is (= "secrets.enc" (:secrets-file env))))))

(deftest unknown-environment-throws
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Unknown environment"
                        (cli/recipients! (cli/normalize-config (test-config)) "nope"))))

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
