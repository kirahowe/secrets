(ns com.kirahowe.secrets.cli-test
  "Tests for the non-interactive CLI paths, exercising the real `age` binary
  like the core suite. Nothing here opens $EDITOR or prompts; command fns are
  called directly (they are REPL-safe — they return data and throw ex-info
  instead of exiting), plus `run!` for the dispatch/arg-order cases that don't
  exit on success.

  Tests that pin a specific key skip themselves when an SECRETS_AGE_IDENTITY*
  env var is set, because the env legitimately overrides :key-file."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.java.shell :as shell]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.cli :as cli]
            [com.kirahowe.secrets.manifest :as manifest]))

(def ^:private ^:dynamic *dir* nil)
(def ^:private ^:dynamic *key* nil)

(defn- with-tmp-key [f]
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

(defn- age-env-set?
  "Whether an SECRETS_AGE_IDENTITY* variable overrides the fixture key."
  []
  (boolean
   (some #(System/getenv %)
         ["SECRETS_AGE_IDENTITY_FILE"
          "SECRETS_AGE_IDENTITY"
          "SECRETS_AGE_IDENTITY_B64"])))

(defn- test-config
  "A single-env config rooted in the fixture's temp dir, key pinned to *key*."
  ([] (test-config {}))
  ([env-overrides]
   {:app "cli-test"
    :default-environment :dev
    :environments {:dev (merge {:secrets-file (str *dir* "/secrets.edn.age")
                                :key-file *key*}
                               env-overrides)}}))

(defn- encrypt-edn!
  "Encrypt `m` to the config's secrets file out-of-band (no manifest written),
  as a teammate bypassing the CLI would."
  [m]
  (let [plain (str *dir* "/plain.edn")
        enc (str *dir* "/secrets.edn.age")]
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

(defn- capture-verify
  "Run verify! with stdout and stderr captured separately; return its result
  map plus both streams, for tests that assert on what was reported."
  [config env-arg]
  (let [result (atom nil)
        out (java.io.StringWriter.)
        err (java.io.StringWriter.)]
    (binding [*out* out *err* err]
      (reset! result (cli/verify! config env-arg)))
    {:result @result :out (str out) :err (str err)}))

(defn- file-bytes [path]
  (vec (java.nio.file.Files/readAllBytes (.toPath (io/file path)))))

(defn- cli-private [sym]
  (ns-resolve 'com.kirahowe.secrets.cli sym))

(defn- under-default-key-file
  [path f]
  (with-redefs-fn {(cli-private 'default-key-file) (constantly path)} f))

(defn- capture-doctor
  [config env-arg]
  (let [result (atom nil)
        out (java.io.StringWriter.)
        err (java.io.StringWriter.)]
    (binding [*out* out *err* err]
      (reset! result (cli/doctor! config env-arg)))
    {:result @result :out (str out) :err (str err)}))

(defn- doctor-under
  "Run doctor with process boundaries replaced, including the app default key
  path so tests do not depend on the developer's home or environment."
  [config env-arg {:keys [environment identity-path version] :as opts}]
  (with-redefs-fn {(cli-private 'getenv) (or environment {})
                   (cli-private 'default-key-file) (fn [_] *key*)
                   #'secrets/identity-from-env (fn [] identity-path)
                   #'age/version (fn [] (if (contains? opts :version)
                                          version
                                          "age test-version"))}
    #(capture-doctor config env-arg)))

(defn- complete-doctor-config
  ([] (complete-doctor-config {}))
  ([overrides]
   (let [config (test-config overrides)
         env (get-in config [:environments :dev])
         cipher (:secrets-file env)
         template (if (contains? env :template)
                    (:template env)
                    (str/replace cipher #"\.age$" ".example"))
         manifest (if (contains? env :manifest)
                    (:manifest env)
                    (str/replace cipher #"\.age$" ".manifest"))]
     (spit cipher "age ciphertext fixture")
     (when (string? template) (spit template "{}"))
     (when (string? manifest)
       (spit manifest "{:version 2 :ciphertext-sha \"fixture-sha\"}"))
     config)))

;;;; Normalize config

(deftest normalize-config-defaults-test
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
    (if (age-env-set?)
      (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
      (is (= (:key-file env) (:identity-file env))
          ":identity-file falls back to :key-file without SECRETS_AGE_IDENTITY*"))))

(deftest normalize-config-explicit-values-respected-test
  (let [cfg (cli/normalize-config
             {:app "myapp"
              :environments {:dev {:secrets-file "s.edn.age"
                                   :template "tpl.edn"
                                   :manifest false}}})
        env (get-in cfg [:environments :dev])]
    (is (= "tpl.edn" (:template env)))
    (is (false? (:manifest env)) ":manifest false survives normalization")))

(deftest normalize-config-validation-test
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
                                        :template "secrets.example"
                                        :manifest false}}}
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
          env {:secrets-file "ciphertext.age"
               :manifest "manifest.edn"
               :template "template.edn"
               :key-file "key.txt"
               :recipients-file "recipients.txt"}]
      (doseq [left-index (range (count fields))
              right-index (range (inc left-index) (count fields))]
        (let [left (nth fields left-index)
              right (nth fields right-index)
              env (assoc env right (str "./" (get env left)))]
          (is (thrown-with-msg? clojure.lang.ExceptionInfo #"colliding artifact paths"
                                (cli/normalize-config
                                 {:app "x" :environments {:dev env}}))
              (str left " and " right " alias the same canonical path")))))))

(deftest unknown-environment-throws-test
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Unknown environment"
                        (cli/recipients! (cli/normalize-config (test-config)) "nope"))))

;;;; Doctor

(deftest doctor-healthy-warning-invalid-and-stable-output-test
  (testing "a healthy configuration has stable output"
    (let [config (complete-doctor-config)
          {:keys [result out err]} (doctor-under config nil {})]
      (is (= 0 (:exit result)))
      (is (= :healthy (:status result)))
      (is (= :dev (:environment result)))
      (is (= {:available? true :version "age test-version"} (:age result)))
      (is (true? (get-in result [:verify :keyless?])))
      (is (true? (get-in result [:verify :full?])))
      (is (= (.getCanonicalPath
              (io/file (get-in config [:environments :dev :secrets-file])))
             (get-in result [:artifacts :ciphertext :path])))
      (is (str/starts-with? out "Age: available"))
      (is (re-find #"(?m)^Age: available" out))
      (is (re-find #"(?m)^Environment: dev$" out))
      (is (re-find #"(?m)^Status: healthy$" out))
      (is (= "" err))))
  (testing "an unavailable age binary produces a warning"
    (let [{:keys [result]} (doctor-under (test-config) nil {:version nil})]
      (is (= 1 (:exit result)))
      (is (= :warning (:status result)))
      (is (false? (get-in result [:age :available?])))))
  (testing "an invalid configuration produces only the stable diagnostic"
    (let [{:keys [result out err]}
          (doctor-under {:environments {:dev {:secrets-file "s.age"}}} nil {})]
      (is (= 2 (:exit result)))
      (is (= :invalid (:status result)))
      (is (= "Configuration: invalid\nStatus: invalid\n" out))
      (is (= "" err)))))

(deftest doctor-identifies-every-identity-source-without-disclosure-test
  (let [raw-value "RAW-IDENTITY-SENTINEL"
        b64-value "B64-IDENTITY-SENTINEL"
        file-value (str *dir* "/FILE-IDENTITY-SENTINEL")
        raw-path (str *dir* "/RAW-MATERIALIZED-PATH-SENTINEL")
        b64-path (str *dir* "/B64-MATERIALIZED-PATH-SENTINEL")
        _ (doseq [path [file-value raw-path b64-path]] (spit path "identity fixture"))
        base (test-config)
        specs [{:source :secrets-age-identity-file
                :label "SECRETS_AGE_IDENTITY_FILE"
                :environment {"SECRETS_AGE_IDENTITY_FILE" file-value}
                :identity-path file-value
                :sentinels [file-value]}
               {:source :secrets-age-identity
                :label "SECRETS_AGE_IDENTITY"
                :environment {"SECRETS_AGE_IDENTITY" raw-value}
                :identity-path raw-path
                :sentinels [raw-value raw-path]}
               {:source :secrets-age-identity-b64
                :label "SECRETS_AGE_IDENTITY_B64"
                :environment {"SECRETS_AGE_IDENTITY_B64" b64-value}
                :identity-path b64-path
                :sentinels [b64-value b64-path]}
               {:source :identity-file
                :label ":identity-file"
                :config (test-config {:identity-file *key*})}
               {:source :configured-key-file
                :label "configured key path"}
               {:source :default-key-file
                :label "default key path"
                :config {:app "cli-test"
                         :default-environment :dev
                         :environments {:dev {:secrets-file (str *dir* "/default.edn.age")}}}}]]
    (doseq [{:keys [source config sentinels] :as spec} specs]
      (testing (name source)
        (let [{:keys [result out err]}
              (doctor-under (or config base) nil spec)
              disclosed (str (pr-str result) out err)]
          (is (= source (get-in result [:identity :source])))
          (is (str/includes? out (str "Identity: " (:label spec) " — usable\n")))
          (is (true? (get-in result [:identity :usable?])))
          (doseq [sentinel sentinels]
            (is (not (str/includes? disclosed sentinel)))))))))

(deftest doctor-recipient-modes-and-validity-test
  (let [recipients (str *dir* "/recipients.txt")
        config (complete-doctor-config {:recipients-file recipients})
        valid-a "age1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        valid-b "age1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]
    (testing "missing configured recipients is actionable, not invalid"
      (let [{:keys [result]} (doctor-under config nil {})]
        (is (= 1 (:exit result)))
        (is (= :multi-recipient (get-in result [:encryption :mode])))
        (is (= :missing (get-in result [:encryption :recipients :state])))))
    (testing "empty and invalid configured recipients are invalid configuration"
      (spit recipients "# no recipients\n")
      (is (= [2 :empty]
             ((juxt :exit #(get-in % [:encryption :recipients :state]))
              (:result (doctor-under config nil {})))))
      (spit recipients "not-an-age-recipient\n")
      (let [result (:result (doctor-under config nil {}))]
        (is (= 2 (:exit result)))
        (is (= {:state :invalid :count 1 :valid? false :invalid-count 1}
               (get-in result [:encryption :recipients])))))
    (testing "valid recipients expose counts, never lines"
      (spit recipients (str valid-a "\n" valid-b "\n"))
      (let [{:keys [result out]} (doctor-under config nil {})]
        (is (= 0 (:exit result)))
        (is (= {:state :valid :count 2 :valid? true}
               (get-in result [:encryption :recipients])))
        (is (not (str/includes? (str (pr-str result) out) valid-a)))
        (is (not (str/includes? (str (pr-str result) out) valid-b)))))
    (testing "unconfigured recipients is explicit single-key mode"
      (let [result (:result (doctor-under (complete-doctor-config) nil {}))]
        (is (= :single-key (get-in result [:encryption :mode])))
        (is (= {:state :unconfigured :count 0 :valid? nil}
               (get-in result [:encryption :recipients])))))))

(deftest doctor-keyless-full-and-disabled-manifest-capability-test
  (let [config (complete-doctor-config)]
    (testing "a complete setup supports keyless and full verification"
      (is (= {:state :ready :keyless? true :full? true}
             (:verify (:result (doctor-under config nil {}))))))
    (testing "a missing identity preserves keyless verification"
      (let [missing-identity (str *dir* "/missing-identity")
            result (:result
                    (doctor-under
                     config
                     nil
                     {:environment {"SECRETS_AGE_IDENTITY_FILE" missing-identity}
                      :identity-path missing-identity}))]
        (is (= 1 (:exit result)))
        (is (= {:state :ready :keyless? true :full? false} (:verify result)))))
    (testing "an unavailable age binary preserves keyless verification"
      (let [result (:result (doctor-under config nil {:version nil}))]
        (is (= {:state :ready :keyless? true :full? false} (:verify result)))))
    (testing "an incomplete manifest prevents keyless verification"
      (spit (str *dir* "/secrets.edn.manifest") "{:version 2}")
      (let [result (:result (doctor-under config nil {}))]
        (is (= 1 (:exit result)))
        (is (= {:state :missing-ciphertext-sha :keyless? false :full? true}
               (:verify result))))))
  (testing "a disabled manifest skips verification"
    (let [result (:result
                  (doctor-under (complete-doctor-config {:manifest false}) nil {}))]
      (is (= 0 (:exit result)))
      (is (= {:state :skipped :keyless? false :full? false} (:verify result)))
      (is (= :disabled (get-in result [:artifacts :manifest :state]))))))

(deftest run-dispatches-doctor-before-normalization-test
  (let [called (atom nil)]
    (with-redefs [cli/doctor! (fn [config env]
                                (reset! called [config env])
                                {:exit 0})]
      (cli/run! {:deliberately :invalid} ["doctor" "prod"]))
    (is (= [{:deliberately :invalid} "prod"] @called))))

;;;; Validated, transactional saves

(deftest new-rejects-invalid-edn-before-writing-test
  (let [config (cli/normalize-config (test-config))
        encrypted (str *dir* "/secrets.edn.age")
        manifest (str *dir* "/secrets.edn.manifest")]
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

(deftest edit-rejects-invalid-edn-without-replacing-valid-files-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          encrypted (str *dir* "/secrets.edn.age")
          manifest-path (str *dir* "/secrets.edn.manifest")]
      (encrypt-edn! {:valid true})
      (with-out-str (cli/reencrypt! config "dev"))
      (let [ciphertext-before (file-bytes encrypted)
            manifest-before (slurp manifest-path)]
        (is (thrown-with-msg?
             clojure.lang.ExceptionInfo #"not valid EDN"
             (with-out-str
               (with-redefs-fn {(cli-private 'run-editor!) #(spit % "{:broken")}
                 #(cli/edit! config "dev")))))
        (is (= ciphertext-before (file-bytes encrypted)))
        (is (= manifest-before (slurp manifest-path)))))))

(deftest edit-stages-all-output-before-replacing-either-file-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          encrypted (str *dir* "/secrets.edn.age")
          manifest-path (str *dir* "/secrets.edn.manifest")]
      (encrypt-edn! {:version :old})
      (with-out-str (cli/reencrypt! config "dev"))
      (let [ciphertext-before (file-bytes encrypted)
            manifest-before (slurp manifest-path)]
        (is (thrown-with-msg?
             clojure.lang.ExceptionInfo #"manifest rendering failed"
             (with-out-str
               (with-redefs-fn {(cli-private 'run-editor!) #(spit % "{:version :new}")
                                #'manifest/render (fn [& _]
                                                    (throw
                                                     (ex-info
                                                      "manifest rendering failed"
                                                      {})))}
                 #(cli/edit! config "dev")))))
        (is (= ciphertext-before (file-bytes encrypted)))
        (is (= manifest-before (slurp manifest-path)))))))

(deftest edit-rolls-back-an-interrupted-pair-commit-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          encrypted (str *dir* "/secrets.edn.age")
          manifest-path (str *dir* "/secrets.edn.manifest")]
      (encrypt-edn! {:version :old})
      (with-out-str (cli/reencrypt! config "dev"))
      (let [ciphertext-before (file-bytes encrypted)
            manifest-before (slurp manifest-path)
            atomic-var (cli-private 'atomic-replace!)
            atomic-replace! @atomic-var
            moves (atom 0)]
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

;;;; Re-encrypt and verify

(deftest reencrypt-writes-manifest-and-verify-passes-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))]
      (encrypt-edn! {:database/url "jdbc:x" :auth/admins #{"a@b.com"}})
      (with-out-str (cli/reencrypt! config "dev"))
      (let [m (edn/read-string (slurp (str *dir* "/secrets.edn.manifest")))]
        (is (= 2 (:version m)))
        (is (string? (:ciphertext-sha m)) "manifest records the ciphertext hash")
        (is (contains? (:keys m) [:database/url]))
        (is (contains? (get-in m [:keys [:database/url]]) :vhash)
            "single-key mode keys the value hashes"))
      (let [{:keys [results exit]} (verify config "dev")]
        (is (= 0 exit))
        (is (= :ok (:dev results)))))))

(deftest verify-detects-drift-test
  (if (age-env-set?)
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

(deftest verify-keyless-freshness-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
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

(deftest verify-version-gate-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))]
      (encrypt-edn! {:a 1})
      (spit (str *dir* "/secrets.edn.manifest")
            "{:version 3 :app \"cli-test\" :keys {}}")
      (let [{:keys [results exit]} (verify config "dev")]
        (is (= 1 exit))
        (is (= :drift (:dev results)) "an unsupported :version is reported, not misdiffed")))))

(deftest v1-manifest-is-rejected-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          manifest-path (str *dir* "/secrets.edn.manifest")]
      (encrypt-edn! {:a 1})
      (with-out-str (cli/reencrypt! config "dev"))
      (let [committed (edn/read-string (slurp manifest-path))]
        (is (= 2 (:version committed)) "the CLI writes v2")
        ;; Everything but :version stays consistent with the ciphertext, so only
        ;; the version can be what fails: a v1 hash is never read as a v2 one.
        (spit manifest-path (pr-str (assoc committed :version 1))))
      (let [{:keys [results exit]} (verify config "dev")]
        (is (= 1 exit) "a v1 manifest fails verification")
        (is (= :drift (:dev results)) "and is never reported as :ok")))))

(deftest public-recipient-forgery-fails-verification-test
  ;; The two values here collided under the v1 encoding, so this exact forgery
  ;; — ciphertext replaced using only the public recipient, :ciphertext-sha
  ;; refreshed, every committed :vhash left alone — passed full verification
  ;; before manifest v2.
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          ciphertext (str *dir* "/secrets.edn.age")
          manifest-path (str *dir* "/secrets.edn.manifest")
          sha256 (cli-private 'sha256)]
      (encrypt-edn! {:x ['{a=b c}]})
      (with-out-str (cli/reencrypt! config "dev"))
      (let [committed (edn/read-string (slurp manifest-path))
            recipient (age/public-key *key*)
            forged (str *dir* "/forged.edn")]
        (is (age/valid-recipient? recipient)
            "the public recipient is the attacker's only key material")
        (spit forged (pr-str {:x ['{a b=c}]}))
        (age/encrypt-file! {:recipients [recipient]} forged ciphertext)
        (.delete (io/file forged))
        (spit manifest-path
              (pr-str (assoc committed :ciphertext-sha (sha256 ciphertext))))
        (is (= (:keys committed) (:keys (edn/read-string (slurp manifest-path))))
            "the forged manifest keeps every original :vhash"))
      (let [{:keys [result out]} (capture-verify config "dev")]
        (is (= 1 (:exit result)) "full verification fails")
        (is (= :drift (get-in result [:results :dev])))
        (is (str/includes? out "value or type changed")
            "and names the forged entry as stale")))))

(deftest verify-missing-is-exit-2-and-repl-safe-test
  (let [config (cli/normalize-config (test-config))
        {:keys [results exit]} (verify config nil)]
    (is (= 2 exit) "no secrets file yet is missing (2), not drift (1)")
    (is (= :missing (:dev results)))
    (is true "and verify! returned instead of killing the process")))

;;;; Encrypt and decrypt (environment-first argument order)

(deftest encrypt-decrypt-arg-order-and-binary-safety-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (test-config)
          f (str *dir* "/note.txt")
          g (str *dir* "/other.txt")
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
          (with-open [replacement (java.io.PrintStream. baos)]
            (System/setOut replacement)
            (try
              (with-out-str (cli/run! config ["decrypt" "dev" (str f ".age")]))
              (finally
                (System/setOut orig))))
          (is (= payload (String. (.toByteArray baos) "UTF-8"))))))))

;;;; Command-line option boundary

(defn- with-cwd-entry
  "Run `(f entry)` on a working-directory entry named exactly `entry-name`,
  then delete it. A dash-leading argv element can only come from a
  cwd-relative path, so these fixtures cannot live in the absolute temp dir
  the rest of the suite uses. Refuses to touch a pre-existing entry rather
  than clobbering it, and cleans up even when an assertion fails."
  [entry-name f]
  (let [entry (io/file entry-name)]
    (when (.exists entry)
      (throw (ex-info "refusing to clobber an existing working-directory entry"
                      {:entry entry-name})))
    (try
      (f entry)
      (finally
        (doseq [p (reverse (file-seq entry))] (.delete p))))))

(deftest encrypt-decrypt-a-dash-leading-relative-path-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (with-cwd-entry "-secrets-cli-boundary"
      (fn [_]
        (let [config (cli/normalize-config (test-config))
              rel "-secrets-cli-boundary/note.txt"
              payload "hello from a dash-leading path"]
          (io/make-parents rel)
          (spit rel payload)
          ;; The commands are called directly rather than through `run!`: `run!`
          ;; turns a command failure into System/exit, which would kill the test
          ;; runner instead of reporting a failing assertion.
          (testing "encrypt takes a dash-leading path as a file, not as options"
            (with-out-str (cli/encrypt! config "dev" rel))
            (is (.exists (io/file (str rel ".age")))))
          (testing "decrypt streams the exact bytes of a dash-leading ciphertext"
            (let [baos (java.io.ByteArrayOutputStream.)
                  orig System/out]
              (with-open [replacement (java.io.PrintStream. baos)]
                (System/setOut replacement)
                (try
                  (with-out-str (cli/decrypt! config "dev" (str rel ".age")))
                  (finally
                    (System/setOut orig))))
              (is (= payload (String. (.toByteArray baos) "UTF-8"))))))))))

(deftest run-editor-receives-an-absolute-path-test
  (with-cwd-entry "-secrets-cli-boundary-editor"
    (fn [entry]
      (.mkdir entry)
      (let [relative-plaintext "-secrets-cli-boundary-editor/plain.edn"
            script (io/file *dir* "capture-editor-operand.sh")
            capture (io/file *dir* "editor-operand.txt")
            run-editor! (cli-private 'run-editor!)]
        (spit relative-plaintext "plaintext")
        (spit script "#!/bin/sh\nprintf '%s' \"$2\" > \"$1\"\n")
        (is (.setExecutable script true true) "the fixture editor must be executable")
        (with-redefs-fn {(cli-private 'editor)
                         (constantly (str (.getAbsolutePath script)
                                          " "
                                          (.getAbsolutePath capture)))}
          #(run-editor! relative-plaintext))
        (is (= (.getAbsolutePath (io/file relative-plaintext))
               (slurp capture)))))))

(deftest secure-delete-option-boundary-test
  (let [secure-delete! (cli-private 'secure-delete!)
        real-sh shell/sh
        calls (atom [])
        recording (fn [& args]
                    (let [argv (vec (take-while string? args))
                          result (apply real-sh args)]
                      (swap! calls conj {:args argv :exit (:exit result)})
                      result))
        outcome (fn [path]
                  (spit path "plaintext that must be overwritten, not just unlinked")
                  (reset! calls [])
                  (with-redefs [shell/sh recording]
                    (secure-delete! path))
                  @calls)
        dash-path "-secrets-cli-boundary-delete"
        control (outcome (str *dir* "/control-plaintext.edn"))
        dash (with-cwd-entry dash-path (fn [_] (outcome dash-path)))
        only-dash (with-cwd-entry "-" (fn [_] (outcome "-")))
        mechanism (fn [calls] (mapv (juxt (comp first :args) :exit) calls))]
    (testing "a dash-named path is shredded by the same mechanism, same status"
      (doseq [[label observed] [["dash-leading" dash] ["exact -" only-dash]]]
        (is (= (mechanism control) (mechanism observed))
            (str label ": a platform whose rm/shred is unusable for both paths makes "
                 "this comparison vacuous but never wrong: control " (pr-str control)
                 " vs " (pr-str observed)))))
    (testing "argv shape (the overwrite guarantee is otherwise unobservable)"
      (doseq [[path observed] [[dash-path dash] ["-" only-dash]]]
        (let [deletions (filterv #(#{"rm" "shred"} (first (:args %))) observed)
              absolute (.getAbsolutePath (io/file path))]
          (if (seq deletions)
            (doseq [{:keys [args]} deletions]
              (is (= ["--" absolute] (take-last 2 args))
                  (str "argv " (pr-str args) " must end with -- then an absolute path")))
            (is true (str "vacuous: no rm/shred subprocess ran for " path))))))))

(deftest secure-delete-platform-argv-shape-test
  (let [secure-delete! (cli-private 'secure-delete!)
        absolute (.getAbsolutePath (io/file "-"))]
    (testing "macOS uses rm -P with an option terminator and absolute operand"
      (with-cwd-entry "-"
        (fn [entry]
          (spit entry "plaintext")
          (let [calls (atom [])
                recording (fn [& args]
                            (swap! calls conj (vec args))
                            {:exit 0})]
            (with-redefs [str/starts-with? (constantly true)
                          shell/sh recording]
              (secure-delete! "-"))
            (is (= [["rm" "-P" "--" absolute]] @calls))))))
    (testing "non-macOS probes for shred, then uses the same safe operand shape"
      (with-cwd-entry "-"
        (fn [entry]
          (spit entry "plaintext")
          (let [calls (atom [])
                recording (fn [& args]
                            (swap! calls conj (vec args))
                            {:exit 0})]
            (with-redefs [str/starts-with? (constantly false)
                          shell/sh recording]
              (secure-delete! "-"))
            (is (= [["sh" "-c" "command -v shred"]
                    ["shred" "-u" "--" absolute]]
                   @calls))))))))

;;;; Set and remove

(deftest set-creates-a-brand-new-store-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          encrypted (str *dir* "/secrets.edn.age")]
      (is (not (.exists (io/file encrypted))) "no store yet")
      (with-out-str
        (with-in-str "s3cr3t" (cli/set-secret! config "dev" ":openrouter/api-key" false)))
      (is (.exists (io/file encrypted)) "set creates the file")
      (is (= {:openrouter/api-key "s3cr3t"}
             (edn/read-string (age/decrypt *key* encrypted)))))))

(deftest set-overwrites-an-existing-key-leaving-others-untouched-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          encrypted (str *dir* "/secrets.edn.age")]
      (encrypt-edn! {:a "old" :b "keep"})
      (with-out-str (cli/reencrypt! config "dev"))
      (with-out-str (with-in-str "new" (cli/set-secret! config "dev" ":a" false)))
      (is (= {:a "new" :b "keep"} (edn/read-string (age/decrypt *key* encrypted)))))))

(deftest set-nested-vector-path-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          encrypted (str *dir* "/secrets.edn.age")]
      (with-out-str
        (with-in-str "acct-123" (cli/set-secret! config "dev" "[:r2 :account-id]" false)))
      (is (= {:r2 {:account-id "acct-123"}} (edn/read-string (age/decrypt *key* encrypted))))
      (testing "a sibling key added under the same parent leaves the first untouched"
        (with-out-str
          (with-in-str "us-east" (cli/set-secret! config "dev" "[:r2 :region]" false)))
        (is (= {:r2 {:account-id "acct-123" :region "us-east"}}
               (edn/read-string (age/decrypt *key* encrypted))))))))

(deftest set-edn-flag-parses-typed-values-and-manifest-records-type-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          encrypted (str *dir* "/secrets.edn.age")]
      (with-out-str
        (with-in-str "#{\"a@b.com\" \"c@d.com\"}"
          (cli/set-secret! config "dev" ":auth/admins" true)))
      (is (= {:auth/admins #{"a@b.com" "c@d.com"}}
             (edn/read-string (age/decrypt *key* encrypted))))
      (let [m (edn/read-string (slurp (str *dir* "/secrets.edn.manifest")))]
        (is (= :set (get-in m [:keys [:auth/admins] :type]))
            "manifest records the EDN-parsed value's real type, not :string")))))

(deftest set-without-edn-stores-a-plain-string-even-when-it-looks-like-edn-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          encrypted (str *dir* "/secrets.edn.age")]
      (with-out-str (with-in-str "42" (cli/set-secret! config "dev" ":n" false)))
      (is (= {:n "42"} (edn/read-string (age/decrypt *key* encrypted)))
          "default (no --edn) always stores a string, regardless of stdin's shape"))))

(deftest set-strips-exactly-one-trailing-newline-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          encrypted (str *dir* "/secrets.edn.age")]
      (testing "a single trailing \\n is stripped"
        (with-out-str (with-in-str "secret\n" (cli/set-secret! config "dev" ":a" false)))
        (is (= "secret" (:a (edn/read-string (age/decrypt *key* encrypted))))))
      (testing "a single trailing \\r\\n is stripped"
        (with-out-str (with-in-str "secret\r\n" (cli/set-secret! config "dev" ":b" false)))
        (is (= "secret" (:b (edn/read-string (age/decrypt *key* encrypted))))))
      (testing "only exactly one trailing newline is stripped — the rest is verbatim"
        (with-out-str (with-in-str "line1\n\n" (cli/set-secret! config "dev" ":c" false)))
        (is (= "line1\n" (:c (edn/read-string (age/decrypt *key* encrypted))))))
      (testing "no trailing newline at all is untouched"
        (with-out-str (with-in-str "bare" (cli/set-secret! config "dev" ":d" false)))
        (is (= "bare" (:d (edn/read-string (age/decrypt *key* encrypted)))))))))

(deftest set-refuses-a-blank-value-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          encrypted (str *dir* "/secrets.edn.age")]
      (testing (str "empty stdin fails rather than storing \"\""
                    " — an unset CI variable expands to nothing")
        (is (thrown-with-msg?
             clojure.lang.ExceptionInfo #"(?i)nothing on stdin"
             (with-out-str (with-in-str "" (cli/set-secret! config "dev" ":a" false)))))
        (is (not (.exists (io/file encrypted))) "and nothing was written"))
      (testing "whitespace-only stdin fails the same way"
        (is (thrown-with-msg?
             clojure.lang.ExceptionInfo #"(?i)nothing on stdin"
             (with-out-str (with-in-str "\n" (cli/set-secret! config "dev" ":a" false))))))
      (testing "--edn is the escape hatch for a deliberately empty value"
        (with-out-str (with-in-str "\"\"" (cli/set-secret! config "dev" ":a" true)))
        (is (= {:a ""} (edn/read-string (age/decrypt *key* encrypted))))))))

(deftest set-writes-a-store-that-stays-readable-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          encrypted (str *dir* "/secrets.edn.age")]
      (with-out-str (with-in-str "v" (cli/set-secret! config "dev" "[:a :b]" false)))
      (with-out-str (with-in-str "w" (cli/set-secret! config "dev" ":c" false)))
      (let [plaintext (age/decrypt *key* encrypted)]
        (is (= {:a {:b "v"} :c "w"} (edn/read-string plaintext)))
        (is (re-find #"\n" plaintext)
            "the regenerated store is pretty-printed, so the next `edit` is readable"))
      (testing "print limits set in a REPL cannot truncate the store"
        (binding [*print-length* 1 *print-level* 1]
          (with-out-str (with-in-str "x" (cli/set-secret! config "dev" ":d" false))))
        (is (= {:a {:b "v"} :c "w" :d "x"}
               (edn/read-string (age/decrypt *key* encrypted))))))))

(deftest set-refreshes-the-manifest-so-verify-passes-test
  (let [config (cli/normalize-config (test-config))]
    (with-out-str (with-in-str "v" (cli/set-secret! config "dev" ":k" false)))
    (let [{:keys [results exit]} (verify config "dev")]
      (is (= 0 exit))
      (is (= :ok (:dev results))))))

(deftest rm-removes-a-key-and-verify-still-passes-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          encrypted (str *dir* "/secrets.edn.age")]
      (encrypt-edn! {:a "keep" :b "gone"})
      (with-out-str (cli/reencrypt! config "dev"))
      (with-out-str (cli/remove-secret! config "dev" ":b"))
      (is (= {:a "keep"} (edn/read-string (age/decrypt *key* encrypted))))
      (let [{:keys [results exit]} (verify config "dev")]
        (is (= 0 exit))
        (is (= :ok (:dev results)))))))

(deftest rm-leaves-the-parent-map-in-place-for-a-nested-path-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          encrypted (str *dir* "/secrets.edn.age")]
      (encrypt-edn! {:r2 {:account-id "acct-123"}})
      (with-out-str (cli/reencrypt! config "dev"))
      (with-out-str (cli/remove-secret! config "dev" "[:r2 :account-id]"))
      (is (= {:r2 {}} (edn/read-string (age/decrypt *key* encrypted)))
          "the (now empty) parent map is left in place, not pruned"))))

(deftest rm-of-an-absent-key-fails-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          encrypted (str *dir* "/secrets.edn.age")]
      (encrypt-edn! {:a 1})
      (with-out-str (cli/reencrypt! config "dev"))
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"No such key"
                            (with-out-str (cli/remove-secret! config "dev" ":nope"))))
      (is (= {:a 1} (edn/read-string (age/decrypt *key* encrypted)))
          "a failed rm never touches the ciphertext"))))

(deftest rm-on-a-missing-store-fails-pointing-at-new-or-set-test
  (let [config (cli/normalize-config (test-config))]
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"No secrets file"
                          (with-out-str (cli/remove-secret! config "dev" ":a"))))))

(deftest invalid-key-argument-fails-test
  (let [config (cli/normalize-config (test-config))]
    (testing "neither a keyword nor a vector"
      (doseq [bad ["not-a-keyword" "42" "{}" "\"a string\"" "nil"]]
        (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Invalid key"
                              (with-out-str (cli/set-secret! config "dev" bad false)))
            bad)))
    (testing "an empty vector"
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Invalid key"
                            (with-out-str (cli/set-secret! config "dev" "[]" false)))))
    (testing "a vector of non-keyword/string elements"
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Invalid key"
                            (with-out-str (cli/set-secret! config "dev" "[1 2]" false)))))
    (testing "malformed EDN"
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Invalid key"
                            (with-out-str (cli/set-secret! config "dev" "[:unfinished" false)))))
    (testing "a missing key argument"
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Missing key"
                            (with-out-str (cli/set-secret! config "dev" nil false)))))
    (testing "the same validation applies to rm"
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Invalid key"
                            (with-out-str (cli/remove-secret! config "dev" "42")))))))

(deftest run!-dispatches-set-and-rm-with-the-edn-flag-parsed-out-anywhere-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (test-config)
          encrypted (str *dir* "/secrets.edn.age")]
      (testing "run! dispatches set as <key> alone via the default env, --edn before it"
        (with-out-str (with-in-str "42" (cli/run! config ["set" "--edn" ":n"])))
        (is (= 42 (:n (edn/read-string (age/decrypt *key* encrypted))))))
      (testing "run! dispatches set as [env] <key>, --edn after both"
        (with-out-str (with-in-str "\"s\"" (cli/run! config ["set" "dev" ":m" "--edn"])))
        (is (= "s" (:m (edn/read-string (age/decrypt *key* encrypted))))))
      (testing "without --edn the value is stored as a plain string"
        (with-out-str (with-in-str "plain" (cli/run! config ["set" "dev" ":p"])))
        (is (= "plain" (:p (edn/read-string (age/decrypt *key* encrypted))))))
      (testing "run! dispatches rm as [env] <key>"
        (with-out-str (cli/run! config ["rm" "dev" ":n"]))
        (is (not (contains? (edn/read-string (age/decrypt *key* encrypted)) :n)))))))

;;;; Regressions

(deftest keygen-overwrites-a-confirmed-existing-key-test
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

(deftest keygen-reports-sharing-environments-and-app-default-clause-test
  (testing "environments without :key-file share the app default"
    (let [home (str *dir* "/home")
          default-key (str home "/.config/cli-test/key.txt")]
      (.mkdirs (io/file home))
      (under-default-key-file
       default-key
       #(let [config (cli/normalize-config
                      {:app "cli-test"
                       :environments
                       {:dev {:secrets-file (str *dir* "/dev/secrets.edn.age")}
                        :prod {:secrets-file (str *dir* "/prod/secrets.edn.age")}}})
              out (with-out-str (cli/keygen! config "dev"))]
          (is (re-find
               #"Used by: dev, prod — every environment without its own :key-file"
               out)))))))

(deftest keygen-excludes-an-environment-with-its-own-key-file-test
  (let [home (str *dir* "/home2")
        default-key (str home "/.config/cli-test/key.txt")]
    (.mkdirs (io/file home))
    (under-default-key-file
     default-key
     #(let [config (cli/normalize-config
                    {:app "cli-test"
                     :environments
                     {:dev {:secrets-file (str *dir* "/dev/secrets.edn.age")}
                      :prod {:secrets-file (str *dir* "/prod/secrets.edn.age")
                             :key-file (str *dir* "/prod-key.txt")}}})
            out (with-out-str (cli/keygen! config "dev"))]
        (is (re-find
             #"Used by: dev — every environment without its own :key-file"
             out)
            "only dev shares the app-default key")
        (is (not (re-find #"prod" out))
            "prod has its own :key-file, so it is not listed as sharing dev's")))))

(deftest keygen-with-no-env-and-no-default-succeeds-when-key-file-is-unambiguous-test
  (let [shared (str *dir* "/shared-key.txt")
        config (cli/normalize-config
                {:app "cli-test"
                 :environments {:dev {:secrets-file (str *dir* "/dev/secrets.edn.age")
                                      :key-file shared}
                                :staging {:secrets-file (str *dir* "/staging/secrets.edn.age")
                                          :key-file shared}}})
        result (atom nil)
        out (with-out-str (reset! result (cli/keygen! config nil)))]
    (is (= shared @result)
        "no [env] and no :default-environment, but every environment agrees on :key-file")
    (is (re-find #"Used by: dev, staging" out))))

(deftest keygen-with-no-env-and-no-default-still-fails-when-key-files-differ-test
  (let [config (cli/normalize-config
                {:app "cli-test"
                 :environments {:dev {:secrets-file (str *dir* "/dev/secrets.edn.age")
                                      :key-file (str *dir* "/dev-key.txt")}
                                :prod {:secrets-file (str *dir* "/prod/secrets.edn.age")
                                       :key-file (str *dir* "/prod-key.txt")}}})]
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Missing environment"
                          (cli/keygen! config nil))
        "differing key files really is ambiguous, so this is unchanged")))

(deftest team-bootstrap-adds-first-owner-before-ciphertext-and-reencrypts-for-teammate-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [recipients (str *dir* "/recipients.txt")
          ciphertext (str *dir* "/secrets.edn.age")
          bob-key (str *dir* "/bob-key.txt")
          secret-value "team-bootstrap-value-that-must-not-be-printed"
          config (cli/normalize-config (test-config {:recipients-file recipients}))
          alice-public (age/public-key *key*)
          added (atom nil)
          initial-out (with-out-str
                        (reset! added (cli/add-recipient! config "dev" nil)))]
      (testing "the first owner is added without creating or re-encrypting ciphertext"
        (is (= alice-public @added))
        (is (= [alice-public] (str/split-lines (slurp recipients))))
        (is (not (.exists (io/file ciphertext))))
        (is (str/includes? initial-out "bb secrets set dev"))
        (is (str/includes? initial-out "bb secrets new dev"))
        (is (not (str/includes? initial-out "reencrypt"))))
      (let [set-out (with-out-str
                      (with-in-str secret-value
                        (cli/set-secret! config "dev" ":service/token" false)))
            bob-public (age/keygen! bob-key)
            teammate-added (atom nil)
            teammate-out (with-out-str
                           (reset! teammate-added
                                   (cli/add-recipient! config "dev" bob-public)))
            reencrypt-out (with-out-str (cli/reencrypt! config "dev"))
            all-output (str initial-out set-out teammate-out reencrypt-out)
            sensitive-values
            (into [secret-value]
                  (comp
                   (mapcat #(str/split-lines (slurp %)))
                   (filter #(str/starts-with? % "AGE-SECRET-KEY-")))
                  [*key* bob-key])]
        (testing "set creates the first store and the later add recommends re-encryption"
          (is (.exists (io/file ciphertext)))
          (is (= bob-public @teammate-added))
          (is (str/includes? teammate-out "bb secrets reencrypt dev")))
        (testing "the committed recipient set is exactly Alice and Bob"
          (is (= #{alice-public bob-public}
                 (->> (slurp recipients)
                      str/split-lines
                      (remove str/blank?)
                      set))))
        (testing "both private identities decrypt the final ciphertext"
          (let [expected {:service/token secret-value}]
            (is (= expected (edn/read-string (age/decrypt *key* ciphertext))))
            (is (= expected (edn/read-string (age/decrypt bob-key ciphertext))))))
        (testing "captured command output contains no secret values or private identities"
          (doseq [sensitive-value sensitive-values]
            (is (not (str/includes? all-output sensitive-value)))))))))

(deftest add-recipient-preserves-comments-and-layout-test
  (let [recipients (str *dir* "/recipients.txt")
        original (str "# Team recipients — keep sorted by name\n"
                      "\n"
                      "# Kira (laptop)\n"
                      "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\n"
                      "\n"
                      "# Bot (CI)\n"
                      "age1wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww\n")
        newkey "age1eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        config (cli/normalize-config (test-config {:recipients-file recipients}))]
    (spit recipients original)
    (with-out-str (cli/add-recipient! config "dev" newkey))
    (let [after (slurp recipients)]
      (testing "the existing bytes are left exactly as they were"
        (is (= original (subs after 0 (count original)))))
      (testing "and the new key is appended"
        (is (= (str original newkey "\n") after)))
      (testing "so comments survive a round trip"
        (is (re-find #"# Kira \(laptop\)" after))
        (is (re-find #"# Bot \(CI\)" after))))
    (testing "a re-add is a no-op, not a rewrite"
      (let [before (slurp recipients)]
        (with-out-str (cli/add-recipient! config "dev" newkey))
        (is (= before (slurp recipients)))))
    (testing "a file with no trailing newline still gets a separated key"
      (let [f (str *dir* "/nonl.txt")
            c (cli/normalize-config (test-config {:recipients-file f}))]
        (spit f "# lead\nage1rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr")
        (with-out-str (cli/add-recipient! c "dev" newkey))
        (is (= (str "# lead\n"
                    "age1rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr\n"
                    newkey "\n")
               (slurp f)))))
    (testing "a missing recipients file is created without a leading blank line"
      (let [f (str *dir* "/fresh/recipients.txt")
            c (cli/normalize-config (test-config {:recipients-file f}))]
        (with-out-str (cli/add-recipient! c "dev" newkey))
        (is (= (str newkey "\n") (slurp f)))))))

(deftest blank-artifact-paths-are-rejected-test
  (let [cfg (fn [env-overrides]
              {:app "x" :environments {:dev (merge {:secrets-file "s.age"} env-overrides)}})]
    (testing "every artifact path field rejects a blank string"
      (doseq [[field overrides]
              [[:secrets-file {:secrets-file "" :template "t" :manifest "m"}]
               [:key-file {:key-file ""}]
               [:template {:template ""}]
               [:manifest {:manifest ""}]
               [:recipients-file {:recipients-file ""}]]]
        (let [e (is (thrown-with-msg? clojure.lang.ExceptionInfo
                                      #"blank"
                                      (cli/normalize-config (cfg overrides))))]
          (is (= field (:field (ex-data e))) "the error names the offending field"))))
    (testing "whitespace-only is blank too — it canonicalizes to a directory, not a file"
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"blank"
                            (cli/normalize-config (cfg {:template "   "})))))
    (testing ":manifest false stays supported — the check is about strings, not presence"
      (is (false? (get-in (cli/normalize-config (cfg {:manifest false}))
                          [:environments :dev :manifest]))))
    (testing "ordinary configs are unaffected"
      (let [e (get-in (cli/normalize-config (cfg {})) [:environments :dev])]
        (is (= "s.age" (:secrets-file e)))
        (is (= "s.manifest" (:manifest e)))
        (is (= "s.example" (:template e)))))))

;;;; Recipient snapshotting

(defn- recorded-sh-argvs
  "Every argv `clojure.java.shell/sh` receives while `f` runs, with the real
  subprocesses still running. `f` may throw; the throw is asserted separately."
  [f]
  (let [calls (atom [])
        real-sh shell/sh]
    (with-redefs [shell/sh (fn [& args]
                             (swap! calls conj (vec (take-while string? args)))
                             (apply real-sh args))]
      (try (f) (catch Exception _ nil)))
    @calls))

(defn- age-argvs [argvs]
  (filterv #(= "age" (first %)) argvs))

(defn- fake-recipient
  "A recipient of exactly `n` characters that `age/valid-recipient?` accepts.
  Not a real key: only the pre-subprocess bounds are meant to see it."
  [n filler]
  (str "age1" (apply str (repeat (- n 4) filler))))

(defn- store-through-stdin!
  "Run `set` (the shortest command that encrypts) with its chatter captured."
  [config]
  (with-out-str
    (with-in-str "snapshot-value" (cli/set-secret! config "dev" ":a" false))))

(deftest recipients-are-snapshotted-before-the-editor-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [recipients (str *dir* "/recipients.txt")
          ciphertext (str *dir* "/secrets.edn.age")
          alice-public (age/public-key *key*)
          bob-key (str *dir* "/bob-key.txt")
          bob-public (age/keygen! bob-key)
          config (cli/normalize-config (test-config {:recipients-file recipients}))
          ;; Exactly what a shared-worktree attacker gets: the editor interval,
          ;; during which the configured recipients file is replaced.
          swapping-editor (fn [path]
                            (spit path (pr-str {:a (str (gensym "value"))}))
                            (spit recipients (str bob-public "\n")))]
      (doseq [[label command] [["new" #(cli/new! config "dev")]
                               ["edit" #(cli/edit! config "dev")]]]
        (testing (str label " encrypts to the list validated before the editor ran")
          (spit recipients (str alice-public "\n"))
          (with-out-str
            (with-redefs-fn {(cli-private 'run-editor!) swapping-editor} command))
          (is (= [bob-public] (str/split-lines (slurp recipients)))
              "the swap really happened, so the assertions below are not vacuous")
          (is (map? (edn/read-string (age/decrypt *key* ciphertext)))
              "the snapshotted recipient still decrypts")
          (is (thrown? clojure.lang.ExceptionInfo (age/decrypt bob-key ciphertext))
              "the recipient substituted during the editor interval cannot"))))))

(deftest recipient-limits-fail-closed-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [recipients (str *dir* "/recipients.txt")
          ciphertext (str *dir* "/secrets.edn.age")
          bob-key (str *dir* "/bob-key.txt")
          bob-public (age/keygen! bob-key)
          alice-public (age/public-key *key*)
          limited (fn [limits]
                    (cli/normalize-config
                     (assoc (test-config {:recipients-file recipients}) :limits limits)))]
      (testing "each bound fails closed, naming the limit and its configured value"
        (doseq [[label limits contents pattern]
                [["more entries than :max-recipients"
                  {:max-recipients 2}
                  (str/join "\n" (map #(fake-recipient 24 %) ["q" "r" "s"]))
                  #":max-recipients of 2"]
                 ["an entry longer than :max-recipient-chars"
                  {:max-recipient-chars 32}
                  (fake-recipient 64 "q")
                  #":max-recipient-chars of 32"]
                 ["a file larger than :max-recipients-bytes"
                  {:max-recipients-bytes 16}
                  (fake-recipient 24 "q")
                  #":max-recipients-bytes of 16"]]]
          (testing label
            (spit recipients (str contents "\n"))
            (is (thrown-with-msg? clojure.lang.ExceptionInfo pattern
                                  (store-through-stdin! (limited limits))))
            (is (not (.exists (io/file ciphertext)))
                "a refused recipient list never produces ciphertext"))))
      (testing "a list sitting exactly on every limit encrypts"
        (spit recipients (str alice-public "\n" bob-public "\n"))
        (store-through-stdin!
         (limited {:max-recipients 2
                   :max-recipient-chars (count alice-public)
                   :max-recipients-bytes (.length (io/file recipients))}))
        (let [expected {:a "snapshot-value"}]
          (is (= expected (edn/read-string (age/decrypt *key* ciphertext))))
          (is (= expected (edn/read-string (age/decrypt bob-key ciphertext)))))))))

(deftest malformed-recipients-fail-closed-test
  (let [recipients (str *dir* "/recipients.txt")
        config (cli/normalize-config (test-config {:recipients-file recipients}))
        long-garbage "garbage-with-a-long-tail-that-must-not-be-echoed"]
    (testing "every unusable line fails before encryption"
      (doseq [[label contents pattern]
              [["a garbage line, named by its file line number"
                (str "# team\n\n" long-garbage "\n")
                #"Not a valid age recipient on line 3"]
               ["a truncated age1 key"
                "age1short\n"
                #"Not a valid age recipient on line 1"]
               ["a file holding only comments and blanks"
                "# nobody yet\n\n"
                #"No recipients yet"]]]
        (testing label
          (spit recipients contents)
          (is (thrown-with-msg? clojure.lang.ExceptionInfo pattern
                                (store-through-stdin! config))))))
    (testing "the diagnostic quotes a truncated prefix, never the whole line"
      (spit recipients (str long-garbage "\n"))
      (let [message (ex-message (is (thrown? clojure.lang.ExceptionInfo
                                             (store-through-stdin! config))))]
        (is (str/includes? message "garbage-with-a-l…"))
        (is (not (str/includes? message long-garbage)))))
    (testing "no age subprocess beyond the installation probe ever starts"
      (spit recipients (str long-garbage "\n"))
      (let [argvs (recorded-sh-argvs #(store-through-stdin! config))]
        (is (= [] (remove #{["age" "--version"]} (age-argvs argvs)))
            "nothing was encrypted, decrypted, or handed to age at all")))))

(deftest invalid-limits-config-fails-closed-test
  (testing "resolved limits land on every normalized environment"
    (is (= {:max-recipients 256 :max-recipient-chars 1024 :max-recipients-bytes 262144}
           (get-in (cli/normalize-config (test-config)) [:environments :dev :limits]))))
  (testing "a supplied limit overrides only itself"
    (is (= {:max-recipients 4 :max-recipient-chars 1024 :max-recipients-bytes 262144}
           (get-in (cli/normalize-config (assoc (test-config) :limits {:max-recipients 4}))
                   [:environments :dev :limits]))))
  (testing "a value that is not a positive integer is rejected"
    (doseq [value [0 -1 2.5 "8" nil]]
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"positive integer"
                            (cli/normalize-config
                             (assoc (test-config) :limits {:max-recipients value})))
          (str "limit value " (pr-str value)))))
  (testing "an unknown limit key is rejected rather than silently read as a default"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"unknown key"
                          (cli/normalize-config
                           (assoc (test-config) :limits {:max-recipient 8})))))
  (testing "a :limits value that is not a map is rejected"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #":limits must be a map"
                          (cli/normalize-config (assoc (test-config) :limits [8]))))))

(deftest age-receives-repeated-r-arguments-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [team-list (str *dir* "/team-list.txt")
          bob-key (str *dir* "/bob-key.txt")
          bob-public (age/keygen! bob-key)
          alice-public (age/public-key *key*)
          config (cli/normalize-config (test-config {:recipients-file team-list}))]
      (spit team-list (str "# team\n" alice-public "\n" bob-public "\n"))
      (let [argvs (recorded-sh-argvs #(store-through-stdin! config))
            encrypt-argv (first (filter #(some #{"-e"} %) (age-argvs argvs)))]
        (is (some? encrypt-argv) "an encryption subprocess ran")
        (testing "age gets one -r value per snapshotted recipient, in file order"
          (is (= ["age" "-e" "-r" alice-public "-r" bob-public]
                 (vec (take 6 encrypt-argv))))
          (is (= 2 (count (filter #{"-r"} encrypt-argv)))))
        (testing "and nothing that would make it re-read the list itself"
          (is (not-any? #{"-R"} encrypt-argv))
          (is (not-any? #(str/includes? % "team-list") encrypt-argv)))))))
