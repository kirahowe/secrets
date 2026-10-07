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
            [clojure.test :refer [are deftest is testing use-fixtures]]
            [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.cli :as cli]
            [com.kirahowe.secrets.fs :as fs]
            [com.kirahowe.secrets.manifest :as manifest]
            [com.kirahowe.secrets.test-env :as test-env]))

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

(defn- throwable-diagnostic
  [e]
  (when e
    {:printed (pr-str e)
     :message (ex-message e)
     :data (ex-data e)
     :cause (throwable-diagnostic (ex-cause e))}))

(defn- capture-failure
  [f]
  (let [failure (atom nil)
        out (java.io.StringWriter.)
        err (java.io.StringWriter.)]
    (binding [*out* out *err* err]
      (try
        (f)
        (catch Exception e
          (reset! failure (throwable-diagnostic e)))))
    {:failure @failure :out (str out) :err (str err)}))

(defn- assert-redacted!
  [sentinel diagnostic]
  (is (not (str/includes? (pr-str diagnostic) sentinel))
      "messages, data, causes, stdout, and stderr omit the malformed source"))

(defn- file-bytes [path]
  (vec (java.nio.file.Files/readAllBytes (.toPath (io/file path)))))

(defn- cli-private [sym]
  (ns-resolve 'com.kirahowe.secrets.cli sym))

(defn- with-identity-environment
  "Run `f` with exactly `environment` as the runtime's identity environment.
  This keeps tests independent from an operator's process environment without
  materializing an identity while config is being normalized."
  [environment f]
  (with-redefs-fn (test-env/getenv-redefs environment) f))

(defn- observe-injected-identities
  "Run `f`, recording only temp files allocated for raw/base64 age identities.
  The wrapper delegates the actual owner-only creation to `fs`; it observes no
  plaintext and ignores the CLI's unrelated plaintext scratch files."
  ([f] (observe-injected-identities (atom []) f))
  ([created f]
   (let [real-owner-only-temp-file! fs/owner-only-temp-file!]
     (with-redefs [fs/owner-only-temp-file!
                   (fn [& args]
                     (let [file (apply real-owner-only-temp-file! args)]
                       (when (= "age-identity-" (first args))
                         (swap! created conj (.getAbsolutePath file)))
                       file))]
       {:result (f) :paths @created}))))

(defn- capture-injected-identity-outcome
  "Like `observe-injected-identities`, but retain an operation failure so a
  cleanup failure can be examined without losing the temp path it left behind."
  [f]
  (let [created (atom [])
        real-owner-only-temp-file! fs/owner-only-temp-file!]
    (with-redefs [fs/owner-only-temp-file!
                  (fn [& args]
                    (let [file (apply real-owner-only-temp-file! args)]
                      (when (= "age-identity-" (first args))
                        (swap! created conj (.getAbsolutePath file)))
                      file))]
      (let [outcome (try
                      {:value (f)}
                      (catch Throwable e {:failure e}))]
        (assoc outcome :paths @created)))))

(defn- identity-environment
  "The one identity environment variable represented by `source`, carrying the
  fixture's real private key without ever putting it in an assertion."
  [source]
  (let [identity (slurp *key*)]
    (case source
      :raw {"SECRETS_AGE_IDENTITY" identity}
      :b64 {"SECRETS_AGE_IDENTITY_B64"
            (.encodeToString (java.util.Base64/getEncoder)
                             (.getBytes identity "UTF-8"))})))

(defn- assert-cleaned-identity! [paths]
  (is (= 1 (count paths)) "each operation gets one temporary identity")
  (is (every? #(not (.exists (io/file %))) paths)
      "the operation removes its temporary identity before returning"))

(defn- under-default-key-file
  [path f]
  (with-redefs-fn {#'secrets/default-key-file (constantly path)} f))

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
  [config env-arg {:keys [environment version] :as opts}]
  (with-redefs-fn {(cli-private 'getenv) (or environment {})
                   #'secrets/default-key-file (fn [_] *key*)
                   #'age/version (fn [] (if (contains? opts :version)
                                          version
                                          "age test-version"))}
    #(with-identity-environment (or environment {})
       (fn [] (capture-doctor config env-arg)))))

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
    (is (nil? (:identity-file env))
        "normalization leaves fallback identity resolution to the operation")))

(deftest normalize-config-explicit-values-respected-test
  (let [cfg (cli/normalize-config
             {:app "myapp"
              :environments {:dev {:secrets-file "s.edn.age"
                                   :template "tpl.edn"
                                   :manifest false}}})
        env (get-in cfg [:environments :dev])]
    (is (= "tpl.edn" (:template env)))
    (is (false? (:manifest env)) ":manifest false survives normalization")))

(deftest normalize-config-does-not-materialize-or-resolve-injected-identities-test
  (doseq [source [:raw :b64]]
    (testing (name source)
      (let [{:keys [result paths]}
            (observe-injected-identities
             #(with-identity-environment (identity-environment source)
                (fn [] (cli/normalize-config (test-config)))))]
        (is (nil? (get-in result [:environments :dev :identity-file])))
        (is (empty? paths)
            "resolving config neither reads injected contents nor writes a temp file")))))

(deftest explicit-cli-identity-wins-over-every-injected-environment-source-test
  (let [config (cli/normalize-config (test-config {:identity-file *key*}))]
    (doseq [environment [{"SECRETS_AGE_IDENTITY_FILE" (str *dir* "/not-a-key")}
                         {"SECRETS_AGE_IDENTITY" "not the fixture identity"}
                         {"SECRETS_AGE_IDENTITY_B64" "bm90IHRoZSBmaXh0dXJlIGlkZW50aXR5"}]]
      (let [{:keys [paths]}
            (observe-injected-identities
             #(with-identity-environment environment
                (fn []
                  (with-out-str
                    (with-in-str "chosen-explicitly"
                      (cli/set-secret! config "dev" ":identity/precedence" false))))))]
        (is (empty? paths) "an explicit path is caller-owned and needs no temp file")
        (is (= {:identity/precedence "chosen-explicitly"}
               (edn/read-string (age/decrypt *key* (str *dir* "/secrets.edn.age")))))))))

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
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"incompatible artifact roles"
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
          (is (thrown-with-msg? clojure.lang.ExceptionInfo #"incompatible artifact roles"
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
        b64-value (.encodeToString (java.util.Base64/getEncoder)
                                   (.getBytes "B64-IDENTITY-SENTINEL" "UTF-8"))
        file-value (str *dir* "/FILE-IDENTITY-SENTINEL")
        _ (spit file-value "identity fixture")
        base (test-config)
        configured-key (str *dir* "/configured-key.txt")
        _ (io/copy (io/file *key*) (io/file configured-key))
        specs [{:source :secrets-age-identity-file
                :label "SECRETS_AGE_IDENTITY_FILE"
                :environment {"SECRETS_AGE_IDENTITY_FILE" file-value}
                :identity-path file-value
                :sentinels [file-value]}
               {:source :secrets-age-identity
                :label "SECRETS_AGE_IDENTITY"
                :environment {"SECRETS_AGE_IDENTITY" raw-value}
                :sentinels [raw-value]}
               {:source :secrets-age-identity-b64
                :label "SECRETS_AGE_IDENTITY_B64"
                :environment {"SECRETS_AGE_IDENTITY_B64" b64-value}
                :sentinels [b64-value]}
               {:source :identity-file
                :label ":identity-file"
                :config (test-config {:identity-file *key*})}
               {:source :configured-key-file
                :label "configured key path"
                :config (test-config {:key-file configured-key})}
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

(deftest safe-edn-failure-rendering-test
  (let [render (cli-private 'edn-failure-message)]
    (is (= "malformed EDN syntax at line 7, column 11"
           (render {:reason :edn-malformed :line 7 :column 11})))
    (is (= "expected one EDN value, found empty input"
           (render {:reason :edn-empty})))
    (is (= "expected one EDN value, found another"
           (render {:reason :edn-extra-values})))
    (is (= "EDN nesting depth 101 exceeds the limit of 100"
           (render {:reason :edn-too-deep :depth 101 :limit 100})))))

(deftest cli-depth-bomb-is-rejected-before-recursive-parse-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [bomb (apply str (repeat 200000 \[))
          config (cli/normalize-config (test-config))
          e (try
              (with-out-str
                (with-in-str bomb
                  (cli/set-secret! config "dev" ":bomb" true)))
              (catch clojure.lang.ExceptionInfo e e))]
      (is (= :edn-too-deep (:reason (ex-data e))))
      (is (= 100 (:limit (ex-data e))))
      (is (= 200000 (:depth (ex-data e))))
      (is (not (.exists (io/file (str *dir* "/secrets.edn.age"))))))))

(deftest secret-bearing-edn-failures-are-redacted-across-cli-routes-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [sentinel "123SENTINELSECRET"
          malformed sentinel
          config (cli/normalize-config (test-config))
          encrypted (str *dir* "/secrets.edn.age")
          manifest-path (str *dir* "/secrets.edn.manifest")]
      (testing "editor plaintext"
        (let [captured
              (with-redefs-fn
                {(cli-private 'run-editor!) (fn [path] (spit path malformed))}
                (fn [] (capture-failure (fn [] (cli/new! config "dev")))))]
          (is (= :edn-malformed (get-in captured [:failure :data :reason])))
          (is (nil? (get-in captured [:failure :cause])))
          (assert-redacted! sentinel captured)))
      (testing "stdin --edn"
        (let [captured
              (capture-failure
               (fn []
                 (with-in-str malformed
                   (cli/set-secret! config "dev" ":secret/value" true))))]
          (is (= :edn-malformed (get-in captured [:failure :data :reason])))
          (is (nil? (get-in captured [:failure :cause])))
          (assert-redacted! sentinel captured)))
      (testing "malformed key EDN"
        (let [captured
              (capture-failure
               (fn []
                 (with-in-str "unused"
                   (cli/set-secret! config "dev" malformed false))))]
          (is (= :edn-malformed (get-in captured [:failure :data :reason])))
          (assert-redacted! sentinel captured)))
      (testing "an existing decrypted store"
        (let [plain (str *dir* "/malformed.edn")]
          (spit plain malformed)
          (age/encrypt-file! *key* plain encrypted)
          (.delete (io/file plain)))
        (let [captured
              (capture-failure
               (fn []
                 (with-in-str "replacement"
                   (cli/set-secret! config "dev" ":secret/value" false))))]
          (is (= :edn-malformed (get-in captured [:failure :data :reason])))
          (is (nil? (get-in captured [:failure :cause])))
          (assert-redacted! sentinel captured)))
      (testing "manifest verification"
        (spit manifest-path malformed)
        (let [{:keys [result err] :as captured} (capture-verify config "dev")]
          (is (= :drift (get-in result [:results :dev])))
          (is (str/includes? err "malformed EDN syntax"))
          (assert-redacted! sentinel captured)))
      (testing "doctor manifest diagnostics"
        (let [doctor-config (complete-doctor-config)]
          (spit manifest-path malformed)
          (let [{:keys [result] :as captured}
                (doctor-under doctor-config nil {})]
            (is (= :invalid (get-in result [:verify :state])))
            (assert-redacted! sentinel captured)))))))

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

(defn- mode
  "POSIX permission names of `path`."
  [path]
  (set (map str (java.nio.file.Files/getPosixFilePermissions
                 (.toPath (io/file path))
                 (into-array java.nio.file.LinkOption [])))))

(deftest public-artifacts-get-ordinary-permissions-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [recipients (str *dir* "/recipients.txt")
          config (cli/normalize-config (test-config {:recipients-file recipients}))
          encrypted (str *dir* "/secrets.edn.age")
          manifest-path (str *dir* "/secrets.edn.manifest")
          ordinary (str *dir* "/ordinary.txt")
          _ (spit ordinary "an ordinary file")
          default-mode (mode ordinary)]
      (is (contains? default-mode "OTHERS_READ")
          "the test needs a umask that lets others read an ordinary file")
      (with-out-str (cli/add-recipient! config "dev" nil))
      (with-out-str (with-in-str "v" (cli/set-secret! config "dev" ":k" false)))
      (testing "a new store, manifest, and recipients file have default permissions"
        (doseq [path [encrypted manifest-path recipients]]
          (is (= default-mode (mode path)) path)))
      (testing "replacing an owner-only artifact gives the replacement default permissions"
        (doseq [path [encrypted manifest-path recipients]]
          (java.nio.file.Files/setPosixFilePermissions
           (.toPath (io/file path))
           (java.nio.file.attribute.PosixFilePermissions/fromString "rw-------")))
        (with-out-str (cli/add-recipient! config "dev" (age/keygen! (str *dir* "/bob.txt"))))
        (with-out-str (cli/reencrypt! config "dev"))
        (doseq [path [encrypted manifest-path recipients]]
          (is (= default-mode (mode path)) path)))
      (testing "no staging file remains beside them"
        (is (= ["bob.txt" "key.txt" "ordinary.txt" "recipients.txt"
                "secrets.edn.age" "secrets.edn.manifest"]
               (sort (.list (io/file *dir*)))))))))

;;;; Re-encrypt and verify

(deftest injected-cli-identities-live-for-one-real-command-test
  (doseq [source [:raw :b64]]
    (testing (name source)
      (let [config (cli/normalize-config (test-config))
            env (identity-environment source)
            ciphertext (str *dir* "/secrets.edn.age")]
        (encrypt-edn! {:value "before"})
        (doseq [[label invoke]
                [["set"
                  #(with-in-str "after-set"
                     (cli/set-secret! config "dev" ":value" false))]
                 ["edit"
                  #(with-redefs-fn {(cli-private 'run-editor!)
                                    (fn [path] (spit path "{:value \"after-edit\"}"))}
                     (fn [] (cli/edit! config "dev")))]
                 ["reencrypt" #(cli/reencrypt! config "dev")]
                 ["verify" #(verify config "dev")]]]
          (let [{:keys [result paths]}
                (observe-injected-identities
                 #(with-identity-environment env
                    (fn [] (with-out-str (invoke)))))]
            (is (some? result) (str label " completes with an injected identity"))
            (assert-cleaned-identity! paths)))
        (is (= {:value "after-edit"}
               (edn/read-string (age/decrypt *key* ciphertext))))))))

(deftest injected-cli-identity-remains-through-manifest-hashing-test
  (let [value {:database/url "jdbc:test" :service/token "manifest-value"}
        expected-config (cli/normalize-config (test-config {:identity-file *key*}))
        actual-config (cli/normalize-config (test-config))
        manifest-path (str *dir* "/secrets.edn.manifest")]
    (encrypt-edn! value)
    (with-out-str (cli/reencrypt! expected-config "dev"))
    (let [expected-keys (:keys (edn/read-string (slurp manifest-path)))]
      (encrypt-edn! value)
      (let [present-during-hash? (atom false)
            created (atom [])
            real-hmac-key manifest/hmac-key
            hash-with-live-identity
            (fn [identity]
              (reset! present-during-hash?
                      (and (seq @created)
                           (every? #(.exists (io/file %)) @created)))
              (real-hmac-key identity))
            {:keys [paths]}
            (observe-injected-identities
             created
             #(with-identity-environment (identity-environment :raw)
                (fn []
                  (with-redefs [manifest/hmac-key hash-with-live-identity]
                    (with-out-str (cli/reencrypt! actual-config "dev"))))))]
        (is @present-during-hash?
            "the identity temp file exists while the manifest HMAC is derived")
        (is (= expected-keys (:keys (edn/read-string (slurp manifest-path))))
            "an operation-scoped raw identity produces the same keyed manifest entries")
        (assert-cleaned-identity! paths)))))

(deftest caller-owned-cli-identity-files-survive-operations-test
  (let [ciphertext (str *dir* "/secrets.edn.age")
        explicit (cli/normalize-config (test-config {:identity-file *key*}))
        from-environment (cli/normalize-config (test-config))]
    (encrypt-edn! {:caller-owned true})
    (doseq [[label config environment]
            [["explicit :identity-file" explicit {"SECRETS_AGE_IDENTITY" "wrong"}]
             ["SECRETS_AGE_IDENTITY_FILE" from-environment
              {"SECRETS_AGE_IDENTITY_FILE" *key*}]]]
      (let [{:keys [paths]}
            (observe-injected-identities
             #(with-identity-environment environment
                (fn [] (with-out-str (cli/reencrypt! config "dev")))))]
        (is (.exists (io/file *key*)) (str label " leaves the caller's key file alone"))
        (is (empty? paths) (str label " does not materialize a copy"))))
    (is (= {:caller-owned true}
           (edn/read-string (age/decrypt *key* ciphertext))))))

(deftest failed-cli-operation-cleans-its-injected-identity-test
  (doseq [source [:raw :b64]]
    (let [config (cli/normalize-config (test-config))
          {:keys [failure paths]}
          (capture-injected-identity-outcome
           #(with-identity-environment (identity-environment source)
              (fn [] (with-out-str (cli/reencrypt! config "dev")))))]
      (is (instance? clojure.lang.ExceptionInfo failure))
      (is (str/includes? (ex-message failure) "No secrets file"))
      (assert-cleaned-identity! paths))))

(defn- failing-delete-of
  "A `with-redefs-fn` map under which deleting a private temp file whose name
  starts with `prefix` fails, and every other delete behaves normally."
  [prefix]
  (let [real @#'fs/try-delete!]
    {#'fs/try-delete! (fn [^java.io.File file]
                        (if (str/starts-with? (.getName file) prefix)
                          false
                          (real file)))}))

(deftest cleanup-failure-is-actionable-after-cli-success-or-failure-test
  (let [config (cli/normalize-config (test-config))
        failure-config (cli/normalize-config
                        (test-config {:secrets-file (str *dir* "/missing.age")}))
        environment (identity-environment :raw)
        success
        (capture-injected-identity-outcome
         #(with-identity-environment environment
            (fn []
              (with-redefs-fn (failing-delete-of "age-identity-")
                (fn []
                  (with-out-str
                    (with-in-str "written-before-cleanup-failure"
                      (cli/set-secret! config "dev" ":cleanup/test" false))))))))
        success-error (:failure success)
        remaining (first (:paths success))
        rendered (str/join " " (mapcat rest ((cli-private 'error-lines) success-error)))
        failure
        (capture-injected-identity-outcome
         #(with-identity-environment environment
            (fn []
              (with-redefs-fn (failing-delete-of "age-identity-")
                (fn [] (with-out-str (cli/reencrypt! failure-config "dev")))))))]
    (is (= :private-file-remains (:reason (ex-data success-error))))
    (is (.exists (io/file (str *dir* "/secrets.edn.age")))
        "the command committed its ciphertext before cleanup reported failure")
    (is (and remaining (.exists (io/file remaining)))
        "a failed cleanup leaves a concrete file for the operator to remove")
    (is (str/includes? rendered remaining))
    (is (not (str/includes? rendered (slurp *key*)))
        "the remediation reports only the temp path, never identity contents")
    (is (= (first (:paths failure)) (:remaining-file (ex-data (:failure failure)))))
    (is (str/includes? (ex-message (:failure failure)) "No secrets file"))
    (is (str/includes? (ex-message (:failure failure)) (first (:paths failure)))
        "the operation's own failure also names the remaining file")
    (doseq [path (:paths failure)]
      (when (.exists (io/file path)) (.delete (io/file path))))
    (when (.exists (io/file remaining)) (.delete (io/file remaining)))))

(deftest plaintext-temp-file-is-deleted-plainly-and-a-failure-is-reported-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          tmpdir (io/file (System/getProperty "java.io.tmpdir"))
          plaintext-temps #(set (filter (fn [n] (re-matches #"secrets-.*\.edn" n))
                                        (seq (.list tmpdir))))
          before (plaintext-temps)
          subprocesses (atom [])
          real-sh shell/sh]
      (testing "a successful command leaves no plaintext file and shells out to no eraser"
        (with-redefs [shell/sh (fn [& args]
                                 (swap! subprocesses conj (first args))
                                 (apply real-sh args))]
          (with-out-str (with-in-str "v" (cli/set-secret! config "dev" ":k" false))))
        (is (= before (plaintext-temps)))
        (is (empty? (filter #{"rm" "shred" "sh"} @subprocesses))))
      (testing "a failed delete after success is an error naming the plaintext file"
        (let [e (with-redefs-fn (failing-delete-of "secrets-")
                  #(try
                     (with-out-str (with-in-str "v2" (cli/set-secret! config "dev" ":k" false)))
                     nil
                     (catch clojure.lang.ExceptionInfo e e)))
              remaining (:remaining-file (ex-data e))]
          (try
            (is (= :private-file-remains (:reason (ex-data e))))
            (is (contains? (plaintext-temps) (.getName (io/file remaining))))
            (is (str/includes? (ex-message e) remaining))
            (is (= "v2" (:k (edn/read-string (age/decrypt *key* (str *dir* "/secrets.edn.age")))))
                "the store was written before the cleanup failure was reported")
            (finally
              (some-> remaining io/file .delete))))))))

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

(deftest wrong-app-manifest-is-rejected-test
  ;; The wrong-app half of the authenticity contract. `:app` is the one field a
  ;; manifest records about *which store* it describes, so a manifest belonging
  ;; to another project must be refused rather than diffed as a shape. It
  ;; matters most in team mode, where there are no :vhashes to disagree: a
  ;; foreign structure-only manifest with a refreshed :ciphertext-sha would
  ;; otherwise verify clean.
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          manifest-path (str *dir* "/secrets.edn.manifest")]
      (encrypt-edn! {:a 1})
      (with-out-str (cli/reencrypt! config "dev"))
      (let [committed (edn/read-string (slurp manifest-path))]
        (is (= "cli-test" (:app committed)) "the CLI records the app it wrote for")
        (testing "a manifest naming another app is drift, not a shape to diff"
          (spit manifest-path (pr-str (assoc committed :app "someone-elses-app")))
          (let [{:keys [results exit]} (verify config "dev")]
            (is (= 1 exit))
            (is (= :drift (:dev results)))))
        (testing "so is a manifest that records no app at all"
          (spit manifest-path (pr-str (dissoc committed :app)))
          (is (= :drift (:dev (:results (verify config "dev"))))))
        (testing "and the honest manifest still verifies"
          (spit manifest-path (pr-str committed))
          (is (= 0 (:exit (verify config "dev")))))))))

(deftest public-recipient-forgery-fails-verification-test
  ;; The single-key half of the README's authenticity contract and threat
  ;; model: a public-recipient holder who replaces the ciphertext cannot
  ;; recompute a :vhash, so a keyed `verify` reports the forgery.
  ;;
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

;; The team half of the same contract, and a *documented boundary* rather than
;; a bug anyone forgot to fix. Multi-recipient mode has no shared private key,
;; so `manifest-hmac-key` is nil and team manifests carry no :vhash at all.
;; A holder of one listed public recipient can therefore encrypt a chosen
;; payload, regenerate the structure-only manifest from it with no key
;; whatsoever, refresh :ciphertext-sha, and pass full verification. Sender
;; authenticity is the repository's job here, not `verify`'s. This test exists
;; so the limitation cannot change silently and so the README's claim is
;; falsifiable: if it starts failing, the tool gained a property the contract
;; says it does not have, and the contract is what needs updating.
(deftest team-mode-manifest-is-not-a-value-integrity-signal-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [recipients (str *dir* "/recipients.txt")
          ciphertext (str *dir* "/secrets.edn.age")
          manifest-path (str *dir* "/secrets.edn.manifest")
          sha256 (cli-private 'sha256)
          config (cli/normalize-config (test-config {:recipients-file recipients}))
          recipient (age/public-key *key*)
          forged-value {:db/url "postgres://attacker.example/app"}
          forged-file (str *dir* "/forged.edn")
          body #(remove (fn [line] (str/includes? line ":ciphertext-sha"))
                        (str/split-lines %))]
      (spit recipients (str recipient "\n"))
      (encrypt-edn! {:db/url "postgres://prod.internal/app"})
      (with-out-str (cli/reencrypt! config "dev"))
      (let [committed (edn/read-string (slurp manifest-path))
            honest-manifest (slurp manifest-path)
            honest-ciphertext (file-bytes ciphertext)]
        (is (not-any? #(contains? % :vhash) (vals (:keys committed)))
            "a team manifest is structure-only: there is no :vhash to forge")
        (is (age/valid-recipient? recipient)
            "the committed public recipient is the attacker's only key material")
        (spit forged-file (pr-str forged-value))
        (age/encrypt-file! {:recipients [recipient]} forged-file ciphertext)
        (.delete (io/file forged-file))
        (spit manifest-path
              (manifest/render {:app "cli-test" :ciphertext-sha (sha256 ciphertext)}
                               (manifest/entries forged-value nil)))
        (testing "the app will now load the attacker's configuration"
          (is (= forged-value (edn/read-string (age/decrypt *key* ciphertext)))))
        (testing "and a same-shape forgery leaves the manifest body untouched"
          (is (= (body honest-manifest) (body (slurp manifest-path)))
              "only :ciphertext-sha moves, so the diff reads as a re-encryption"))
        (testing "so full verification passes — the known boundary"
          (let [{:keys [result out]} (capture-verify config "dev")]
            (is (= 0 (:exit result))
                "expected: nothing in a team manifest binds a value to its shape")
            (is (= :ok (get-in result [:results :dev]))
                "verify reports agreement, which is all it ever claimed")
            (is (str/includes? out "manifest matches"))))
        (testing "but the forgery had to rewrite committed artifacts"
          (is (not= honest-ciphertext (file-bytes ciphertext))
              "the ciphertext is tracked, so replacing it is a repository change")
          (is (not= honest-manifest (slurp manifest-path))
              "and so is refreshing :ciphertext-sha — the reviewable boundary"))))))

(deftest verify-missing-is-exit-2-and-repl-safe-test
  (let [config (cli/normalize-config (test-config))
        {:keys [results exit]} (verify config nil)]
    (is (= 2 exit) "no secrets file yet is missing (2), not drift (1)")
    (is (= :missing (:dev results)))
    (is true "and verify! returned instead of killing the process")))

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

;;;; Editor resolution

(deftest editor-resolution-table-test
  (let [editor-value (cli-private 'editor-value)]
    (are [visual editor expected] (= expected (editor-value visual editor))
      "" "nano" "nano"
      "   " "nano" "nano"
      "\t\n" "nano" "nano"
      "" "" "vim"
      "  " "\t" "vim"
      nil nil "vim"
      "" nil "vim"
      nil "" "vim"
      "code --wait" nil "code --wait"
      "  " "emacsclient -t" "emacsclient -t"
      "vi" "nano" "vi")))

(defn- shell-command-word
  "The word `/bin/sh` would execute for the argv `run-editor!` builds. `set --`
  re-splits the command string exactly as `sh -c` does, with `path` arriving as
  `$1` the way the real invocation passes it, so a command string that expands
  to nothing but `$1` reports the path — which is the defect."
  [argv]
  (let [[_sh _c command _name path] argv]
    (:out (shell/sh "sh" "-c" (str "set -- " command "; printf '%s' \"$1\"")
                    "editor" path))))

(deftest blank-editor-never-makes-the-plaintext-the-command-word-test
  (let [editor-value (cli-private 'editor-value)
        editor-argv (cli-private 'editor-argv)
        plaintext (str *dir* "/plain.edn")]
    (testing "the probe reproduces the defect, so the assertions below are not vacuous"
      (is (= plaintext (shell-command-word (editor-argv "" plaintext)))
          "a blank editor really does make the plaintext the command word"))
    (doseq [[visual editor] [["" ""] ["   " "\t"] ["" nil] [nil "  "] ["" "  "]]]
      (testing (pr-str [visual editor])
        (let [argv (editor-argv (editor-value visual editor) plaintext)]
          (is (= "vim" (shell-command-word argv))
              "the fallback editor is the command word, never the plaintext")
          (is (= plaintext (peek argv))
              "and the plaintext is still the positional argument"))))))

(deftest editor-with-arguments-still-receives-the-path-positionally-test
  (let [run-editor! (cli-private 'run-editor!)
        script (io/file *dir* "recording-editor.sh")
        capture (io/file *dir* "editor-argv.txt")
        plaintext (str *dir* "/plain.edn")]
    (spit plaintext "plaintext")
    (spit script (str "#!/bin/sh\nout=\"$1\"\nshift\n"
                      "for a in \"$@\"; do printf '%s\\n' \"$a\"; done > \"$out\"\n"))
    (is (.setExecutable script true true) "the fixture editor must be executable")
    (with-redefs-fn {(cli-private 'editor)
                     (constantly (str (.getAbsolutePath script)
                                      " "
                                      (.getAbsolutePath capture)
                                      " --wait"))}
      #(run-editor! plaintext))
    (is (= ["--wait" plaintext] (str/split-lines (slurp capture)))
        "the editor keeps its own arguments and the path stays a separate one")))

(deftest edit-leaves-the-store-untouched-when-the-editor-fails-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          encrypted (str *dir* "/secrets.edn.age")
          manifest-path (str *dir* "/secrets.edn.manifest")
          failing (io/file *dir* "failing-editor.sh")]
      (spit failing "#!/bin/sh\nexit 3\n")
      (is (.setExecutable failing true true) "the fixture editor must be executable")
      (encrypt-edn! {:valid true})
      (with-out-str (cli/reencrypt! config "dev"))
      (let [command (.getAbsolutePath failing)
            ciphertext-before (file-bytes encrypted)
            manifest-before (slurp manifest-path)]
        (is (thrown-with-msg?
             clojure.lang.ExceptionInfo
             (re-pattern (str "Editor exited with an error.*"
                              (java.util.regex.Pattern/quote command)))
             (with-out-str
               (with-redefs-fn {(cli-private 'editor) (constantly command)}
                 #(cli/edit! config "dev")))))
        (is (= ciphertext-before (file-bytes encrypted)))
        (is (= manifest-before (slurp manifest-path)))))))

;;;; CLI flag extraction boundary

;;; The same defect as the age boundary above, one layer out: the CLI's own
;;; parser used to strip `--edn` from every command's arguments, so a file
;;; named `--edn` was removed before positional dispatch. `--edn` is `set`'s
;;; flag alone now, and `--` ends the options for every command.

(defn- management-invocation [args]
  (shell/sh "bb" "-cp" "src" "-e"
            (str "(require '[com.kirahowe.secrets.cli :as cli]) "
                 "(cli/run! {:deliberately :invalid} " (pr-str args) ")")))

(defn- management-help [args]
  (let [{:keys [exit out err]} (management-invocation args)]
    (when-not (zero? exit)
      (throw (ex-info "Management help subprocess failed" {:args args :error err})))
    out))

(defn- dispatched
  "Record the exact operands a successful `run!` invocation gives its leaf."
  [config args]
  (let [seen (atom nil)
        record (fn [_config & more] (reset! seen (vec more)) {:exit 0})]
    (with-redefs [cli/keygen! record
                  cli/new! record
                  cli/edit! record
                  cli/set-secret! record
                  cli/remove-secret! record
                  cli/verify! record
                  cli/show-key! record
                  cli/add-recipient! record
                  cli/recipients! record
                  cli/reencrypt! record
                  cli/doctor! record]
      (with-out-str (cli/run! config args)))
    @seen))

(deftest help-aliases-and-command-scoping-test
  (let [empty-help (management-help [])
        long-help (management-help ["--help"])
        short-help (management-help ["-h"])
        help-command (management-help ["help"])]
    (is (= empty-help long-help short-help help-command))
    (is (str/includes? long-help "Usage: bb secrets [options] <command>"))
    (is (str/includes? long-help "help           Show global or command-specific help"))
    (is (str/includes? long-help "Run \"bb secrets <command> --help\"")))
  (let [via-help (management-help ["help" "SET"])
        via-long-flag (management-help ["set" "--help"])
        via-short-flag (management-help ["set" "key" "-h"])]
    (is (= via-help via-long-flag via-short-flag))
    (is (str/starts-with? via-help
                          "Usage: bb secrets set [options] <env-or-key> [<key>]"))
    (is (str/includes? via-help
                       "Parse the value as EDN instead of storing it verbatim as a string")))
  (let [out (management-help ["help" "keygen"])]
    (is (str/starts-with? out "Usage: bb secrets keygen [options] [<env>]"))
    (is (str/includes? out "Generate an age key for an environment"))))

(deftest command-errors-are-rendered-at-the-run-boundary-test
  (let [missing (management-invocation ["set"])
        surplus (management-invocation ["keygen" "dev" "extra"])
        unknown (management-invocation ["wat"])
        terminated-long-help (management-invocation ["help" "--" "--help"])
        terminated-short-help (management-invocation ["help" "--" "-h"])]
    (is (= 1 (:exit missing) (:exit surplus) (:exit unknown)
           (:exit terminated-long-help) (:exit terminated-short-help)))
    (is (str/includes? (:err missing) "Required argument: <env-or-key>"))
    (is (str/includes? (:err surplus) "Unexpected argument: extra"))
    (is (str/includes? (:err unknown) "Unknown command: wat"))
    (testing "the store commands are the whole surface: no general file commands"
      (doseq [command ["encrypt" "decrypt"]]
        (let [{:keys [exit err]} (management-invocation [command "dev" "note.txt"])]
          (is (= 1 exit) command)
          (is (str/includes? err (str "Unknown command: " command)) command))))
    (is (str/includes? (:err terminated-long-help) "Unknown command: --help"))
    (is (str/includes? (:err terminated-short-help) "Unknown command: -h"))))

(deftest help-flags-after-the-terminator-remain-operands-test
  (let [config (test-config)]
    (is (= ["--help"] (dispatched config ["keygen" "--" "--help"])))
    (is (= [nil "--help" false]
           (dispatched config ["set" "--" "--help"])))))

(deftest command-names-are-case-insensitive-test
  (is (= ["prod"] (dispatched (test-config) ["KEYGEN" "prod"]))))

(deftest set-edn-still-works-everywhere-it-did-test
  ;; Every position the dispatch accepts the flag in today: before or after an
  ;; explicit [env], and with [env] omitted. A real EDN value each time, since
  ;; a dropped flag stores the same text as a string and would still "work".
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (test-config)
          encrypted (str *dir* "/secrets.edn.age")
          stored (fn [k] (k (edn/read-string (age/decrypt *key* encrypted))))]
      (doseq [[k args] [[:flag-only-arg ["set" "--edn" ":flag-only-arg"]]
                        [:flag-after-key ["set" ":flag-after-key" "--edn"]]
                        [:flag-before-env ["set" "--edn" "dev" ":flag-before-env"]]
                        [:flag-between ["set" "dev" "--edn" ":flag-between"]]
                        [:flag-after-key-and-env ["set" "dev" ":flag-after-key-and-env" "--edn"]]]]
        (testing (str/join " " args)
          (with-out-str (with-in-str "{:port 5432}" (cli/run! config args)))
          (is (= {:port 5432} (stored k))
              "the value was parsed as EDN, not stored as its text")))
      (testing "the terminator leaves set's own positional arguments alone"
        (with-out-str (with-in-str "plain" (cli/run! config ["set" "dev" "--" ":past-terminator"])))
        (is (= "plain" (stored :past-terminator)))))))

(deftest other-commands-do-not-consume-a-flag-they-do-not-define-test
  (let [config (test-config)]
    (doseq [[args expected note]
            [;; The two cases the issue confirmed.
             [["rm" "--edn"] [nil "--edn"] "rm reads it as the key"]
             [["rm" "dev" "--edn"] ["dev" "--edn"] "rm reads it as the key"]
             [["add-recipient" "--edn"] ["--edn" nil] "add-recipient reads it as [env]"]
             [["add-recipient" "dev" "--edn"] ["dev" "--edn"] "add-recipient reads it as [key]"]
             [["keygen" "--edn"] ["--edn"] "single-argument commands read it as [env]"]
             [["new" "--edn"] ["--edn"] "single-argument commands read it as [env]"]
             [["edit" "--edn"] ["--edn"] "single-argument commands read it as [env]"]
             [["verify" "--edn"] ["--edn"] "single-argument commands read it as [env]"]
             [["show-key" "--edn"] ["--edn"] "single-argument commands read it as [env]"]
             [["recipients" "--edn"] ["--edn"] "single-argument commands read it as [env]"]
             [["reencrypt" "--edn"] ["--edn"] "single-argument commands read it as [env]"]
             [["doctor" "--edn"] ["--edn"] "doctor dispatches before normalization"]
             ;; [env] positional and optional, unchanged.
             [["keygen"] [nil] "an omitted [env] is still nil at the boundary"]
             [["keygen" "dev"] ["dev"] "an explicit [env] is still positional"]
             ;; The terminator is consumed by every command, not passed on.
             [["rm" "--" "--edn"] [nil "--edn"] "terminated, with [env] omitted"]
             [["rm" "dev" "--" "--edn"] ["dev" "--edn"] "terminated, [env] given"]
             [["keygen" "--" "dev"] ["dev"] "terminated single-argument command"]]]
      (testing (str (str/join " " args) " — " note)
        (is (= expected (dispatched config args)))))))

(deftest default-environment-still-resolves-without-env-test
  ;; What the original global extraction was protecting: [env] is positional
  ;; and optional, and omitting it selects the default. Proved by effect rather
  ;; than by the dispatched argument — the same command with and without the
  ;; environment name has to agree.
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (test-config)]
      (testing "recipients resolves the default environment by name"
        (let [omitted (with-out-str (cli/run! config ["recipients"]))]
          (is (= (with-out-str (cli/run! config ["recipients" "dev"])) omitted))
          (is (str/includes? omitted "dev"))))
      (testing "set writes the default environment's store"
        (with-out-str (with-in-str "v" (cli/run! config ["set" ":default-env"])))
        (let [store (str *dir* "/secrets.edn.age")]
          (is (= "v" (:default-env (edn/read-string (age/decrypt *key* store)))))))
      (testing "verify reports the same result either way"
        (is (= (with-out-str (cli/run! config ["verify" "dev"]))
               (with-out-str (cli/run! config ["verify"]))))))))

;;;; Generated shell commands

;;; The CLI prints copy/paste commands and never runs them, so the defect
;;; issue 020 fixes is what an operator's shell would do with an interpolated
;;; configuration value. These tests hand the emitted text to a real /bin/sh
;;; and look at the argv it produces.

(def ^:private stub-cat-output
  "What the `cat` stub prints, so a recorded flyctl argument is checkable
  without any real key material reaching an assertion."
  "STUB-CAT-OUTPUT")

(defn- posix-sh? []
  (.canExecute (io/file "/bin/sh")))

(defn- sh-word
  "Let a real /bin/sh parse `quoted` as command-line words; return how many
  words it produced and the exact bytes of the first. Bytes rather than a
  decoded string: what matters is what the shell hands the program. The two
  capture paths arrive through the environment, so the script itself
  interpolates nothing but the word under test."
  [quoted]
  (let [argc-file (io/file *dir* "sh-argc")
        word-file (io/file *dir* "sh-word")]
    (doseq [f [argc-file word-file]] (.delete f))
    (let [{:keys [exit err]}
          (shell/sh "/bin/sh" "-c"
                    (str "set -- " quoted "\n"
                         "printf %s \"$#\" > \"$ARGC_FILE\"\n"
                         "printf %s \"$1\" > \"$WORD_FILE\"\n")
                    :env {"PATH" "/usr/bin:/bin"
                          "ARGC_FILE" (.getPath argc-file)
                          "WORD_FILE" (.getPath word-file)})]
      {:exit exit
       :err err
       :argc (when (.exists argc-file) (slurp argc-file))
       :bytes (when (.exists word-file) (file-bytes (.getPath word-file)))})))

(defn- write-stub!
  "An executable `stub-name` in `dir` that appends its own argv to $STUB_LOG,
  prints `stdout-text`, and creates nothing."
  [dir stub-name stdout-text]
  (let [f (io/file dir stub-name)]
    (spit f (str "#!/bin/sh\n"
                 "{ printf 'CMD %s\\n' \"$0\"\n"
                 "  for a in \"$@\"; do printf 'ARG %s\\n' \"$a\"; done\n"
                 "  printf 'END\\n'\n"
                 "} >> \"$STUB_LOG\"\n"
                 "printf %s " (pr-str stdout-text) "\n"))
    (when-not (.setExecutable f true true)
      (throw (ex-info "stub is not executable" {:stub stub-name})))
    f))

(defn- stub-invocations
  "The argv of every stub invocation recorded in `log`, in order, with each
  command reduced to its basename. One log line per argv element, so values
  carrying newlines are out of scope here — those are what
  `shell-quote-round-trips-adversarial-values-test` covers."
  [log]
  (->> (str/split-lines (slurp (io/file log)))
       (partition-by #(= "END" %))
       (remove #(= ["END"] %))
       (mapv (fn [[cmd & args]]
               (into [(last (str/split (subs cmd 4) #"/"))]
                     (map #(subs % 4))
                     args)))))

(defn- emitted-snippets
  "Every shell command the CLI printed in `guidance`, in emission order."
  [guidance]
  (into []
        (comp (map str/trim)
              (filter #(re-find #"^(flyctl|bb secrets|printf) " %)))
        (str/split-lines guidance)))

(defn- run-snippet
  "Run one emitted snippet in `dir` with `stub-dir` first on PATH, so no real
  bb or flyctl can be reached."
  [snippet {:keys [dir stub-dir log]}]
  (shell/sh "/bin/sh" "-c" snippet
            :dir dir
            :env {"PATH" (str stub-dir ":/usr/bin:/bin") "STUB_LOG" log}))

(deftest shell-quote-round-trips-adversarial-values-test
  (if-not (posix-sh?)
    (is true "skipped: no executable /bin/sh")
    (let [shell-quote (cli-private 'shell-quote)]
      (doseq [[label value]
              [["a space" "two words"]
               ["a single quote" "it's"]
               ["nothing but single quotes" "'''"]
               ["a double quote" "say \"hi\""]
               ["a newline" "first\nsecond"]
               ["a leading dash" "-n"]
               ["a long option" "--help"]
               ["a command substitution" "$(id)"]
               ["backticks" "`id`"]
               ["a variable reference" "$HOME"]
               ["a separator" "a;b"]
               ["an and-list" "a&&b"]
               ["a pipe" "a|b"]
               ["a redirect" "a>b"]
               ["a glob star" "*"]
               ["a glob question mark" "?"]
               ["a tilde" "~"]
               ["history expansion" "!"]
               ["a comment marker" "a#b"]
               ["a backslash" "a\\b"]
               ["a quote-escape payload" "';touch sentinel;'"]
               ["utf-8" "clé δοκιμή 🔐"]
               ["the empty string" ""]]]
        (let [{:keys [exit err argc bytes]} (sh-word (shell-quote value))]
          (is (zero? exit) (str label ": the shell parsed the word (" err ")"))
          (is (= "1" argc) (str label ": exactly one argument"))
          (is (= (vec (.getBytes value "UTF-8")) bytes)
              (str label ": the argument's bytes are the original's")))))))

(deftest generated-commands-execute-as-one-argument-test
  (if-not (posix-sh?)
    (is true "skipped: no executable /bin/sh")
    (doseq [[i [label environment-name key-name]]
            (map-indexed vector
                         [["a separator"
                           (keyword "dev; touch pwned-env")
                           "key.txt; touch pwned-key"]
                          ["a command substitution"
                           (keyword "dev$(touch pwned-env)")
                           "key$(touch pwned-key).txt"]
                          ["a quote and a space"
                           (keyword "dev' ; touch pwned-env #")
                           "key' ; touch pwned-key .txt"]])]
      (let [case-dir (doto (io/file *dir* (str "case-" i)) .mkdirs)
            run-dir (doto (io/file case-dir "run") .mkdirs)
            stub-dir (doto (io/file case-dir "stubs") .mkdirs)
            log (.getPath (io/file case-dir "argv.log"))
            key-file (.getPath (io/file case-dir key-name))
            environment-label (name environment-name)
            config (cli/normalize-config
                    {:app "cli-test"
                     :default-environment environment-name
                     :environments
                     {environment-name
                      {:secrets-file (.getPath (io/file case-dir "secrets.edn.age"))
                       :key-file key-file
                       :recipients-file (.getPath (io/file case-dir "recipients.txt"))}}})]
        (doseq [stub ["bb" "flyctl"]] (write-stub! stub-dir stub ""))
        (write-stub! stub-dir "cat" stub-cat-output)
        (let [guidance (str (with-out-str (cli/keygen! config nil))
                            (with-out-str (cli/add-recipient! config nil nil)))
              snippets (emitted-snippets guidance)
              runs (mapv #(run-snippet % {:dir run-dir
                                          :stub-dir (.getPath stub-dir)
                                          :log log})
                         snippets)]
          (is (= 4 (count snippets)) (str label ": every snippet was emitted"))
          (is (= [0 0 0 0] (mapv :exit runs))
              (str label ": each snippet parsed and ran"))
          (is (= [["cat" "--" key-file]
                  ["flyctl" "secrets" "set"
                   (str "SECRETS_AGE_IDENTITY=" stub-cat-output)]
                  ["bb" "secrets" "add-recipient" environment-label]
                  ["bb" "secrets" "set" environment-label ":secret/key"]
                  ["bb" "secrets" "new" environment-label]]
                 (stub-invocations log))
              (str label ": exactly the intended argv ran, and nothing else"))
          (is (empty? (filter #(str/starts-with? % "pwned")
                              (concat (.list run-dir) (.list case-dir))))
              (str label ": no sentinel file was created")))))))

(deftest key-file-named-like-an-option-is-read-as-a-path-test
  (if-not (posix-sh?)
    (is true "skipped: no executable /bin/sh")
    (doseq [[i entry-name] (map-indexed vector ["-n" "--help"])]
      (with-cwd-entry entry-name
        (fn [_]
          (let [case-dir (doto (io/file *dir* (str "option-" i)) .mkdirs)
                stub-dir (doto (io/file case-dir "stubs") .mkdirs)
                log (.getPath (io/file case-dir "argv.log"))
                marker "KEY-FILE-CONTENTS"
                config (cli/normalize-config
                        {:app "cli-test"
                         :default-environment :dev
                         :environments
                         {:dev {:secrets-file (.getPath
                                               (io/file case-dir "secrets.edn.age"))
                                :key-file entry-name}}})
                snippet (first (emitted-snippets
                                (with-out-str (cli/keygen! config nil))))]
            ;; Real cat, stub flyctl: the generated key is replaced by a marker
            ;; because the question is only whether cat resolved a dash-leading
            ;; name as a pathname, and no key material belongs in an assertion.
            (spit entry-name marker)
            (write-stub! stub-dir "flyctl" "")
            (let [{:keys [exit]} (run-snippet snippet {:dir "."
                                                       :stub-dir (.getPath stub-dir)
                                                       :log log})]
              (is (zero? exit) (str entry-name ": the snippet ran"))
              (is (= [["flyctl" "secrets" "set"
                       (str "SECRETS_AGE_IDENTITY=" marker)]]
                     (stub-invocations log))
                  (str entry-name ": cat read the file, not an option")))))))))

(deftest ordinary-guidance-is-unchanged-in-substance-test
  (let [key-file (.getPath (io/file *dir* "ordinary-key.txt"))
        config (cli/normalize-config
                {:app "cli-test"
                 :default-environment :dev
                 :environments
                 {:dev {:secrets-file (.getPath (io/file *dir* "ordinary.edn.age"))
                        :key-file key-file
                        :recipients-file (.getPath
                                          (io/file *dir* "ordinary-recipients.txt"))}}})
        guidance (str (with-out-str (cli/keygen! config nil))
                      (with-out-str (cli/add-recipient! config nil nil)))]
    (is (= [(str "flyctl secrets set SECRETS_AGE_IDENTITY=\"$(cat -- '" key-file "')\"")
            "bb secrets add-recipient 'dev'"
            "printf %s \"$VALUE\" | bb secrets set 'dev' :secret/key"
            "bb secrets new 'dev'"]
           (emitted-snippets guidance))
        "quoting changed the rendering, not the binary, subcommand, environment, or path")))

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

(deftest set-prompts-on-a-terminal-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          encrypted (str *dir* "/secrets.edn.age")
          prompts (atom [])
          typed (atom nil)
          at-terminal (fn [f]
                        (with-redefs-fn {(cli-private 'tty?) (constantly true)
                                         (cli-private 'prompt-hidden!)
                                         (fn [prompt] (swap! prompts conj prompt) @typed)}
                          f))
          stored #(edn/read-string (age/decrypt *key* encrypted))]
      (testing "a terminal gets a hidden prompt and stdin is left alone"
        (reset! typed "typed-secret")
        (with-out-str
          (with-in-str "piped-and-ignored"
            (at-terminal #(cli/set-secret! config "dev" ":api/key" false))))
        (is (= {:api/key "typed-secret"} (stored)))
        (is (= 1 (count @prompts)))
        (is (str/includes? (first @prompts) ":api/key") "the prompt names the key"))
      (testing "--edn parses the typed line"
        (reset! typed "#{\"a@b.com\"}")
        (with-out-str (at-terminal #(cli/set-secret! config "dev" ":auth/admins" true)))
        (is (= #{"a@b.com"} (:auth/admins (stored)))))
      (testing "a blank line is refused like blank stdin"
        (reset! typed "")
        (is (thrown-with-msg?
             clojure.lang.ExceptionInfo #"(?i)nothing entered"
             (with-out-str (at-terminal #(cli/set-secret! config "dev" ":blank" false))))))
      (testing "end of input at the prompt is refused the same way"
        (reset! typed nil)
        (is (thrown-with-msg?
             clojure.lang.ExceptionInfo #"(?i)nothing entered"
             (with-out-str (at-terminal #(cli/set-secret! config "dev" ":eof" false))))))
      (is (= {:api/key "typed-secret" :auth/admins #{"a@b.com"}} (stored))
          "refused values left the store untouched"))))

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
  (testing "keygen! stages the new key beside the old one and moves it over"
    (let [path (str *dir* "/regen.txt")
          pub1 (age/keygen! path)
          pub2 (age/keygen! path)]
      (is (some? pub1))
      (is (some? pub2))
      (is (not= pub1 pub2) "the second call really did replace the key")
      (is (= pub2 (age/public-key path)) "and the file on disk is the new one")
      (is (= ["regen.txt"]
             (filter #(str/includes? % "regen.txt") (.list (io/file *dir*))))
          "no staging leftovers beside the key"))))

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
        (is (str/includes? initial-out "bb secrets set 'dev'"))
        (is (str/includes? initial-out "bb secrets new 'dev'"))
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
          (is (str/includes? teammate-out "bb secrets reencrypt 'dev'")))
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

(deftest artifact-locators-are-rejected-test
  (let [config (fn [overrides]
                 {:app "x"
                  :environments
                  {:dev (merge {:secrets-file "s.age"} overrides)}})]
    (testing "every configured artifact location is a filesystem path, never a URL"
      (doseq [[field value]
              [[:secrets-file "https://127.0.0.1/store.age"]
               [:key-file "file:/tmp/key.txt"]
               [:template "jar:file:/tmp/app.jar!/template.edn"]
               [:manifest "ftp://example.com/store.manifest"]
               [:recipients-file "http://10.0.0.1/recipients.txt"]]]
        (let [e (is (thrown-with-msg? clojure.lang.ExceptionInfo
                                      #"filesystem path"
                                      (cli/normalize-config
                                       (config {field value}))))]
          (is (= field (:field (ex-data e)))))))
    (testing "credential-bearing locators survive only as allowlisted metadata"
      (let [sentinel "URI-CREDENTIAL-SENTINEL"
            locator (str "HTTPS://user:" sentinel "@127.0.0.1/store.age?sig=" sentinel)
            e (try
                (cli/normalize-config (config {:secrets-file locator}))
                nil
                (catch clojure.lang.ExceptionInfo e e))
            rendered (str (pr-str e) (ex-message e) (pr-str (ex-data e)))]
        (is (= {:environment :dev
                :field :secrets-file
                :reason :disallowed-source-location
                :scheme "https"}
               (select-keys (ex-data e) [:environment :field :reason :scheme])))
        (is (not (str/includes? rendered sentinel)))
        (is (not (contains? (ex-data e) :path)))))
    (testing "whitespace before the scheme does not hide it"
      (let [e (try
                (cli/normalize-config (config {:secrets-file " https://127.0.0.1/store.age"}))
                nil
                (catch clojure.lang.ExceptionInfo e e))]
        (is (= {:reason :disallowed-source-location :scheme "https"}
               (select-keys (ex-data e) [:reason :scheme])))))
    (testing "a Windows drive path is not mistaken for a one-letter scheme"
      (is (= "C:\\secrets\\store.age"
             (get-in (cli/normalize-config
                      (config {:secrets-file "C:\\secrets\\store.age"}))
                     [:environments :dev :secrets-file]))))))

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

(defn- with-bound
  "Run `f` with the private bound constant held by var `v` set to `n`."
  [v n f]
  (with-redefs-fn {v n} f))

(deftest recipients-file-byte-bound-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [recipients (str *dir* "/recipients.txt")
          ciphertext (str *dir* "/secrets.edn.age")
          bob-key (str *dir* "/bob-key.txt")
          bob-public (age/keygen! bob-key)
          alice-public (age/public-key *key*)
          config (cli/normalize-config (test-config {:recipients-file recipients}))]
      (testing "the bound is 256 KiB"
        (is (= 262144 @(cli-private 'max-recipients-bytes))))
      (testing "a file past the byte bound never produces ciphertext"
        (spit recipients (str (fake-recipient 24 "q") "\n"))
        (let [e (with-bound (cli-private 'max-recipients-bytes) 16
                  #(try (store-through-stdin! config)
                        (catch clojure.lang.ExceptionInfo e e)))]
          (is (= :input-too-large (:reason (ex-data e))))
          (is (= 16 (:limit (ex-data e))))
          (is (= (.length (io/file recipients)) (:observed (ex-data e))))
          (is (str/includes? (ex-message e) recipients) "the message names the file"))
        (is (not (.exists (io/file ciphertext)))))
      (testing "a list sitting exactly on the bound encrypts"
        (spit recipients (str alice-public "\n" bob-public "\n"))
        (with-bound (cli-private 'max-recipients-bytes) (.length (io/file recipients))
          #(store-through-stdin! config))
        (let [expected {:a "snapshot-value"}]
          (is (= expected (edn/read-string (age/decrypt *key* ciphertext))))
          (is (= expected (edn/read-string (age/decrypt bob-key ciphertext))))))
      (testing "no count or line-length bound sits beside the byte bound"
        (spit recipients (str/join "\n" (repeat 300 alice-public)))
        (let [listed (atom nil)]
          (with-out-str (reset! listed (cli/recipients! config "dev")))
          (is (= 300 (count @listed))))))))

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

(deftest read-only-recipient-boundaries-test
  (let [recipients-file (str *dir* "/read-only-recipients.txt")
        first-recipient (fake-recipient 24 "q")
        exact-content (str first-recipient "\n")
        config (cli/normalize-config (test-config {:recipients-file recipients-file}))
        bounded (fn [f] (with-bound (cli-private 'max-recipients-bytes) (count exact-content) f))]
    (testing "listing accepts the exact byte bound"
      (spit recipients-file exact-content)
      (let [listed (atom nil)]
        (bounded #(with-out-str (reset! listed (cli/recipients! config "dev"))))
        (is (= [first-recipient] @listed))))
    (testing "listing rejects the first byte over and doctor reports only the bound"
      (let [sentinel "#"]
        (spit recipients-file (str exact-content sentinel))
        (let [e (bounded #(try
                            (with-out-str (cli/recipients! config "dev"))
                            (catch clojure.lang.ExceptionInfo e e)))
              rendered (pr-str (ex-data e))
              doctor (bounded #(:result (doctor-under config "dev" {})))
              state (get-in doctor [:encryption :recipients])]
          (is (= {:reason :input-too-large
                  :limit (count exact-content)
                  :observed (inc (count exact-content))}
                 (select-keys (ex-data e) [:reason :limit :observed])))
          (is (not (str/includes? rendered sentinel)))
          (is (= {:state :bounded
                  :reason :input-too-large
                  :limit (count exact-content)
                  :observed (inc (count exact-content))}
                 state)))))))

(deftest plaintext-file-and-stdin-byte-boundaries-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [plaintext-file (str *dir* "/bounded-plain.edn")
          exact-plaintext (str "{:a 1}" (apply str (repeat 26 " ")))
          limit (count exact-plaintext)
          bounded (fn [n f] (with-bound #'age/max-plaintext-bytes n f))
          config (cli/normalize-config (test-config {:manifest false}))
          env (get-in config [:environments :dev])
          write-secrets! (cli-private 'write-secrets!)
          ciphertext (:secrets-file env)]
      (testing "an editor plaintext at the exact byte bound is accepted"
        (spit plaintext-file exact-plaintext)
        (bounded limit #(write-secrets! env {:identity-file *key*} plaintext-file))
        (is (= {:a 1} (edn/read-string (age/decrypt *key* ciphertext)))))
      (testing "the first byte over is rejected before parsing or encryption"
        (let [sentinel "~"
              before (file-bytes ciphertext)]
          (spit plaintext-file (str exact-plaintext sentinel))
          (let [e (bounded limit #(try
                                    (write-secrets! env {:identity-file *key*} plaintext-file)
                                    (catch clojure.lang.ExceptionInfo e e)))
                rendered (str (ex-message e) (pr-str (ex-data e)))]
            (is (= {:reason :input-too-large :limit limit :observed (inc limit)}
                   (select-keys (ex-data e) [:reason :limit :observed])))
            (is (str/includes? (ex-message e) ciphertext) "the message names the store")
            (is (not (str/includes? rendered sentinel)))
            (is (= before (file-bytes ciphertext))))))
      (testing "stdin accepts exact UTF-8 bytes and rejects one byte over"
        (let [stdin-limit 64
              exact-stdin (str "\"é\"" (apply str (repeat (- stdin-limit 4) " ")))]
          (is (= stdin-limit (alength (.getBytes exact-stdin "UTF-8")))
              "the fixture is at the bound in bytes, not characters")
          (with-out-str
            (with-in-str exact-stdin
              (bounded stdin-limit #(cli/set-secret! config "dev" ":n" true))))
          (is (= "é" (:n (edn/read-string (age/decrypt *key* ciphertext)))))
          (let [e (try
                    (with-out-str
                      (with-in-str (str exact-stdin " ")
                        (bounded stdin-limit #(cli/set-secret! config "dev" ":n" true))))
                    (catch clojure.lang.ExceptionInfo e e))]
            (is (= {:reason :input-too-large :limit stdin-limit :observed (inc stdin-limit)}
                   (select-keys (ex-data e) [:reason :limit :observed])))))))))

(deftest manifest-byte-bound-test
  (let [manifest-file (str *dir* "/bounded.manifest")
        read-supported (cli-private 'read-supported-manifest)
        value {:version 2
               :app "cli-test"
               :keys {[:a] {:type :string}
                      [:b] {:type :integer}}}
        exact-content (pr-str value)
        bounded (fn [f] (with-bound (cli-private 'max-manifest-bytes) (count exact-content) f))]
    (testing "the bound is 1 MiB"
      (is (= 1048576 @(cli-private 'max-manifest-bytes))))
    (testing "a manifest exactly at the byte bound is accepted"
      (spit manifest-file exact-content)
      (is (= value (:committed (bounded #(read-supported "cli-test" manifest-file))))))
    (testing "the first byte over is rejected, naming the file and the bound"
      (spit manifest-file (str exact-content " "))
      (let [e (bounded #(try
                          (read-supported "cli-test" manifest-file)
                          (catch clojure.lang.ExceptionInfo e e)))]
        (is (= {:reason :input-too-large
                :limit (count exact-content)
                :observed (inc (count exact-content))
                :manifest manifest-file}
               (dissoc (ex-data e) :secrets/exit)))
        (is (str/includes? (ex-message e) manifest-file))))))

(deftest verify-reports-a-tripped-bound-per-environment-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config
                  {:app "cli-test"
                   :environments
                   {:dev {:secrets-file (str *dir* "/dev.edn.age") :key-file *key*}
                    :prod {:secrets-file (str *dir* "/prod.edn.age") :key-file *key*}}})
          big-manifest (str *dir* "/dev.edn.manifest")]
      (doseq [env ["dev" "prod"]]
        (with-out-str (with-in-str "v" (cli/set-secret! config env ":k" false))))
      (spit big-manifest (str (slurp big-manifest) (apply str (repeat 4096 " "))))
      (let [{:keys [result err]}
            (with-bound (cli-private 'max-manifest-bytes) 4096
              #(capture-verify config nil))]
        (is (= {:dev :drift :prod :ok} (:results result))
            "the oversized manifest is one environment's problem; the other is verified")
        (is (= 1 (:exit result)))
        (is (str/includes? err big-manifest) "the report names the file")))))

(deftest a-limits-key-configures-nothing-test
  (let [normalized (cli/normalize-config
                    (assoc (test-config) :limits {:max-plaintext-bytes 1}))]
    (is (not (contains? (get-in normalized [:environments :dev]) :limits))
        "environments carry no limits")
    (is (nil? (cli-private 'default-limits)))))

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

;;;; Artifact role collisions
;;; These normalize-config tests live here rather than in the section above
;;; because one of them needs the subprocess recorder defined further up.

(defn- normalize-without-env-identity
  "`normalize-config` is pure with respect to identity environment variables.
  Keep this helper at the call sites that used to need environment neutralizing:
  their purpose is now to describe static artifact collisions only."
  [config]
  (cli/normalize-config config))

(defn- normalize-failure
  "The ex-info `normalize-without-env-identity` throws for `config`, or nil when
  it succeeds."
  [config]
  (try
    (normalize-without-env-identity config)
    nil
    (catch clojure.lang.ExceptionInfo e e)))

(defn- role-collision
  "Assert `config` is rejected as an artifact role collision, and return the
  exception so callers can assert on what it names."
  [config]
  (let [e (normalize-failure config)]
    (is (str/includes? (str (ex-message e)) "incompatible artifact roles")
        (str "rejected as a role collision, got: " (pr-str (ex-message e))))
    e))

(deftest incompatible-artifact-roles-are-rejected-test
  (doseq [[label environments tokens]
          [["the resolved identity equals the manifest in one environment"
            {:dev {:secrets-file "s.age" :manifest "id.txt" :identity-file "id.txt"}}
            [":dev manifest" ":dev identity-file"]]
           ["the resolved identity equals the ciphertext"
            {:dev {:secrets-file "s.age" :identity-file "s.age"}}
            [":dev secrets-file" ":dev identity-file"]]
           ["the resolved identity equals the template"
            {:dev {:secrets-file "s.age" :identity-file "s.example"}}
            [":dev template" ":dev identity-file"]]
           ["dev ciphertext equals the prod key file"
            {:dev {:secrets-file "shared.age" :key-file "dev-key.txt"}
             :prod {:secrets-file "prod.age" :key-file "shared.age"}}
            [":dev secrets-file" ":prod key-file"]]
           ["two environments write one manifest"
            {:dev {:secrets-file "d.age" :manifest "m.edn" :key-file "k.txt"}
             :prod {:secrets-file "p.age" :manifest "m.edn" :key-file "k.txt"}}
            [":dev manifest" ":prod manifest"]]
           ["two environments write one ciphertext"
            {:dev {:secrets-file "s.age" :template "d.example" :manifest "d.manifest"}
             :prod {:secrets-file "s.age" :template "p.example" :manifest "p.manifest"}}
            [":dev secrets-file" ":prod secrets-file"]]
           ["the template equals the ciphertext"
            {:dev {:secrets-file "s.age" :template "s.age"}}
            [":dev secrets-file" ":dev template"]]
           ["the recipients file equals the key file"
            {:dev {:secrets-file "s.age" :key-file "k.txt" :recipients-file "k.txt"}}
            [":dev key-file" ":dev recipients-file"]]]]
    (testing label
      (let [message (str (ex-message (role-collision {:app "x" :environments environments})))]
        (doseq [token tokens]
          (is (str/includes? message token) (str "the diagnostic names " token)))))))

(deftest compatible-artifact-sharing-is-allowed-test
  (let [sharing-environments (cli-private 'sharing-environments)]
    (testing "the app-wide default key file shared by two environments"
      (let [default-key (str *dir* "/home/.config/x/key.txt")
            config (under-default-key-file
                    default-key
                    #(normalize-without-env-identity
                      {:app "x"
                       :environments {:dev {:secrets-file (str *dir* "/dev/s.age")}
                                      :prod {:secrets-file (str *dir* "/prod/s.age")}}}))]
        (is (= [:dev :prod] (sharing-environments (:environments config) default-key))
            "keygen still reports every environment sharing the one key")))
    (testing "an explicit :identity-file equal to the environment's own :key-file"
      (let [env (-> {:app "x"
                     :environments {:dev {:secrets-file "s.age"
                                          :key-file "k.txt"
                                          :identity-file "./k.txt"}}}
                    normalize-without-env-identity
                    (get-in [:environments :dev]))]
        (is (= "./k.txt" (:identity-file env))
            "an explicit identity aliasing the key file is kept, not rejected")))
    (testing "one recipients file shared by two environments"
      (is (nil? (normalize-failure
                 {:app "x"
                  :environments {:dev {:secrets-file "d.age"
                                       :key-file "dev-key.txt"
                                       :recipients-file "team.txt"}
                                 :prod {:secrets-file "p.age"
                                        :key-file "prod-key.txt"
                                        :recipients-file "team.txt"}}}))))
    (testing "one template shared by two environments"
      (is (nil? (normalize-failure
                 {:app "x"
                  :environments {:dev {:secrets-file "d.age" :template "shared.example"}
                                 :prod {:secrets-file "p.age" :template "shared.example"}}}))))))

(deftest canonical-aliases-collide-test
  (testing "a ./x/.. detour resolves to the plain path"
    (role-collision {:app "x"
                     :environments {:dev {:secrets-file "./x/../secrets.edn.age"
                                          :manifest "secrets.edn.age"
                                          :template "t.example"}}}))
  (testing "a trailing slash names the same file"
    (role-collision {:app "x"
                     :environments {:dev {:secrets-file "secrets.edn.age"
                                          :manifest "secrets.edn.age/"
                                          :template "t.example"}}}))
  (testing "a symlink to another environment's key file resolves through it"
    (let [key-file (str *dir* "/real-key.txt")
          link (str *dir* "/linked-secrets.edn.age")]
      (spit key-file "identity fixture")
      (if-not (try
                (java.nio.file.Files/createSymbolicLink
                 (.toPath (io/file link))
                 (.toPath (io/file key-file))
                 (into-array java.nio.file.attribute.FileAttribute []))
                true
                (catch Exception _ false))
        (is true "skipped: this platform does not allow creating a symlink")
        (role-collision {:app "x"
                         :environments {:dev {:secrets-file (str *dir* "/dev.age")
                                              :key-file key-file}
                                        :prod {:secrets-file link
                                               :key-file (str *dir* "/prod-key.txt")}}})))))

(deftest missing-leaf-paths-are-compared-consistently-test
  (testing "neither path exists yet, as in a fresh project"
    (let [missing (str *dir* "/fresh/secrets.edn.age")]
      (is (not (.exists (io/file missing))) "the leaf really is absent")
      (role-collision {:app "x"
                       :environments {:dev {:secrets-file missing
                                            :manifest (str *dir* "/fresh/nested/../secrets.edn.age")
                                            :template (str *dir* "/fresh/t.example")}}})))
  (testing "one existing path and one alias through a directory that does not exist"
    (let [key-file (str *dir* "/existing-key.txt")
          alias-path (str *dir* "/absent/../existing-key.txt")]
      (spit key-file "identity fixture")
      (role-collision {:app "x"
                       :environments {:dev {:secrets-file (str *dir* "/dev.age")
                                            :key-file key-file
                                            :manifest alias-path}}}))))

(deftest role-collision-is-rejected-before-any-filesystem-write-test
  (let [ciphertext (str *dir* "/pre-write/secrets.edn.age")
        identity-file (str *dir* "/pre-write/identity.txt")
        key-file (str *dir* "/pre-write/key.txt")
        config {:app "cli-test"
                :default-environment :dev
                :environments {:dev {:secrets-file ciphertext
                                     :manifest identity-file
                                     :identity-file identity-file
                                     :key-file key-file}}}]
    (doseq [[label command]
            [["keygen" #(cli/keygen! (normalize-without-env-identity config) "dev")]
             ["set" #(cli/set-secret! (normalize-without-env-identity config) "dev" ":a" false)]]]
      (testing label
        (is (thrown-with-msg? clojure.lang.ExceptionInfo #"incompatible artifact roles"
                              (with-out-str (with-in-str "value\n" (command)))))
        (let [argvs (recorded-sh-argvs #(with-out-str (with-in-str "value\n" (command))))]
          (is (= [] (filterv #(some-> (first %) (str/starts-with? "age")) argvs))
              "no age or age-keygen subprocess ran"))
        (doseq [path [ciphertext identity-file key-file]]
          (is (not (.exists (io/file path))) (str path " was not created")))))))

(deftest unresolvable-artifact-path-fails-closed-test
  ;; No portable configured path makes .getCanonicalPath raise, so the
  ;; IOException is injected at the boundary that has to catch it.
  (let [canonical-path (cli-private 'canonical-path)
        real @canonical-path]
    (with-redefs-fn {canonical-path (fn [path]
                                      (if (str/includes? (str path) "unresolvable")
                                        (throw (java.io.IOException. "simulated failure"))
                                        (real path)))}
      #(let [e (normalize-failure
                {:app "x"
                 :environments {:dev {:secrets-file "s.age"
                                      :manifest (str *dir* "/unresolvable/m.edn")}}})]
         (is (str/includes? (str (ex-message e)) "unresolvable manifest path")
             "the diagnostic names the environment's offending role")
         (is (= {:environment :dev :role :manifest}
                (select-keys (ex-data e) [:environment :role])))))))

(deftest injected-identity-cannot-overlap-another-environments-artifact-test
  (let [other (str *dir* "/other.age")
        config (cli/normalize-config
                (assoc-in (test-config) [:environments :prod]
                          {:secrets-file other :key-file *key*}))
        identity (slurp *key*)]
    (spit other identity)
    (with-identity-environment {"SECRETS_AGE_IDENTITY_FILE" other}
      #(is (thrown-with-msg? clojure.lang.ExceptionInfo #"incompatible artifact roles"
                             (with-in-str "value"
                               (cli/set-secret! config "dev" ":test" false)))))
    (is (= identity (slurp other)))
    (is (not (.exists (io/file (str *dir* "/secrets.edn.age")))))))

(deftest doctor-does-not-hide-identity-cleanup-failure-test
  (let [{:keys [failure paths]}
        (capture-injected-identity-outcome
         #(with-identity-environment (identity-environment :raw)
            (fn []
              (with-redefs-fn (failing-delete-of "age-identity-")
                (fn [] (with-out-str (cli/doctor! (complete-doctor-config) "dev")))))))]
    (try
      (is (= :private-file-remains (:reason (ex-data failure))))
      (is (= (first paths) (:remaining-file (ex-data failure))))
      (finally
        (doseq [path paths] (.delete (io/file path)))))))

;;;; Release-hardening checks: cleanup, disclosure, and error paths

(deftest write-secrets-releases-staging-when-a-later-acquisition-fails-test
  (let [plaintext (str *dir* "/plain.edn")
        env (get-in (cli/normalize-config (test-config)) [:environments :dev])
        real-staging-file fs/staging-file
        calls (atom 0)
        leftovers #(->> (.listFiles (io/file *dir*))
                        (map (fn [f] (.getName f)))
                        (filter (fn [n] (str/ends-with? n ".tmp")))
                        vec)]
    (spit plaintext "{:a 1}")
    (with-redefs-fn {#'fs/staging-file
                     (fn [target]
                       (if (= 2 (swap! calls inc))
                         (throw (java.io.IOException. "no space"))
                         (real-staging-file target)))}
      #(is (thrown? java.io.IOException
                    ((cli-private 'write-secrets!) env {:identity-file *key*} plaintext))))
    (is (= 2 @calls) "the manifest staging file was the failing acquisition")
    (is (= [] (leftovers)) "the ciphertext staging file was released")))

(deftest key-file-source-is-derived-and-stable-under-renormalizing-test
  (let [normalized (fn [env-config]
                     (cli/normalize-config
                      {:app "cli-test"
                       :environments {:dev (merge {:secrets-file (str *dir* "/s.age")}
                                                  env-config)}}))
        source #(get-in % [:environments :dev :key-file-source])]
    (testing "a user-supplied :key-file-source is not honoured"
      (is (= :default (source (normalized {:key-file-source :bogus}))))
      (is (= :configured (source (normalized {:key-file-source :bogus
                                              :key-file (str *dir* "/k.txt")})))))
    (testing "normalizing twice changes nothing"
      (doseq [config [(normalized {}) (normalized {:key-file (str *dir* "/k.txt")})]]
        (is (= config (cli/normalize-config config)))))))

(deftest config-failures-carry-no-config-maps-test
  (let [marker "CONFIG-MARKER-9d31"
        failure (fn [config]
                  (try (cli/normalize-config config)
                       (catch clojure.lang.ExceptionInfo e e)))]
    (are [config] (let [e (failure config)]
                    (and (instance? clojure.lang.ExceptionInfo e)
                         (not (str/includes? (pr-str [(ex-message e) (ex-data e)]) marker))))
      {:app "a" :environments {:dev {:note marker}}}
      {:app "a" :note marker :environments {}}
      {:app " " :note marker :environments {:dev {:secrets-file "s.age"}}})))

(deftest doctor-reports-an-identity-variable-error-test
  (let [run (fn [variable value]
              (with-identity-environment
                {variable value}
                #(capture-doctor (cli/normalize-config (test-config)) "dev")))]
    (testing "a blank variable"
      (let [{:keys [result out]} (run "SECRETS_AGE_IDENTITY" "")]
        (is (= 2 (:exit result)))
        (is (str/includes? out "Configuration: invalid"))
        (is (str/includes? out "SECRETS_AGE_IDENTITY is set but empty"))))
    (testing "invalid base64"
      (let [marker "NOT-BASE64-MARKER!!"
            {:keys [result out err]} (run "SECRETS_AGE_IDENTITY_B64" marker)]
        (is (= 2 (:exit result)))
        (is (str/includes? out "SECRETS_AGE_IDENTITY_B64 is not valid base64"))
        (is (not (str/includes? (str out err) marker)))))
    (testing "a valid configuration carries a nil reason"
      (let [{:keys [result]} (doctor-under (test-config) nil {})]
        (is (contains? (:configuration result) :reason))
        (is (nil? (get-in result [:configuration :reason])))))))

(deftest verify-reports-a-malformed-manifest-as-a-finding-test
  (let [config (cli/normalize-config (test-config))
        env (get-in config [:environments :dev])
        keyless-config (cli/normalize-config
                        (test-config {:key-file (str *dir* "/absent-key.txt")}))]
    (encrypt-edn! {:a 1})
    (with-identity-environment
      {}
      (fn []
        (doseq [[label text] [["a top-level list" "(1 2 3)"]
                              ["a wrapped map" "({:version 2 :app \"cli-test\" :keys {}})"]
                              ["a vector" "[1 2]"]
                              ["a number" "5"]
                              ["a string" "\"x\""]
                              ["nil" "nil"]
                              [":keys a vector" "{:version 2 :app \"cli-test\" :keys []}"]
                              [":keys a number" "{:version 2 :app \"cli-test\" :keys 5}"]
                              [":keys nil" "{:version 2 :app \"cli-test\" :keys nil}"]]
                cfg [config keyless-config]]
          (spit (:manifest env) text)
          (let [{:keys [result out err]} (capture-verify cfg "dev")]
            (is (= 1 (:exit result)) label)
            (is (= :drift (get-in result [:results :dev])) label)
            (is (str/includes? (str out err) "manifest is malformed") label)))
        (testing "a manifest with no :keys is not called malformed"
          (spit (:manifest env) "{:version 2 :app \"cli-test\"}")
          (let [{:keys [out err]} (capture-verify config "dev")]
            (is (not (str/includes? (str out err) "malformed")))))))))

(deftest set-never-echoes-a-misplaced-value-test
  (let [marker "hunter2-MARKER"
        config (test-config)
        dispatch! (cli-private 'dispatch!)
        refused (fn [argv]
                  (let [{:keys [failure] :as captured}
                        (capture-failure #(dispatch! config argv))]
                    (is (some? failure) (pr-str argv))
                    (assert-redacted! marker captured)
                    failure))]
    (testing "surplus operands and option-shaped operands"
      (doseq [argv [["set" "dev" ":db/pw" marker]
                    ["set" "dev" ":db/pw" marker marker]
                    ["set" "--edn" "dev" ":db/pw" marker]
                    ["set" "dev" "--edn" ":db/pw" marker]
                    ["set" "dev" ":db/pw" "--" marker]
                    ["set" "dev" ":db/pw" "--value" marker]
                    ["set" "dev" ":db/pw" (str "--value=" marker)]]]
        (refused argv)))
    (testing "the value in the key position or the environment position"
      (doseq [argv [["set" marker]
                    ["set" "dev" marker]
                    ["set" marker ":db/pw"]
                    ["set" (str "dev/" marker) ":k"]
                    ["set" ":db/pw" marker]
                    ["set" "dev" (str "[:a \"" marker "\"")]
                    ["set" "dev" (str "[:a " marker "]")]
                    ["set" "dev" (str ":a " marker)]]]
        (let [failure (refused argv)]
          (is (str/includes? (str (:message failure) (:hint (:data failure)))
                             "prompt or stdin")
              (pr-str argv)))))))

(deftest recipients-listing-escapes-and-truncates-an-invalid-line-test
  (let [recipients-file (str *dir* "/recipients.txt")
        line (str "AGE-SECRET-KEY-1\u001b[31m" (apply str (repeat 40 "Q")) "TAILMARKER")
        config (cli/normalize-config (test-config {:recipients-file recipients-file}))]
    (spit recipients-file (str line "\n"))
    (let [out (with-out-str (cli/recipients! config "dev"))
          prefix ((cli-private 'line-prefix) line)]
      (is (str/includes? out (str "  " (pr-str prefix))))
      (is (not (str/includes? out "\u001b")) "control characters are escaped")
      (is (not (str/includes? out "TAILMARKER"))))))
