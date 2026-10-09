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

(defn- with-no-terminal
  "Run `f` as if no terminal were attached. `set` prompts when it sees one, so
  a run from an interactive shell would otherwise wait on the keyboard instead
  of reading the piped input these tests give it. The tests that exercise the
  prompt put a terminal back themselves."
  [f]
  (with-redefs-fn {(ns-resolve 'com.kirahowe.secrets.cli 'tty?) (constantly false)}
    f))

(use-fixtures :each with-no-terminal with-tmp-key)

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

(defn- encrypt-text!
  "Encrypt exactly `text` to the config's secrets file out-of-band (no
  manifest written)."
  [text]
  (let [plain (str *dir* "/plain.edn")
        enc (str *dir* "/secrets.edn.age")]
    (spit plain text)
    (age/encrypt-file! *key* plain enc)
    (.delete (io/file plain))
    enc))

(defn- encrypt-raw-edn!
  "Encrypt exactly `m` out-of-band, so the store holds only the metadata `m`
  itself carries."
  [m]
  (encrypt-text! (pr-str m)))

(defn- metadata-line
  "The first line of a store's map as the library writes it, typed out here so
  the tests state the format instead of asking the source for it."
  [metadata]
  (str ":com.kirahowe.secrets/store " metadata "\n "))

(defn- current-metadata
  "Well-formed metadata text for a single-key store."
  []
  (str "{:version 1 :manifest-key " (pr-str (manifest/generate-key))
       " :recipients \"identity\"}"))

(defn- encrypt-edn!
  "Encrypt `m` out-of-band (no manifest written), as a teammate bypassing the
  CLI would: the store carries well-formed metadata on the library's line."
  [m]
  (encrypt-text! (str "{" (metadata-line (current-metadata))
                      (subs (binding [*print-namespace-maps* false] (pr-str m)) 1))))

(defn- new-store!
  "Create the store through `cli/new!`, with an editor that writes `text`."
  [config env-arg text]
  (with-out-str
    (with-redefs-fn {(ns-resolve 'com.kirahowe.secrets.cli 'run-editor!) #(spit % text)}
      #(cli/new! config env-arg))))

(defn- edit-store!
  "Run `cli/edit!` with an editor that replaces the plaintext with
  `(f plaintext)`."
  [config env-arg f]
  (with-out-str
    (with-redefs-fn {(ns-resolve 'com.kirahowe.secrets.cli 'run-editor!)
                     #(spit % (f (slurp %)))}
      #(cli/edit! config env-arg))))

(defn- manifest-of
  "The committed manifest at `path`, parsed."
  [path]
  (edn/read-string (slurp path)))

(defn- store-text
  "The decrypted plaintext of the store at `path`, library metadata included."
  [path identity]
  (age/decrypt identity path))

(defn- store-manifest-key
  "The manifest key the store at `path` holds, read as a recipient who
  decrypts it with `identity` reads it."
  [path identity]
  (get-in (edn/read-string (store-text path identity))
          [:com.kirahowe.secrets/store :manifest-key]))

(defn- manifest-key?
  "True when `x` has the shape of a manifest key: 64 lowercase hex characters."
  [x]
  (boolean (and (string? x) (re-matches #"[0-9a-f]{64}" x))))

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
  (with-redefs-fn {#'secrets/default-key-file (fn [_] *key*)
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
       (spit manifest (manifest/render {:app "cli-test"
                                        :ciphertext-sha (apply str (repeat 64 "0"))}
                                       {})))
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
               (secrets/load-secrets (str *dir* "/secrets.edn.age") *key*)))))))

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
  (testing "a configuration that does not normalize is reported with its reason"
    (doseq [[label config fragment]
            [["no :app" {:environments {:dev {:secrets-file "s.age"}}}
              "secrets config has no :app"]
             ["a blank path" {:app "x" :environments {:dev {:secrets-file "s.age" :template ""}}}
              "has a blank :template"]
             ["no .age extension" {:app "x" :environments {:dev {:secrets-file "s.txt"}}}
              "does not end in .age"]
             ["a URI-shaped path"
              {:app "x" :environments {:dev {:secrets-file "https://example.com/s.age"}}}
              "Environment :dev :secrets-file must be a local filesystem path"]
             ["a role collision"
              {:app "x" :environments {:dev {:secrets-file "s.age" :template "s.age"
                                             :manifest "s.manifest"}}}
              "incompatible artifact roles"]]]
      (testing label
        (let [{:keys [result out err]} (doctor-under config "dev" {})]
          (is (= 2 (:exit result)))
          (is (= :invalid (:status result)))
          (is (str/starts-with? out "Configuration: invalid\nReason: "))
          (is (str/includes? out fragment))
          (is (str/ends-with? out "Status: invalid\n"))
          (is (= "" err)))))))

(deftest doctor-prints-the-identity-source-and-path-test
  (let [raw-value (slurp *key*)
        b64-value (.encodeToString (java.util.Base64/getEncoder)
                                   (.getBytes ^String raw-value "UTF-8"))
        file-value (str *dir* "/env-named-key.txt")
        _ (io/copy (io/file *key*) (io/file file-value))
        configured-key (str *dir* "/configured-key.txt")
        _ (io/copy (io/file *key*) (io/file configured-key))
        default-config {:app "cli-test"
                        :default-environment :dev
                        :environments {:dev {:secrets-file (str *dir* "/default.edn.age")}}}
        specs [{:source :secrets-age-identity-file
                :label "SECRETS_AGE_IDENTITY_FILE"
                :environment {"SECRETS_AGE_IDENTITY_FILE" file-value}
                :path file-value}
               {:source :secrets-age-identity
                :label "SECRETS_AGE_IDENTITY"
                :environment {"SECRETS_AGE_IDENTITY" raw-value}}
               {:source :secrets-age-identity-b64
                :label "SECRETS_AGE_IDENTITY_B64"
                :environment {"SECRETS_AGE_IDENTITY_B64" b64-value}}
               {:source :identity-file
                :label ":identity-file"
                :config (test-config {:identity-file configured-key})
                :path configured-key}
               {:source :configured-key-file
                :label "configured key path"
                :config (test-config {:key-file configured-key})
                :path configured-key}
               {:source :default-key-file
                :label "default key path"
                :config default-config
                :path *key*}]
        secret-line (first (filter #(str/starts-with? % "AGE-SECRET-KEY-")
                                   (str/split-lines raw-value)))]
    (doseq [{:keys [source config path label] :as spec} specs]
      (testing (name source)
        (let [{:keys [result out err]} (doctor-under (or config (test-config)) nil spec)
              disclosed (str (pr-str result) out err)]
          (is (= {:source source :path path :usable? true :exists? true :problem nil}
                 (:identity result)))
          (is (str/includes? out (str "Identity: " label
                                      (when path (str " — " path))
                                      " — usable\n")))
          (when-not path
            (is (not (str/includes? disclosed "/age-identity-"))
                "an injected identity is named by its variable, never by a temp path"))
          (is (not (str/includes? disclosed secret-line)))
          (is (not (str/includes? disclosed b64-value))))))))

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
    (testing "an absent default key leaves keyless verification available"
      (let [missing (str *dir* "/missing-default-key.txt")
            {:keys [result out]}
            (with-redefs-fn {#'secrets/default-key-file (constantly missing)
                             #'age/version (constantly "age test-version")}
              #(with-identity-environment {}
                 (fn [] (capture-doctor (update-in config [:environments :dev] dissoc :key-file)
                                        nil))))]
        (is (= 1 (:exit result)))
        (is (= {:state :ready :keyless? true :full? false} (:verify result)))
        (is (str/includes? out (str "Identity: default key path — " missing " — missing\n")))))
    (testing "a designated identity that does not exist is a problem, as it is for verify"
      (doseq [[label spec-config environment subject]
              [["SECRETS_AGE_IDENTITY_FILE" config
                {"SECRETS_AGE_IDENTITY_FILE" (str *dir* "/missing-identity")}
                "SECRETS_AGE_IDENTITY_FILE"]
               [":identity-file"
                (assoc-in config [:environments :dev :identity-file]
                          (str *dir* "/missing-identity"))
                {} "The explicit identity path"]
               [":key-file"
                (assoc-in config [:environments :dev :key-file] (str *dir* "/missing-identity"))
                {} "The configured :key-file"]]]
        (testing label
          (let [{:keys [result out]} (doctor-under spec-config nil {:environment environment})]
            (is (= 2 (:exit result)))
            (is (= :invalid (:status result)))
            (is (= {:state :ready :keyless? false :full? false} (:verify result)))
            (is (str/includes? out (str "Identity problem: " subject
                                        " names an age identity file that does not exist: "
                                        *dir* "/missing-identity")))
            (is (str/includes? out "Ciphertext: present")
                "the rest of the report is still printed")))))
    (testing "an unavailable age binary preserves keyless verification"
      (let [result (:result (doctor-under config nil {:version nil}))]
        (is (= {:state :ready :keyless? true :full? false} (:verify result)))))
    (testing "an incomplete manifest prevents keyless verification"
      (spit (str *dir* "/secrets.edn.manifest") "{:version 3 :app \"cli-test\" :keys {}}")
      (let [result (:result (doctor-under config nil {}))]
        (is (= 1 (:exit result)))
        (is (= {:state :invalid :keyless? false :full? true}
               (:verify result)))))
    (testing "so does a manifest in another version"
      (spit (str *dir* "/secrets.edn.manifest") "{:version 2}")
      (is (= {:state :unsupported :keyless? false :full? true}
             (:verify (:result (doctor-under config nil {})))))))
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

(deftest a-failed-manifest-replace-leaves-a-detectably-stale-manifest-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          encrypted (str *dir* "/secrets.edn.age")
          manifest-path (str *dir* "/secrets.edn.manifest")]
      (encrypt-edn! {:version :old})
      (with-out-str (cli/reencrypt! config "dev"))
      (let [manifest-before (slurp manifest-path)
            real-move fs/atomic-move!
            moves (atom [])
            e (try
                (with-out-str
                  (with-redefs-fn {(cli-private 'run-editor!) #(spit % "{:version :new}")
                                   #'fs/atomic-move!
                                   (fn [source target]
                                     (swap! moves conj (str target))
                                     (if (= manifest-path (str target))
                                       (throw (java.io.IOException. "simulated move failure"))
                                       (real-move source target)))}
                    #(cli/edit! config "dev")))
                nil
                (catch clojure.lang.ExceptionInfo e e))]
        (is (= [encrypted manifest-path] @moves)
            "the ciphertext is replaced, then the manifest; nothing is rolled back")
        (is (= {:version :new} (secrets/load-secrets encrypted *key*))
            "the ciphertext is authoritative and holds the edit")
        (is (= manifest-before (slurp manifest-path)) "the manifest is the old one")
        (is (= :manifest-stale (:reason (ex-data e))))
        (doseq [fragment [encrypted manifest-path "was updated" "stale"
                          "bb secrets verify" "bb secrets reencrypt 'dev'"]]
          (is (str/includes? (ex-message e) fragment) fragment))
        (is (= ["key.txt" "secrets.edn.age" "secrets.edn.manifest"]
               (sort (.list (io/file *dir*))))
            "no staging or backup file remains")
        (is (= 1 (:exit (verify config "dev"))) "verify reports the stale manifest")
        (with-out-str (cli/reencrypt! config "dev"))
        (is (= 0 (:exit (verify config "dev"))) "and reencrypt regenerates it")))))

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
               (secrets/load-secrets ciphertext *key*)))))))

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
           (secrets/load-secrets ciphertext *key*)))))

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
            (is (= "v2" (:k (secrets/load-secrets (str *dir* "/secrets.edn.age") *key*)))
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
        (is (= 3 (:version m)))
        (is (string? (:ciphertext-sha m)) "manifest records the ciphertext hash")
        (is (= #{[:database/url] [:auth/admins]} (set (keys (:keys m))))
            "the store's reserved keys get no entry")
        (is (every? :vhash (vals (:keys m))) "every leaf has a value hash"))
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
          missing (str *dir* "/no-such-key.txt")
          keyless-verify (fn []
                           (under-default-key-file
                            missing
                            #(verify (cli/normalize-config (test-config {:key-file nil})) "dev")))]
      (encrypt-edn! {:a 1})
      (with-out-str (cli/reencrypt! config "dev"))
      (testing "fresh manifest → freshness verified without any key"
        (let [{:keys [results exit]} (keyless-verify)]
          (is (= 0 exit))
          (is (= :ok-keyless (:dev results)))))
      (testing "a designated identity that does not exist is an error, never keyless"
        (doseq [[label run]
                [["a configured :key-file"
                  #(verify (cli/normalize-config (test-config {:key-file missing})) "dev")]
                 ["an :identity-file"
                  #(verify (cli/normalize-config (test-config {:identity-file missing})) "dev")]
                 ["SECRETS_AGE_IDENTITY_FILE"
                  #(with-identity-environment {"SECRETS_AGE_IDENTITY_FILE" missing}
                     (fn [] (verify config "dev")))]]]
          (testing label
            (let [e (try (run) (catch clojure.lang.ExceptionInfo e e))]
              (is (= :no-identity (:reason (ex-data e))))
              (is (str/includes? (str (ex-message e)) missing))))))
      (testing "tampered ciphertext → drift, still without any key"
        (encrypt-edn! {:a 2})
        (let [{:keys [results exit]} (keyless-verify)]
          (is (= 1 exit))
          (is (= :drift (:dev results))))))))

(defn- keyless-config
  "A config with no designated identity, for use under `under-default-key-file`
  with an absent default, so `verify` takes the keyless path."
  [absent]
  (under-default-key-file absent #(cli/normalize-config (test-config {:key-file nil}))))

(defn- capture-keyed-and-keyless
  "Run `verify` on dev with the fixture identity and again with none. Returns
  `[[label captured] …]`."
  [config]
  (let [absent (str *dir* "/absent-key.txt")
        keyless (keyless-config absent)]
    [["keyed" (with-identity-environment {} #(capture-verify config "dev"))]
     ["keyless" (with-identity-environment
                  {} (fn [] (under-default-key-file absent #(capture-verify keyless "dev"))))]]))

(deftest verify-version-gate-test
  (let [config (cli/normalize-config (test-config))
        manifest-path (str *dir* "/secrets.edn.manifest")]
    (new-store! config "dev" "{:a 1}")
    (let [committed (manifest-of manifest-path)]
      (is (= 3 (:version committed)) "the CLI writes version 3")
      ;; Everything but :version stays consistent with the ciphertext, so only
      ;; the version can be what fails.
      (doseq [version [1 2 4 "3" nil]]
        (spit manifest-path (pr-str (if (nil? version)
                                      (dissoc committed :version)
                                      (assoc committed :version version))))
        (doseq [[label {:keys [result out err]}] (capture-keyed-and-keyless config)]
          (testing (str label " version " (pr-str version))
            (is (= {:results {:dev :drift} :exit 1} result))
            (is (str/includes? err "is unsupported by this version of the library"))
            (is (str/includes? out "bb secrets reencrypt 'dev'")))))
      (testing "and the manifest as written verifies on both paths"
        (spit manifest-path (pr-str committed))
        (is (= [0 0] (map (comp :exit :result second) (capture-keyed-and-keyless config))))))))

(deftest wrong-app-manifest-is-rejected-test
  ;; `:app` is the one field a manifest records about which store it describes,
  ;; so a manifest belonging to another project is refused rather than diffed.
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

(deftest an-incomplete-manifest-is-drift-with-and-without-an-identity-test
  (let [config (cli/normalize-config (test-config))
        manifest-path (str *dir* "/secrets.edn.manifest")]
    (new-store! config "dev" "{:a 1 :b {:c \"x\"}}")
    (let [committed (manifest-of manifest-path)
          without-vhash (update-in committed [:keys [:a]] dissoc :vhash)]
      (is (= 0 (:exit (verify config "dev"))) "the manifest the CLI wrote is complete")
      (doseq [[label text]
              [["a top-level list" "(1 2 3)"]
               ["a wrapped map" (str "(" (pr-str committed) ")")]
               ["a vector" "[1 2]"]
               ["a number" "5"]
               ["nil" "nil"]
               ["no :keys" (pr-str (dissoc committed :keys))]
               [":keys a vector" (pr-str (assoc committed :keys []))]
               [":keys a number" (pr-str (assoc committed :keys 5))]
               [":keys nil" (pr-str (assoc committed :keys nil))]
               ["an entry without :vhash" (pr-str without-vhash)]
               ["every entry without :vhash"
                (pr-str (update committed :keys update-vals #(dissoc % :vhash)))]
               ["an entry with a nil :vhash"
                (pr-str (assoc-in committed [:keys [:a] :vhash] nil))]
               ["an entry with a short :vhash"
                (pr-str (assoc-in committed [:keys [:a] :vhash] "abc"))]
               ["an entry without :type"
                (pr-str (update-in committed [:keys [:a]] dissoc :type))]
               ["an entry that is not a map" (pr-str (assoc-in committed [:keys [:a]] :integer))]
               ["no :ciphertext-sha" (pr-str (dissoc committed :ciphertext-sha))]
               ["a :ciphertext-sha that is not a digest"
                (pr-str (assoc committed :ciphertext-sha "fresh"))]]]
        (spit manifest-path text)
        (doseq [[path {:keys [result out err]}] (capture-keyed-and-keyless config)]
          (testing (str path ": " label)
            (is (= {:results {:dev :drift} :exit 1} result))
            (is (str/includes? err "manifest is incomplete"))
            (is (str/includes? (str out err) "bb secrets reencrypt 'dev'")))))
      (testing "reencrypt writes a complete manifest again"
        (with-out-str (cli/reencrypt! config "dev"))
        (is (= [0 0] (map (comp :exit :result second) (capture-keyed-and-keyless config))))))))

(deftest a-replaced-ciphertext-fails-verification-in-solo-and-team-stores-test
  ;; Someone who holds only a public recipient can encrypt a chosen payload and
  ;; refresh :ciphertext-sha, but cannot compute a :vhash: the manifest key is
  ;; inside the store they cannot read. The same holds for a team store.
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (doseq [[mode env-config] [["solo" {}]
                               ["team" {:recipients-file (str *dir* "/recipients.txt")}]]]
      (testing mode
        (let [config (cli/normalize-config (test-config env-config))
              ciphertext (str *dir* "/secrets.edn.age")
              manifest-path (str *dir* "/secrets.edn.manifest")
              sha256 (cli-private 'sha256)
              recipient (age/public-key *key*)
              forge! (fn [committed value]
                       (let [forged (str *dir* "/forged.edn")]
                         (spit forged (pr-str value))
                         (age/encrypt-file! {:recipients [recipient]} forged ciphertext)
                         (.delete (io/file forged))
                         (spit manifest-path
                               (pr-str (assoc committed :ciphertext-sha (sha256 ciphertext))))))]
          (when (:recipients-file env-config)
            (spit (:recipients-file env-config) (str recipient "\n")))
          (.delete (io/file ciphertext))
          (new-store! config "dev" "{:db/url \"postgres://prod.internal/app\"}")
          (let [committed (manifest-of manifest-path)
                recorded (get-in (edn/read-string (store-text ciphertext *key*))
                                 [:com.kirahowe.secrets/store :recipients])]
            (is (= 0 (:exit (verify config "dev"))))
            (testing "a same-shape payload with no store metadata"
              (forge! committed {:db/url "postgres://attacker.example/app"})
              (let [{:keys [result err]} (capture-verify config "dev")]
                (is (= {:results {:dev :drift} :exit 1} result))
                (is (str/includes? err "has no store metadata"))))
            (testing "a same-shape payload with a key the forger made up"
              (forge! committed {:db/url "postgres://attacker.example/app"
                                 :com.kirahowe.secrets/store
                                 {:version 1
                                  :manifest-key (manifest/generate-key)
                                  :recipients recorded}})
              (let [{:keys [result out err]} (capture-verify config "dev")]
                (is (= {:results {:dev :drift} :exit 1} result))
                (is (str/includes? (str out err) "value or type changed"))))))))))

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
          stored (fn [k] (k (secrets/load-secrets encrypted *key*)))]
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
          (is (= "v" (:default-env (secrets/load-secrets store *key*))))))
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
             (secrets/load-secrets encrypted *key*))))))

(deftest set-overwrites-an-existing-key-leaving-others-untouched-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          encrypted (str *dir* "/secrets.edn.age")]
      (encrypt-edn! {:a "old" :b "keep"})
      (with-out-str (cli/reencrypt! config "dev"))
      (with-out-str (with-in-str "new" (cli/set-secret! config "dev" ":a" false)))
      (is (= {:a "new" :b "keep"} (secrets/load-secrets encrypted *key*))))))

(deftest set-nested-vector-path-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          encrypted (str *dir* "/secrets.edn.age")]
      (with-out-str
        (with-in-str "acct-123" (cli/set-secret! config "dev" "[:r2 :account-id]" false)))
      (is (= {:r2 {:account-id "acct-123"}} (secrets/load-secrets encrypted *key*)))
      (testing "a sibling key added under the same parent leaves the first untouched"
        (with-out-str
          (with-in-str "us-east" (cli/set-secret! config "dev" "[:r2 :region]" false)))
        (is (= {:r2 {:account-id "acct-123" :region "us-east"}}
               (secrets/load-secrets encrypted *key*)))))))

(deftest set-edn-flag-parses-typed-values-and-manifest-records-type-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          encrypted (str *dir* "/secrets.edn.age")]
      (with-out-str
        (with-in-str "#{\"a@b.com\" \"c@d.com\"}"
          (cli/set-secret! config "dev" ":auth/admins" true)))
      (is (= {:auth/admins #{"a@b.com" "c@d.com"}}
             (secrets/load-secrets encrypted *key*)))
      (let [m (edn/read-string (slurp (str *dir* "/secrets.edn.manifest")))]
        (is (= :set (get-in m [:keys [:auth/admins] :type]))
            "manifest records the EDN-parsed value's real type, not :string")))))

(deftest set-without-edn-stores-a-plain-string-even-when-it-looks-like-edn-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          encrypted (str *dir* "/secrets.edn.age")]
      (with-out-str (with-in-str "42" (cli/set-secret! config "dev" ":n" false)))
      (is (= {:n "42"} (secrets/load-secrets encrypted *key*))
          "default (no --edn) always stores a string, regardless of stdin's shape"))))

(deftest set-strips-exactly-one-trailing-newline-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          encrypted (str *dir* "/secrets.edn.age")]
      (testing "a single trailing \\n is stripped"
        (with-out-str (with-in-str "secret\n" (cli/set-secret! config "dev" ":a" false)))
        (is (= "secret" (:a (secrets/load-secrets encrypted *key*)))))
      (testing "a single trailing \\r\\n is stripped"
        (with-out-str (with-in-str "secret\r\n" (cli/set-secret! config "dev" ":b" false)))
        (is (= "secret" (:b (secrets/load-secrets encrypted *key*)))))
      (testing "only exactly one trailing newline is stripped — the rest is verbatim"
        (with-out-str (with-in-str "line1\n\n" (cli/set-secret! config "dev" ":c" false)))
        (is (= "line1\n" (:c (secrets/load-secrets encrypted *key*)))))
      (testing "no trailing newline at all is untouched"
        (with-out-str (with-in-str "bare" (cli/set-secret! config "dev" ":d" false)))
        (is (= "bare" (:d (secrets/load-secrets encrypted *key*))))))))

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
        (is (= {:a ""} (secrets/load-secrets encrypted *key*)))))))

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
          stored #(secrets/load-secrets encrypted *key*)]
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
      (let [plaintext ((cli-private 'user-plaintext) (age/decrypt *key* encrypted))]
        (is (= {:a {:b "v"} :c "w"} (edn/read-string plaintext)))
        (is (= "{:a {:b \"v\"}, :c \"w\"}\n" plaintext)
            "what `edit` shows next is the pretty-printed map, without library metadata")
        (is (re-find #"\n" plaintext)
            "the regenerated store is pretty-printed, so the next `edit` is readable"))
      (testing "print limits set in a REPL cannot truncate the store"
        (binding [*print-length* 1 *print-level* 1]
          (with-out-str (with-in-str "x" (cli/set-secret! config "dev" ":d" false))))
        (is (= {:a {:b "v"} :c "w" :d "x"}
               (secrets/load-secrets encrypted *key*)))))))

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
      (is (= {:a "keep"} (secrets/load-secrets encrypted *key*)))
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
      (is (= {:r2 {}} (secrets/load-secrets encrypted *key*))
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
      (is (= {:a 1} (secrets/load-secrets encrypted *key*))
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
        (is (= 42 (:n (secrets/load-secrets encrypted *key*)))))
      (testing "run! dispatches set as [env] <key>, --edn after both"
        (with-out-str (with-in-str "\"s\"" (cli/run! config ["set" "dev" ":m" "--edn"])))
        (is (= "s" (:m (secrets/load-secrets encrypted *key*)))))
      (testing "without --edn the value is stored as a plain string"
        (with-out-str (with-in-str "plain" (cli/run! config ["set" "dev" ":p"])))
        (is (= "plain" (:p (secrets/load-secrets encrypted *key*)))))
      (testing "run! dispatches rm as [env] <key>"
        (with-out-str (cli/run! config ["rm" "dev" ":n"]))
        (is (not (contains? (secrets/load-secrets encrypted *key*) :n)))))))

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
            (is (= expected (secrets/load-secrets ciphertext *key*)))
            (is (= expected (secrets/load-secrets ciphertext bob-key)))))
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
                                      #"must be a local filesystem path"
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
                :reason :disallowed-source
                :scheme "https"}
               (select-keys (ex-data e) [:environment :field :reason :scheme])))
        (is (not (str/includes? rendered sentinel)))
        (is (not (contains? (ex-data e) :path)))))
    (testing "whitespace before the scheme does not hide it"
      (let [e (try
                (cli/normalize-config (config {:secrets-file " https://127.0.0.1/store.age"}))
                nil
                (catch clojure.lang.ExceptionInfo e e))]
        (is (= {:reason :disallowed-source :scheme "https"}
               (select-keys (ex-data e) [:reason :scheme])))))
    (testing "identity roles share the runtime's reason and wording"
      (doseq [field [:key-file :identity-file]]
        (let [e (try (cli/normalize-config (config {field "key:txt"}))
                     nil
                     (catch clojure.lang.ExceptionInfo e e))]
          (is (= {:environment :dev :field field :reason :disallowed-identity :scheme "key"}
                 (select-keys (ex-data e) [:environment :field :reason :scheme])))
          (is (= (str "Environment :dev " field " must be a local filesystem path, but its"
                      " value starts with the URI scheme \"key\". For a relative file whose"
                      " name contains a colon, write ./ before the name.")
                 (ex-message e))))))
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
          (is (map? (secrets/load-secrets ciphertext *key*))
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
          (is (= expected (secrets/load-secrets ciphertext *key*)))
          (is (= expected (secrets/load-secrets ciphertext bob-key)))))
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
          manifest-key (manifest/generate-key)
          ;; The bound is on what is encrypted: the user's text plus the
          ;; store's metadata line.
          limit (+ (count exact-plaintext)
                   (count ((cli-private 'metadata-line)
                           manifest-key (manifest/recipients-id nil))))
          bounded (fn [n f] (with-bound #'age/max-plaintext-bytes n f))
          config (cli/normalize-config (test-config {:manifest false}))
          env (get-in config [:environments :dev])
          write-secrets! (fn [text]
                           ((cli-private 'write-secrets!)
                            env {:identity-file *key*} plaintext-file text manifest-key))
          ciphertext (:secrets-file env)]
      (testing "an editor plaintext at the exact byte bound is accepted"
        (bounded limit #(write-secrets! exact-plaintext))
        (is (= {:a 1} (secrets/load-secrets ciphertext *key*))))
      (testing "the first byte over is rejected before parsing or encryption"
        (let [sentinel "~"
              before (file-bytes ciphertext)
              e (bounded limit #(try
                                  (write-secrets! (str exact-plaintext sentinel))
                                  (catch clojure.lang.ExceptionInfo e e)))
              rendered (str (ex-message e) (pr-str (ex-data e)))]
          (is (= {:reason :input-too-large :limit limit :observed (inc limit)}
                 (select-keys (ex-data e) [:reason :limit :observed])))
          (is (str/includes? (ex-message e) ciphertext) "the message names the store")
          (is (not (str/includes? rendered sentinel)))
          (is (= before (file-bytes ciphertext)))))
      (testing "stdin accepts exact UTF-8 bytes and rejects one byte over"
        ;; Large enough that the stored plaintext, metadata included, fits too.
        (let [stdin-limit 512
              exact-stdin (str "\"é\"" (apply str (repeat (- stdin-limit 4) " ")))]
          (is (= stdin-limit (alength (.getBytes exact-stdin "UTF-8")))
              "the fixture is at the bound in bytes, not characters")
          (with-out-str
            (with-in-str exact-stdin
              (bounded stdin-limit #(cli/set-secret! config "dev" ":n" true))))
          (is (= "é" (:n (secrets/load-secrets ciphertext *key*))))
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
        exact-content (manifest/render
                       {:app "cli-test" :ciphertext-sha (apply str (repeat 64 "a"))}
                       (manifest/entries {:a "x" :b 1} (manifest/generate-key)))
        value (edn/read-string exact-content)
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
               (ex-data e)))
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

(deftest unknown-config-keys-are-rejected-test
  (let [failure (fn [config]
                  (try (cli/normalize-config config)
                       nil
                       (catch clojure.lang.ExceptionInfo e e)))]
    (testing "a misspelled or leftover top-level key"
      (doseq [[k v] [[:enviroments {}] [:limits {:max-plaintext-bytes 1}]]]
        (let [e (failure (assoc (test-config) k v))]
          (is (= {:reason :unknown-config-key :unknown-keys [k]} (ex-data e)))
          (is (str/includes? (ex-message e) (str "secrets config has an unknown key: " k)))
          (is (str/includes? (ex-message e)
                             "Known keys: :app, :default-environment, :environments")))))
    (testing "a misspelled per-environment key, which would otherwise leave the default in force"
      (let [e (failure (test-config {:secrets-fle "elsewhere.age" :manfest false}))]
        (is (= :unknown-config-key (:reason (ex-data e))))
        (is (= #{:secrets-fle :manfest} (set (:unknown-keys (ex-data e)))))
        (is (str/includes? (ex-message e) "Environment :dev has an unknown key"))
        (is (str/includes? (ex-message e) ":secrets-fle"))
        (doseq [known [:secrets-file :key-file :identity-file :template :manifest
                       :recipients-file]]
          (is (str/includes? (ex-message e) (str known)) known))
        (is (not (str/includes? (ex-message e) "elsewhere.age"))
            "the message names the key and never its value")))
    (testing "every documented key is accepted"
      (is (map? (cli/normalize-config
                 (test-config {:identity-file *key*
                               :template (str *dir* "/t.example")
                               :manifest (str *dir* "/m.manifest")
                               :recipients-file (str *dir* "/r.txt")})))))))

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

(deftest write-secrets-releases-staging-on-every-failure-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [plaintext (str *dir* "/plain.edn")
          env (assoc (get-in (cli/normalize-config (test-config)) [:environments :dev])
                     :identity-file *key*)
          manifest-key (manifest/generate-key)
          write! #((cli-private 'write-secrets!)
                   env {:identity-file *key*} plaintext "{:a 1}" manifest-key)
          entries #(sort (.list (io/file *dir*)))
          real-encrypt age/encrypt-file!
          real-move fs/atomic-move!]
      (write!)
      (let [settled (entries)
            ciphertext (file-bytes (:secrets-file env))
            manifest-text (slurp (:manifest env))]
        (doseq [[label redefs]
                [["encryption fails after writing its output"
                  {#'age/encrypt-file! (fn [& args]
                                         (apply real-encrypt args)
                                         (throw (ex-info "forced encryption failure" {})))}]
                 ["rendering the manifest fails"
                  {#'manifest/render (fn [& _] (throw (ex-info "forced render failure" {})))}]
                 ["the ciphertext move fails"
                  {#'fs/atomic-move! (fn [& _] (throw (java.io.IOException. "forced")))}]
                 ["the manifest move fails"
                  {#'fs/atomic-move! (fn [source target]
                                       (if (= (:manifest env) (str target))
                                         (throw (java.io.IOException. "forced"))
                                         (real-move source target)))}]]]
          (testing label
            (is (thrown? Exception (with-redefs-fn redefs write!)))
            (is (= settled (entries)) "no staging file remains")
            (is (= manifest-text (slurp (:manifest env))))
            (when-not (= label "the manifest move fails")
              (is (= ciphertext (file-bytes (:secrets-file env)))
                  "a failure before the first replace leaves the ciphertext as it was"))))))))

(deftest normalizing-twice-changes-nothing-test
  (doseq [env-config [{} {:key-file (str *dir* "/k.txt")}]]
    (let [config (cli/normalize-config
                  {:app "cli-test"
                   :environments {:dev (merge {:secrets-file (str *dir* "/s.age")}
                                              env-config)}})]
      (is (= config (cli/normalize-config config)))
      (is (not (contains? (get-in config [:environments :dev]) :key-file-source))))))

(deftest key-contents-in-a-configured-path-are-refused-at-normalization-test
  (let [key-line (first (filter #(str/starts-with? % "AGE-SECRET-KEY-")
                                (str/split-lines (slurp *key*))))
        config (fn [field]
                 {:app "cli-test"
                  :default-environment :dev
                  :environments {:dev (merge {:secrets-file (str *dir* "/s.age")}
                                             {field key-line})}})]
    (testing "every path role refuses key contents, naming the field and never the value"
      (doseq [field [:key-file :identity-file :template :manifest :recipients-file]]
        (let [{:keys [failure] :as captured}
              (capture-failure #(cli/normalize-config (config field)))]
          (is (= (str "Environment :dev " field " holds age key contents where a local"
                      " filesystem path was expected. Key contents belong in"
                      " SECRETS_AGE_IDENTITY.")
                 (:message failure)))
          (is (= field (get-in failure [:data :field])))
          (assert-redacted! key-line captured))))
    (testing "show-key and keygen never print, or create a file named by, the key"
      (doseq [[label args] [["show-key" ["show-key"]] ["keygen" ["keygen"]]]]
        (testing label
          (let [captured (capture-failure #((cli-private 'dispatch!) (config :key-file) args))]
            (is (= :disallowed-identity (get-in captured [:failure :data :reason])))
            (assert-redacted! key-line captured)
            (is (not (.exists (io/file key-line))))))))))

(deftest a-colon-named-identity-variable-fails-the-command-and-doctor-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (test-config)
          expected (str "SECRETS_AGE_IDENTITY_FILE must be a local filesystem path, but its"
                        " value starts with the URI scheme \"key\". For a relative file whose"
                        " name contains a colon, write ./ before the name.")]
      (encrypt-edn! {:a 1})
      (with-identity-environment {"SECRETS_AGE_IDENTITY_FILE" "key:txt"}
        (fn []
          (testing "a command fails with the runtime's reason and wording"
            (doseq [args [["reencrypt" "dev"] ["verify" "dev"] ["rm" "dev" ":a"]]]
              (let [{:keys [failure]} (capture-failure #((cli-private 'dispatch!) config args))]
                (is (= expected (:message failure)) (pr-str args))
                (is (= {:reason :disallowed-identity
                        :scheme "key"
                        :identity-source :secrets-age-identity-file}
                       (:data failure))))))
          (testing "doctor reports it as an identity problem with the same reason"
            (let [{:keys [result out]} (capture-doctor config "dev")]
              (is (= 2 (:exit result)))
              (is (str/includes? out "Identity: SECRETS_AGE_IDENTITY_FILE — invalid\n"))
              (is (str/includes? out (str "Identity problem: " expected "\n")))
              (is (not (str/includes? out "Configuration: invalid")))))))
      (testing "a URL and key contents are reported the same way, without the value"
        (doseq [[value fragment] [["https://user:pw-SENTINEL@example.com/k" "URI scheme \"https\""]
                                  ["AGE-SECRET-KEY-1SENTINEL" "holds age key contents"]]]
          (let [{:keys [result out]}
                (with-identity-environment {"SECRETS_AGE_IDENTITY_FILE" value}
                  #(capture-doctor config "dev"))]
            (is (= 2 (:exit result)))
            (is (str/includes? out "Identity problem: SECRETS_AGE_IDENTITY_FILE "))
            (is (str/includes? out fragment))
            (is (not (str/includes? (str out (pr-str result)) "SENTINEL")))))))))

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
        (is (not (str/includes? out "Configuration: invalid")))
        (is (str/includes? out "Identity problem: SECRETS_AGE_IDENTITY is set but empty"))))
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

;;;; The per-store manifest key

(defn- team-fixture
  "A two-recipient team store's moving parts: Alice holds the fixture key and
  Bob a second one, and each has a config that differs only in whose key it
  names. The recipients file lists both."
  []
  (let [recipients (str *dir* "/recipients.txt")
        bob-key (str *dir* "/bob-key.txt")
        bob-public (age/keygen! bob-key)
        alice-public (age/public-key *key*)]
    (spit recipients (str alice-public "\n" bob-public "\n"))
    {:recipients recipients
     :ciphertext (str *dir* "/secrets.edn.age")
     :manifest-path (str *dir* "/secrets.edn.manifest")
     :bob-key bob-key
     :alice-public alice-public
     :alice (cli/normalize-config (test-config {:recipients-file recipients}))
     :bob (cli/normalize-config (test-config {:recipients-file recipients :key-file bob-key}))}))

(defn- set-value! [config k v]
  (with-out-str (with-in-str v (cli/set-secret! config "dev" k false))))

(defn- vhash-of
  "The `:vhash` `manifest-key` gives `value`."
  [manifest-key value]
  (:vhash (get (manifest/entries {:x value} manifest-key) [:x])))

(deftest every-store-gets-a-vhash-on-every-leaf-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [recipients (str *dir* "/recipients.txt")
          template (str *dir* "/shared.example")
          env (fn [n extra]
                (merge {:secrets-file (str *dir* "/" n ".edn.age")
                        :key-file *key*
                        :template template}
                       extra))
          config (cli/normalize-config
                  {:app "cli-test"
                   :environments {:solo (env "solo" {})
                                  :team (env "team" {:recipients-file recipients})
                                  :copy (env "copy" {})}})
          text "{:db {:url \"postgres://x\" :port 5432}\n :admins #{\"a@b.c\"}\n :empty {}}"
          manifest-for #(manifest-of (str *dir* "/" % ".edn.manifest"))
          key-for #(store-manifest-key (str *dir* "/" % ".edn.age") *key*)]
      (spit recipients (str (age/public-key *key*) "\n"))
      ;; The template is a decrypted store someone saved, manifest key and all.
      (new-store! config "solo" text)
      (spit template (store-text (str *dir* "/solo.edn.age") *key*))
      (is (str/includes? (slurp template) (key-for "solo"))
          "the template really holds a manifest key")
      (.delete (io/file (str *dir* "/solo.edn.age")))
      (doseq [n ["solo" "team" "copy"]]
        ;; The editor saves the template as it was presented.
        (with-out-str
          (with-redefs-fn {(cli-private 'run-editor!) (fn [_])}
            #(cli/new! config n))))
      (testing "solo and team manifests are the same kind"
        (doseq [n ["solo" "team"]]
          (let [m (manifest-for n)]
            (is (= 3 (:version m)))
            (is (= #{[:db :url] [:db :port] [:admins] [:empty]} (set (keys (:keys m))))
                "one entry per leaf, and none for the store's reserved keys")
            (is (every? #(re-matches #"[0-9a-f]{16}" (:vhash %)) (vals (:keys m))) n)
            (is (= 0 (:exit (verify config n)))))))
      (testing "stores created from one template never share a key"
        (is (every? manifest-key? (map key-for ["solo" "team" "copy"])))
        (is (= 3 (count (set (map key-for ["solo" "team" "copy"]))))
            "none of them is the template's key either")
        (is (not (contains? (set (map key-for ["solo" "team" "copy"]))
                            (get-in (edn/read-string (slurp template))
                                    [:com.kirahowe.secrets/store :manifest-key])))))
      (testing "so equal values hash differently in each"
        (let [hashes (fn [n] (update-vals (:keys (manifest-for n)) :vhash))]
          (doseq [path [[:db :url] [:db :port] [:admins] [:empty]]]
            (is (= 3 (count (set (map #(get (hashes %) path) ["solo" "team" "copy"]))))
                path))))
      (testing "the stores hold the same user data"
        (is (= (edn/read-string text)
               (secrets/load-secrets (str *dir* "/solo.edn.age") *key*)
               (secrets/load-secrets (str *dir* "/team.edn.age") *key*)))))))

(deftest a-template-with-the-reserved-key-off-the-librarys-line-is-refused-test
  ;; Only the line the library writes is taken out of a template. The reserved
  ;; key typed anywhere else is refused, as it is when typed in the editor.
  (let [template (str *dir* "/hand.example")
        config (cli/normalize-config (test-config {:template template}))]
    (spit template (str "{:a 1 :com.kirahowe.secrets/store " (current-metadata) "}"))
    (let [e (try (with-out-str
                   (with-redefs-fn {(cli-private 'run-editor!) (fn [_])}
                     #(cli/new! config "dev")))
                 nil
                 (catch clojure.lang.ExceptionInfo e e))]
      (is (= :reserved-key (:reason (ex-data e))))
      (is (str/includes? (ex-message e) "which the library reserves"))
      (is (not (.exists (io/file (str *dir* "/secrets.edn.age"))))))))

(deftest recipients-of-a-team-store-agree-on-unchanged-values-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [{:keys [alice bob bob-key ciphertext manifest-path]} (team-fixture)
          entries #(:keys (manifest-of manifest-path))
          unchanged-agree (fn [before paths]
                            (is (= (select-keys before paths) (select-keys (entries) paths))))]
      (new-store! alice "dev" "{:a \"one\" :b \"two\" :c {:d \"three\"}}")
      (let [created (entries)
            manifest-key (store-manifest-key ciphertext *key*)]
        (is (= manifest-key (store-manifest-key ciphertext bob-key))
            "both recipients read the same key")
        (testing "Bob sets a value"
          (set-value! bob ":b" "TWO")
          (unchanged-agree created [[:a] [:c :d]])
          (is (not= (created [:b]) ((entries) [:b]))))
        (testing "Alice edits another"
          (let [before (entries)]
            (edit-store! alice "dev" #(str/replace % "\"one\"" "\"ONE\""))
            (unchanged-agree before [[:b] [:c :d]])
            (is (not= (before [:a]) ((entries) [:a])))))
        (testing "Bob removes a third and adds a fourth by editing"
          (let [before (entries)]
            (with-out-str (cli/remove-secret! bob "dev" "[:c :d]"))
            (unchanged-agree before [[:a] [:b]])
            (edit-store! bob "dev" #(str/replace % "{:a" "{:e \"five\" :a"))
            (unchanged-agree before [[:a] [:b]])
            (is (= (vhash-of manifest-key "five") (:vhash ((entries) [:e]))))))
        (testing "the key never moved, and each recipient's verify passes"
          (is (= manifest-key
                 (store-manifest-key ciphertext *key*)
                 (store-manifest-key ciphertext bob-key)))
          (is (= 0 (:exit (verify alice "dev"))))
          (is (= 0 (:exit (verify bob "dev")))))))))

(deftest a-removed-recipients-key-says-nothing-about-later-values-test
  ;; The reproduction from the threat model's manifest lessons, as a test. Bob
  ;; is a recipient and keeps the manifest key. He is removed, and Alice then
  ;; changes a 4-digit PIN. Bob tries every PIN under the key he kept.
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (doseq [[label after-removal!]
            [["reencrypt, then set" (fn [alice]
                                      (with-out-str (cli/reencrypt! alice "dev"))
                                      (set-value! alice ":pin" "4821"))]
             ["set without a reencrypt" (fn [alice] (set-value! alice ":pin" "4821"))]
             ["edit without a reencrypt"
              (fn [alice] (edit-store! alice "dev" #(str/replace % "1234" "4821")))]
             ["rm without a reencrypt, then set"
              (fn [alice]
                (with-out-str (cli/remove-secret! alice "dev" ":other"))
                (set-value! alice ":pin" "4821"))]]]
      (testing label
        (let [{:keys [alice bob-key alice-public recipients ciphertext manifest-path]}
              (team-fixture)
              candidates (map #(format "%04d" %) (range 10000))]
          (.delete (io/file ciphertext))
          (new-store! alice "dev" "{:pin \"1234\" :other \"x\"}")
          (let [retained (store-manifest-key ciphertext bob-key)
                published #(set (map :vhash (vals (:keys (manifest-of manifest-path)))))]
            (is (contains? (published) (vhash-of retained "1234"))
                "while Bob is a recipient his key does identify the PIN")
            (spit recipients (str alice-public "\n"))
            (after-removal! alice)
            (is (= "4821" (:pin (secrets/load-secrets ciphertext *key*))))
            (is (thrown? clojure.lang.ExceptionInfo (age/decrypt bob-key ciphertext))
                "Bob's identity no longer decrypts")
            (let [now (published)]
              (is (not-any? #(contains? now (vhash-of retained %)) candidates)
                  "no candidate PIN under the retained key matches a published hash")
              (is (contains? now (vhash-of (store-manifest-key ciphertext *key*) "4821"))
                  "the store's current key does, so the search above could have matched"))
            (is (= 0 (:exit (verify alice "dev"))))))))))

(deftest the-manifest-key-is-kept-until-the-recipients-change-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [{:keys [alice ciphertext recipients alice-public]} (team-fixture)
          current #(store-manifest-key ciphertext *key*)]
      (new-store! alice "dev" "{:a 1}")
      (let [created (current)]
        (set-value! alice ":b" "x")
        (edit-store! alice "dev" #(str/replace % ":a 1" ":a 2"))
        (with-out-str (cli/remove-secret! alice "dev" ":b"))
        (is (= created (current)) "set, edit, and rm keep the key")
        (with-out-str (cli/reencrypt! alice "dev"))
        (let [renewed (current)]
          (is (not= created renewed) "reencrypt generates a key even with the same recipients")
          (spit recipients (str alice-public "\n"))
          (let [out (set-value! alice ":c" "y")]
            (is (not= renewed (current)) "a write after a recipient change generates one too")
            (is (str/includes? out "Recipients changed since the last write")))
          (let [settled (current)]
            (set-value! alice ":d" "z")
            (is (= settled (current)) "and the next write keeps it")))))))

(deftest reserved-keys-never-reach-the-public-api-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          ciphertext (str *dir* "/secrets.edn.age")
          user-data {:database/url "jdbc:x" :nested {:token "t"}}]
      (new-store! config "dev" (pr-str user-data))
      (is (manifest-key? (store-manifest-key ciphertext *key*))
          "the store on disk does hold the key")
      (let [loaded (secrets/load-secrets ciphertext *key*)
            readers (secrets/reader-literals {:file ciphertext :identity-file *key*})
            req (readers 'secret/req)
            opt (readers 'secret/opt)]
        (is (= user-data loaded))
        (doseq [path [:com.kirahowe.secrets/store
                      [:com.kirahowe.secrets/store]
                      [:com.kirahowe.secrets/store :manifest-key]]]
          (testing (pr-str path)
            (is (nil? (secrets/get-secret loaded path)))
            (is (= ::absent (secrets/get-secret loaded path ::absent)))
            (is (nil? (opt path)))
            (is (= :missing-key
                   (:reason (ex-data (try (req path)
                                          (catch clojure.lang.ExceptionInfo e e))))))))
        (is (= "jdbc:x" (req :database/url) (opt :database/url)))
        (is (not (str/includes? (pr-str loaded) (store-manifest-key ciphertext *key*))))))))

(deftest set-rm-and-edit-cannot-touch-a-reserved-key-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          ciphertext (str *dir* "/secrets.edn.age")
          manifest-path (str *dir* "/secrets.edn.manifest")
          failure (fn [f] (try (with-out-str (f)) nil (catch clojure.lang.ExceptionInfo e e)))]
      (new-store! config "dev" ";; the team's notes\n{:a 1 ; inline note\n :b {:c 2}}\n")
      (let [manifest-key (store-manifest-key ciphertext *key*)
            bytes-before (file-bytes ciphertext)
            manifest-before (slurp manifest-path)
            untouched? #(and (= bytes-before (file-bytes ciphertext))
                             (= manifest-before (slurp manifest-path)))]
        (testing "set and rm refuse a path at or under a reserved key"
          (doseq [reserved [:com.kirahowe.secrets/store]
                  path [(pr-str reserved) (pr-str [reserved]) (pr-str [reserved :x])]
                  [label command] [["set" #(with-in-str "chosen-by-the-user"
                                             (cli/set-secret! config "dev" path false))]
                                   ["rm" #(cli/remove-secret! config "dev" path)]]]
            (testing (str label " " path)
              (let [e (failure command)]
                (is (= :reserved-key (:reason (ex-data e))))
                (is (str/includes? (ex-message e) "is reserved for the library's own metadata"))
                (is (not (str/includes? (str (ex-message e) (pr-str (ex-data e))) manifest-key))
                    "the refusal does not read the key out")
                (is (untouched?))))))
        (testing "edit shows the plaintext without reserved keys, exactly as it was written"
          (let [presented (atom nil)]
            (with-out-str
              (with-redefs-fn {(cli-private 'run-editor!) #(reset! presented (slurp %))}
                #(cli/edit! config "dev")))
            (is (= ";; the team's notes\n{:a 1 ; inline note\n :b {:c 2}}\n" @presented))
            (is (untouched?) "and an edit that changes nothing writes nothing")))
        (testing "a plaintext that comes back holding a reserved key is refused"
          (doseq [typed [(str "{:a 1 :com.kirahowe.secrets/store " (current-metadata) "}")
                         "{:a 1 :com.kirahowe.secrets/store nil}"
                         (str "{" (metadata-line (current-metadata)) ":a 1}")]]
            (let [e (failure #(with-redefs-fn {(cli-private 'run-editor!)
                                               (fn [path] (spit path typed))}
                                (fn [] (cli/edit! config "dev"))))]
              (is (= :reserved-key (:reason (ex-data e))))
              (is (str/includes? (ex-message e) "which the library reserves"))
              (is (untouched?)))))
        (testing "a saved edit keeps the key and the comments"
          (edit-store! config "dev" #(str/replace % ":a 1" ":a 10"))
          (is (= manifest-key (store-manifest-key ciphertext *key*)))
          (is (= {:a 10 :b {:c 2}} (secrets/load-secrets ciphertext *key*)))
          (let [presented (atom nil)]
            (with-out-str
              (with-redefs-fn {(cli-private 'run-editor!) #(reset! presented (slurp %))}
                #(cli/edit! config "dev")))
            (is (= ";; the team's notes\n{:a 10 ; inline note\n :b {:c 2}}\n" @presented)))
          (is (= 0 (:exit (verify config "dev")))))))))

(deftest a-store-without-usable-metadata-fails-until-reencrypt-test
  ;; Setting the key to nil once produced a manifest with no value hashes that
  ;; still verified. Every such store is an error now, on writes and on verify.
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          ciphertext (str *dir* "/secrets.edn.age")
          manifest-path (str *dir* "/secrets.edn.manifest")
          failure (fn [f] (try (with-out-str (f)) nil (catch clojure.lang.ExceptionInfo e e)))
          good-key (manifest/generate-key)
          short-key "0123456789abcdef"
          metadata (fn [overrides]
                     (pr-str (merge {:version 1 :manifest-key good-key :recipients "identity"}
                                    overrides)))
          store (fn [metadata-text] (str "{" (metadata-line metadata-text) ":a 1}"))
          messages {:missing "has no store metadata"
                    :malformed "holds malformed store metadata"
                    :unsupported-version "is in store format version 2, which"}]
      (doseq [[label text problem]
              [["missing" "{:a 1}" :missing]
               ["nil" (store "nil") :missing]
               ["not a map" (store (pr-str good-key)) :malformed]
               ["the two keys this key replaced"
                (str "{:com.kirahowe.secrets/manifest-key " (pr-str good-key)
                     " :com.kirahowe.secrets/manifest-recipients \"identity\" :a 1}")
                :missing]
               ["no version" (store (pr-str {:manifest-key good-key :recipients "identity"}))
                :malformed]
               ["a version that is not a number" (store (metadata {:version "1"})) :malformed]
               ["a later version" (store (metadata {:version 2})) :unsupported-version]
               ["a later version with other fields" (store "{:version 2 :hmac \"x\"}")
                :unsupported-version]
               ["a short key" (store (metadata {:manifest-key short-key})) :malformed]
               ["an upper-case key" (store (metadata {:manifest-key (str/upper-case good-key)}))
                :malformed]
               ["a key that is not a string" (store (metadata {:manifest-key 42})) :malformed]
               ["no recipients record" (store (pr-str {:version 1 :manifest-key good-key}))
                :malformed]
               ["a recipients record that is not a string" (store (metadata {:recipients 42}))
                :malformed]
               ["a field this version does not define" (store (metadata {:extra true}))
                :malformed]]]
        (testing label
          ;; A complete manifest first, so verify gets as far as the store.
          (encrypt-edn! {:a 1})
          (with-out-str (cli/reencrypt! config "dev"))
          (encrypt-text! text)
          (let [bytes-before (file-bytes ciphertext)
                manifest-before (slurp manifest-path)]
            (doseq [[command run]
                    [["set" #(with-in-str "v" (cli/set-secret! config "dev" ":b" false))]
                     ["rm" #(cli/remove-secret! config "dev" ":a")]
                     ["edit" #(with-redefs-fn {(cli-private 'run-editor!)
                                               (fn [path] (spit path "{:a 2}"))}
                                (fn [] (cli/edit! config "dev")))]]]
              (testing command
                (let [e (failure run)]
                  (is (= {:reason :invalid-store :problem problem}
                         (select-keys (ex-data e) [:reason :problem])))
                  (is (str/includes? (ex-message e) (messages problem)))
                  (is (str/includes? (ex-message e) "bb secrets reencrypt 'dev'"))
                  (is (not (str/includes? (str (ex-message e) (pr-str (ex-data e))) short-key))
                      "the failure never carries the value found")
                  (is (= bytes-before (file-bytes ciphertext)))
                  (is (= manifest-before (slurp manifest-path))))))
            (testing "verify"
              (let [{:keys [result err]} (capture-verify config "dev")]
                (is (= {:results {:dev :drift} :exit 1} result))
                (is (str/includes? err (messages problem)))
                (is (str/includes? err "bb secrets reencrypt 'dev'"))))
            (testing "loading returns the user's data and never the metadata"
              (is (not (contains? (secrets/load-secrets ciphertext *key*)
                                  :com.kirahowe.secrets/store))))
            ;; reencrypt takes out the line the library writes, a flat map, and
            ;; any other shape was put there by hand.
            (when (or (= "missing" label) (str/includes? text "/store {"))
              (testing "reencrypt writes a current store"
                (with-out-str (cli/reencrypt! config "dev"))
                (is (= {:version 1 :recipients "identity"}
                       (dissoc (:com.kirahowe.secrets/store
                                (edn/read-string (store-text ciphertext *key*)))
                               :manifest-key)))
                (is (manifest-key? (store-manifest-key ciphertext *key*)))
                (is (not= good-key (store-manifest-key ciphertext *key*)))
                (is (= {:a 1} (secrets/load-secrets ciphertext *key*)))
                (is (every? :vhash (vals (:keys (manifest-of manifest-path)))))
                (is (= 0 (:exit (verify config "dev"))))
                (set-value! config ":b" "v")
                (is (= {:a 1 :b "v"} (secrets/load-secrets ciphertext *key*)))))))))))

(deftest an-existing-store-that-is-not-a-map-says-so-test
  ;; The message once said the manifest key was missing and to run reencrypt,
  ;; which then refused the store for not being a map.
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          failure (fn [f] (try (with-out-str (f)) nil (catch clojure.lang.ExceptionInfo e e)))]
      (encrypt-edn! {:a 1})
      (with-out-str (cli/reencrypt! config "dev"))
      (encrypt-text! "[\"planted-value\" 2]")
      (doseq [[command run]
              [["set" #(with-in-str "v" (cli/set-secret! config "dev" ":b" false))]
               ["rm" #(cli/remove-secret! config "dev" ":a")]
               ["edit" #(with-redefs-fn {(cli-private 'run-editor!) (fn [_])}
                          (fn [] (cli/edit! config "dev")))]]]
        (testing command
          (let [e (failure run)]
            (is (= {:reason :invalid-store :problem :not-a-map}
                   (select-keys (ex-data e) [:reason :problem])))
            (is (str/includes? (ex-message e)
                               "holds a value of type vector where one EDN map is required"))
            (is (str/includes? (ex-message e) "Replace it with:  bb secrets new 'dev'"))
            (is (not (str/includes? (ex-message e) "reencrypt")))
            (is (not (str/includes? (str (ex-message e) (pr-str (ex-data e)))
                                    "planted-value"))))))
      (testing "verify"
        (let [{:keys [result err]} (capture-verify config "dev")]
          (is (= {:results {:dev :drift} :exit 1} result))
          (is (str/includes? err "where one EDN map is required"))
          (is (not (str/includes? err "reencrypt")))
          (is (not (str/includes? err "planted-value"))))))))

(deftest a-store-that-is-not-a-map-is-refused-test
  (let [config (cli/normalize-config (test-config))]
    (doseq [[text reason] [["[1 2 3]" :secrets-not-a-map]
                           ["\"just a string\"" :secrets-not-a-map]
                           ["#_ {:skipped 1} {:a 1}" :secrets-map-not-first]]]
      (let [e (try (new-store! config "dev" text) nil
                   (catch clojure.lang.ExceptionInfo e e))]
        (is (= reason (:reason (ex-data e))) text)
        (is (not (.exists (io/file (str *dir* "/secrets.edn.age")))))))))

(deftest a-failure-after-the-plaintext-is-written-leaves-no-temp-file-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          ciphertext (str *dir* "/secrets.edn.age")
          plaintexts (atom [])
          failing-encrypt (fn [_target in _out]
                            (swap! plaintexts conj {:path (str in) :text (slurp (str in))})
                            (throw (ex-info "forced encryption failure" {})))]
      (new-store! config "dev" "{:a 1}")
      (let [bytes-before (file-bytes ciphertext)]
        (doseq [[label run]
                [["new" #(with-redefs-fn {(cli-private 'run-editor!)
                                          (fn [path] (spit path "{:n 1}"))
                                          (cli-private 'confirm!) (constantly true)}
                           (fn [] (cli/new! config "dev")))]
                 ["edit" #(with-redefs-fn {(cli-private 'run-editor!)
                                           (fn [path] (spit path "{:e 1}"))}
                            (fn [] (cli/edit! config "dev")))]
                 ["set" #(with-in-str "v" (cli/set-secret! config "dev" ":s" false))]
                 ["rm" #(cli/remove-secret! config "dev" ":a")]
                 ["reencrypt" #(cli/reencrypt! config "dev")]]]
          (testing label
            (reset! plaintexts [])
            (is (thrown-with-msg?
                 clojure.lang.ExceptionInfo #"forced encryption failure"
                 (with-out-str (with-redefs [age/encrypt-file! failing-encrypt] (run)))))
            (let [[{:keys [path text]}] @plaintexts]
              (is (= 1 (count @plaintexts)))
              (is (str/includes? text ":com.kirahowe.secrets/store {:version 1 ")
                  "the failure came after the keyed plaintext was on disk")
              (is (re-matches #"secrets-.*\.edn" (.getName (io/file path)))
                  "in the command's own private temp file, not a second one")
              (is (not (.exists (io/file path))) "which is gone"))
            (is (= bytes-before (file-bytes ciphertext)))))))))

(deftest verify-continues-past-an-environment-that-throws-test
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [missing (str *dir* "/no-such-key.txt")
          other-key (str *dir* "/other-key.txt")
          env (fn [n key-file] {:secrets-file (str *dir* "/" n ".edn.age") :key-file key-file})
          config (fn [envs] (cli/normalize-config {:app "cli-test" :environments envs}))
          good {:good (env "good" *key*) :fine (env "fine" *key*)}
          all (config (assoc good
                             :no-identity (env "no-identity" missing)
                             :wrong-key (env "wrong-key" other-key)))]
      (age/keygen! other-key)
      (doseq [n ["good" "fine" "wrong-key"]]
        (with-out-str
          (with-in-str "v" (cli/set-secret! (config {(keyword n) (env n *key*)}) n ":k" false))))
      (testing "each failing environment is reported and the others are verified"
        (let [{:keys [result out err]} (capture-verify all nil)]
          (is (= {:good :ok :fine :ok :no-identity :error :wrong-key :error} (:results result)))
          (is (= 2 (:exit result)))
          (is (str/includes? err (str "no-identity — The configured :key-file names an age"
                                      " identity file that does not exist: " missing)))
          (is (str/includes? out "Create it with `bb secrets keygen`."))
          (is (str/includes? err "wrong-key —"))
          (is (= 2 (count (re-seq #"manifest matches" out))))))
      (testing "an environment named on the command line still throws"
        (is (= :no-identity
               (:reason (ex-data (try (verify all "no-identity")
                                      (catch clojure.lang.ExceptionInfo e e)))))))
      (testing "drift in another environment still decides the exit code"
        (spit (str *dir* "/fine.edn.manifest") "{:version 3}")
        (let [{:keys [result]} (capture-verify all nil)]
          (is (= {:good :ok :fine :drift :no-identity :error :wrong-key :error}
                 (:results result)))
          (is (= 1 (:exit result))))))))

(deftest command-failures-carry-a-reason-test
  ;; Every failure a command throws has a :reason, so a caller never has to
  ;; guess from the other keys in its data.
  (if (age-env-set?)
    (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
    (let [config (cli/normalize-config (test-config))
          reason-of (fn [f]
                      (:reason (ex-data (try (with-out-str (f)) nil
                                             (catch clojure.lang.ExceptionInfo e e)))))]
      (is (= :invalid-config
             (reason-of #(cli/normalize-config {:environments {:dev {:secrets-file "s.age"}}}))))
      (is (= :usage (reason-of #(cli/edit! config "nowhere"))))
      (is (= :no-file (reason-of #(cli/edit! config "dev"))))
      (is (= :no-file (reason-of #(cli/reencrypt! config "dev"))))
      (is (= :no-recipients (reason-of #(cli/add-recipient! config "dev" nil))))
      (is (= :blank-value
             (reason-of #(with-in-str "" (cli/set-secret! config "dev" ":a" false)))))
      (is (= :usage (reason-of #(with-in-str "v" (cli/set-secret! config "dev" "42" false)))))
      (with-out-str (with-in-str "v" (cli/set-secret! config "dev" ":a" false)))
      (is (= :no-such-key (reason-of #(cli/remove-secret! config "dev" ":absent"))))
      (testing "a store the configured key cannot decrypt"
        (let [other-key (str *dir* "/other-key.txt")]
          (age/keygen! other-key)
          (is (= :decrypt-failed
                 (reason-of #(cli/edit! (cli/normalize-config (test-config {:key-file other-key}))
                                        "dev")))))))))
