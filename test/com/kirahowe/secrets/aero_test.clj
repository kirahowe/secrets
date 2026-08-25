(ns com.kirahowe.secrets.aero-test
  "Tests for the aero.core integration, exercising the real `age` binary and a
  real `aero.core/read-config` call, like the core suite. Each test runs in a
  throwaway temp directory with a freshly generated key.

  `register!` is compatibility state with a process-wide lifecycle, and the
  reader cache belongs to that lifecycle: `(register! nil)` ends it and retires
  every entry cached under it. `with-clean-registration` therefore starts and
  ends every test from a cleared registration, so mutable state cannot bleed
  between scenarios."
  (:require [aero.core :as aero]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.aero :as secrets-aero]
            [com.kirahowe.secrets.age :as age]))

;;;; Fixtures

(def ^:dynamic ^:private *dir* nil)
(def ^:dynamic ^:private *key* nil)

(defn- with-tmp-key [f]
  (let [dir (str (java.nio.file.Files/createTempDirectory
                  "kira-secrets-aero-test"
                  (into-array java.nio.file.attribute.FileAttribute [])))
        key (str dir "/key.txt")]
    (age/keygen! key)
    (binding [*dir* dir *key* key]
      (try
        (f)
        (finally
          (doseq [p (reverse (file-seq (io/file dir)))] (.delete p)))))))

(defn- with-clean-registration [f]
  ;; Clearing the registration retires its cache too, so this is one call.
  (secrets-aero/register! nil)
  (try
    (f)
    (finally
      (secrets-aero/register! nil))))

(use-fixtures :each with-tmp-key with-clean-registration)

;;;; Helpers

(defn- encrypt-edn!
  "Write `m` as EDN, encrypt it to <dir>/<filename>, drop the plaintext, and
  return the ciphertext path. `filename` defaults to secrets.edn.age; tests
  that need two distinct secrets files or a wrong-key fixture pass their own
  filename or identity."
  ([m] (encrypt-edn! m "secrets.edn.age" *key*))
  ([m filename] (encrypt-edn! m filename *key*))
  ([m filename identity-file]
   (let [plain (str *dir* "/" filename ".plain.edn")
         enc (str *dir* "/" filename)]
     (spit plain (pr-str m))
     (age/encrypt-file! identity-file plain enc)
     (.delete (io/file plain))
     enc)))

(defn- spit-config! [contents]
  (let [f (str *dir* "/config.edn")]
    (spit f contents)
    f))

(defn- sentinel-loader
  "A stand-in for `secrets/reader-literals` that reads no ciphertext at all:
  every load hands out a fresh sentinel value, so a value read through a
  `#secret/…` tag names the load that produced it and the config it was loaded
  for. Returns `[produced loader]`, where `produced` is an atom holding every
  sentinel handed out, oldest first — the loader's whole history."
  []
  (let [produced (atom [])]
    [produced
     (fn [config]
       (let [v (peek (swap! produced
                            #(conj % {:load (inc (count %)) :config config})))]
         {'secret/req (constantly v)
          'secret/opt (constantly v)}))]))

;;;; Registration and resolution

(deftest register-round-trip-test
  (testing (str "#secret/req and #secret/opt resolve through a real aero.core/read-config, "
                "config from register!")
    (let [enc (encrypt-edn! {:database/url "jdbc:x" :llm/api-key "sk-123"})
          cfg (spit-config! "{:url #secret/req :database/url
                              :key #secret/opt :llm/api-key
                              :absent #secret/opt :not-there}")]
      (secrets-aero/register! {:file enc :identity-file *key*})
      (let [read (aero/read-config cfg)]
        (is (= "jdbc:x" (:url read)))
        (is (= "sk-123" (:key read)))
        (is (nil? (:absent read)) "#secret/opt on a missing key is nil")))))

(deftest per-read-secrets-overrides-registered-test
  (testing "a per-read :secrets opt wins over the registered default"
    (let [registered-enc (encrypt-edn! {:v :registered} "registered.edn.age")
          override-enc (encrypt-edn! {:v :override} "override.edn.age")
          cfg (spit-config! "{:v #secret/req :v}")]
      (secrets-aero/register! {:file registered-enc :identity-file *key*})
      (is (= :registered (:v (aero/read-config cfg)))
          "with no :secrets opt, the registered default is used")
      (is (= :override (:v (aero/read-config
                            cfg {:secrets {:file override-enc :identity-file *key*}})))
          "a :secrets opt on the read overrides the registered default"))))

(deftest no-secrets-config-throws-test
  (testing "no registered default and no :secrets opt names both ways to supply one"
    (let [cfg (spit-config! "{:v #secret/opt :anything}")
          e (is (thrown-with-msg?
                 clojure.lang.ExceptionInfo #"No secrets config found"
                 (aero/read-config cfg)))]
      (is (re-find #"register!" (ex-message e)))
      (is (re-find #":secrets" (ex-message e))))))

(deftest aero-failure-context-is-allowlisted-test
  (let [sentinel "SENTINELaerooptsMUSTNEVERAPPEAR"
        rendered (fn [e]
                   (str/join "\n"
                             (for [link (take-while some? (iterate #(.getCause ^Throwable %) e))
                                   part [(pr-str link) (str (ex-message link))
                                         (pr-str (ex-data link))]]
                               part)))]
    (testing "a missing secrets config names the profile and the opt keys, never a value"
      (let [cfg (spit-config! "{:v #secret/opt :anything}")
            e (is (thrown-with-msg?
                   clojure.lang.ExceptionInfo #"No secrets config found"
                   (aero/read-config cfg {:profile :staging :vault-token sentinel})))
            data (ex-data e)]
        (is (= :staging (:profile data)))
        (is (= [:profile :resolver :source :vault-token] (:aero-opt-keys data))
            "every key aero passed is named, including the two it adds itself")
        (is (nil? (:aero-opts data)) "and the opts map itself is not retained")
        (is (not (str/includes? (rendered e) sentinel)))))
    (testing "a sentinel-bearing :secrets config reaches no failure either"
      (let [cfg (spit-config! "{:v #secret/req :v}")
            e (is (thrown-with-msg?
                   clojure.lang.ExceptionInfo #"no secrets file found"
                   (aero/read-config cfg {:profile :staging
                                          :vault-token sentinel
                                          :secrets {:file (str *dir* "/absent.edn.age")
                                                    :identity-file *key*
                                                    :tenant sentinel}})))]
        (is (= :no-file (:reason (ex-data e))))
        (is (not (str/includes? (rendered e) sentinel))
            "the config is the cache key, and a cache key is not a diagnostic")))))

;;;; Reader cache

(deftest decrypts-once-across-tags-and-reads-test
  (testing (str "several #secret/... tags across multiple reads sharing one config "
                "decrypt exactly once")
    (let [enc (encrypt-edn! {:a 1 :b 2 :c 3})
          calls (atom 0)
          real age/decrypt]
      (with-redefs [age/decrypt (fn [& args] (swap! calls inc) (apply real args))]
        (secrets-aero/register! {:file enc :identity-file *key*})
        (let [cfg (spit-config! "{:a #secret/req :a
                                   :b #secret/req :b
                                   :c #secret/opt :c
                                   :missing #secret/opt :missing}")
              want {:a 1 :b 2 :c 3 :missing nil}
              read1 (aero/read-config cfg)
              ;; A second read with an aero opts map carrying unrelated keys.
              ;; The cache key is the extracted :secrets config, not the whole
              ;; aero opts map, so this must not be a cache miss.
              read2 (aero/read-config cfg {:foo :bar})]
          (is (= want read1))
          (is (= want read2))
          (is (= 1 @calls)
              "decryption is memoized across tags and reads sharing one config"))))))

(deftest reset-cache-picks-up-edits-test
  (testing (str "reset-cache! drops memoized readers so a later read decrypts "
                "the current file")
    (let [enc (encrypt-edn! {:v :old})
          cfg (spit-config! "{:v #secret/req :v}")
          calls (atom 0)
          real age/decrypt]
      (with-redefs [age/decrypt (fn [& args] (swap! calls inc) (apply real args))]
        (secrets-aero/register! {:file enc :identity-file *key*})
        (is (= :old (:v (aero/read-config cfg))))
        ;; Edit the underlying secrets file in place, the way `bb secrets edit` would.
        (encrypt-edn! {:v :new})
        (is (= :old (:v (aero/read-config cfg)))
            "without reset-cache!, the memoized readers still serve the stale value")
        (is (= 1 @calls) "the cached Aero readers do not decrypt the edit")
        (secrets-aero/reset-cache!)
        (is (= :new (:v (aero/read-config cfg)))
            "after reset-cache!, the edited file is decrypted fresh")
        (is (= 2 @calls)
            "reset invalidates the cached reader and decrypted store")))))

(deftest reset-cache-recovers-from-real-decryption-failure-test
  (testing "a wrong-key failure remains cached after repair until reset-cache!"
    (let [wrong-key (str *dir* "/wrong-key.txt")
          _ (age/keygen! wrong-key)
          enc (encrypt-edn! {:v :unreadable} "secrets.edn.age" wrong-key)
          cfg (spit-config! "{:v #secret/req :v}")
          calls (atom 0)
          real age/decrypt]
      (with-redefs [age/decrypt (fn [& args] (swap! calls inc) (apply real args))]
        (secrets-aero/register! {:file enc :identity-file *key*})
        (is (thrown-with-msg?
             clojure.lang.ExceptionInfo #"age decryption failed"
             (aero/read-config cfg))
            "the first read genuinely asks age to decrypt wrong-key ciphertext")
        (encrypt-edn! {:v :repaired})
        (is (thrown-with-msg?
             clojure.lang.ExceptionInfo #"age decryption failed"
             (aero/read-config cfg))
            "repairing the ciphertext does not retry the cached failure")
        (is (= 1 @calls)
            "the cached Aero reader rethrows without another decrypt attempt")
        (secrets-aero/reset-cache!)
        (is (= :repaired (:v (aero/read-config cfg)))
            "reset retries against the repaired ciphertext without re-registering")
        (is (= 2 @calls)
            "reset causes exactly one fresh successful decrypt")))))

;;;; Cache lifecycle

;;; These tests instrument the loader instead of the real `age` binary: the
;;; question is which lifecycle a cached value belongs to, and a sentinel names
;;; that unambiguously where a decrypted value cannot.

(deftest clearing-a-registration-retires-its-cache-test
  (testing "(register! nil) retires every entry cached under the registration"
    (let [a {:file "store.age" :identity-file "key.txt"}
          cfg (spit-config! "{:v #secret/req :v}")
          [produced loader] (sentinel-loader)]
      (with-redefs [secrets/reader-literals loader]
        (secrets-aero/register! a)
        (let [retired (:v (aero/read-config cfg))]
          (is (= {:load 1 :config a} retired) "the first read loads once")
          (secrets-aero/register! nil)
          (let [fresh (:v (aero/read-config cfg {:secrets a}))]
            (is (not= retired fresh) "the retired sentinel is never returned again")
            (is (= {:load 2 :config a} fresh) "the read after the clear loads again")
            (is (= 2 (count @produced)) "exactly one extra load, not a cache hit")))))))

(deftest equal-replacement-cannot-reuse-the-retired-lifecycle-test
  (testing "an equal replacement config is still a new lifecycle with an empty cache"
    (let [a {:file "store.age" :identity-file "key.txt"}
          b (into {} a)
          cfg (spit-config! "{:v #secret/req :v}")
          [produced loader] (sentinel-loader)]
      (is (= a b) "the replacement compares equal to the config it replaces")
      (is (not (identical? a b)) "and is genuinely a different map")
      (with-redefs [secrets/reader-literals loader]
        (secrets-aero/register! a)
        (let [retired (:v (aero/read-config cfg))]
          (secrets-aero/register! b)
          (let [fresh (:v (aero/read-config cfg))]
            (is (not= retired fresh)
                "an equal config cannot inherit the retired lifecycle's plaintext")
            (is (= [{:load 1 :config a} {:load 2 :config b}] @produced)
                "each lifecycle performed its own load")))))))

(deftest cached-failures-are-retired-too-test
  (testing "a cached load failure is retired by reset-cache! and by register!"
    (let [a {:file "store.age" :identity-file "key.txt"}
          cfg (spit-config! "{:v #secret/req :v}")
          calls (atom 0)
          loader (fn [_config]
                   (swap! calls inc)
                   (throw (ex-info "sentinel load failure" {})))]
      (with-redefs [secrets/reader-literals loader]
        (secrets-aero/register! a)
        (is (thrown-with-msg? clojure.lang.ExceptionInfo #"sentinel load failure"
                              (aero/read-config cfg)))
        (is (thrown-with-msg? clojure.lang.ExceptionInfo #"sentinel load failure"
                              (aero/read-config cfg)))
        (is (= 1 @calls) "the failure itself is cached rather than retried per read")
        (secrets-aero/reset-cache!)
        (is (thrown-with-msg? clojure.lang.ExceptionInfo #"sentinel load failure"
                              (aero/read-config cfg)))
        (is (= 2 @calls) "reset-cache! retires the cached failure")
        (secrets-aero/register! a)
        (is (thrown-with-msg? clojure.lang.ExceptionInfo #"sentinel load failure"
                              (aero/read-config cfg)))
        (is (= 3 @calls) "an equal re-registration retires it too")))))

(deftest concurrent-reads-never-see-a-retired-entry-test
  (testing "readers racing register! never observe a load from a retired lifecycle"
    (let [configs [{:file "a.age" :tenant :a} {:file "b.age" :tenant :b}]
          cfg (spit-config! "{:v #secret/req :v}")
          [produced loader] (sentinel-loader)
          read-once (fn [config]
                      (try
                        {:config config :v (:v (aero/read-config cfg {:secrets config}))}
                        (catch Exception e {:config config :error (ex-message e)})))]
      (with-redefs [secrets/reader-literals loader]
        (dotimes [_ 4]
          ;; Opening a round retires every load so far, so no read below may
          ;; return one: that is the invariant, independent of interleaving.
          (secrets-aero/register! (configs 0))
          (let [retired (count @produced)
                churn (future (dotimes [_ 20] (secrets-aero/register! (configs 0))))
                readers (mapv (fn [i]
                                (future (mapv (fn [_] (read-once (configs (mod i 2))))
                                              (range 20))))
                              (range 6))
                settled (mapv #(deref % 60000 ::timeout) readers)
                results (into [] cat (remove #{::timeout} settled))
                sentinels (set @produced)]
            (is (not= ::timeout (deref churn 60000 ::timeout)) "the churn thread finished")
            (is (not-any? #{::timeout} settled) "every reader thread finished")
            (is (empty? (keep :error results)) "no read threw")
            (is (every? #(contains? sentinels (:v %)) results)
                "every value is one the loader actually produced")
            (is (every? #(= (:config %) (:config (:v %))) results)
                "and was loaded for the config that read asked for")
            (is (every? #(> (:load (:v %)) retired) results)
                "no read returned a load from a lifecycle retired before it started")))))))

(deftest distinct-tenant-configs-do-not-share-a-cache-entry-test
  (testing "the config map is the cache key, so a distinguishing key isolates a tenant"
    (let [a {:file "store.age" :tenant :a}
          b {:file "store.age" :tenant :b}
          cfg (spit-config! "{:v #secret/req :v}")
          [produced loader] (sentinel-loader)]
      (with-redefs [secrets/reader-literals loader]
        (let [va (:v (aero/read-config cfg {:secrets a}))
              vb (:v (aero/read-config cfg {:secrets b}))]
          (is (not= va vb) "one differing key gives each config its own decrypted store")
          (is (= [{:load 1 :config a} {:load 2 :config b}] @produced) "two separate loads")
          (is (= va (:v (aero/read-config cfg {:secrets (into {} a)})))
              "an equal config inside one lifecycle deliberately shares the entry")
          (is (= 2 (count @produced)) "sharing means no third load"))))))

(deftest one-load-per-live-lifecycle-test
  (testing "many reads of one config inside one lifecycle load exactly once"
    (let [a {:file "store.age" :identity-file "key.txt"}
          cfg (spit-config! "{:v #secret/req :v :w #secret/opt :w}")
          [produced loader] (sentinel-loader)]
      (with-redefs [secrets/reader-literals loader]
        (secrets-aero/register! a)
        (let [reads (mapv (fn [_] (aero/read-config cfg)) (range 5))]
          (is (= [{:load 1 :config a}] @produced) "five reads, ten tags, one load")
          (is (apply = reads) "every read saw the same decrypted store")
          (is (= {:load 1 :config a} (:v (first reads)))))))))

;;;; Aero evaluation

(deftest profile-evaluates-only-the-selected-branch-test
  (testing "#profile picks a branch before the #secret tag in it is read, so the key
            in the unselected branch does not have to exist"
    ;; The README documents this as the way to give eval runs their own key, and
    ;; the promise that makes it safe is that adding a profile for a key some
    ;; consumers do not have cannot break them. That is aero's behaviour, not
    ;; ours, so pin it: an aero change would otherwise turn the docs into a lie.
    (let [enc (encrypt-edn! {:openrouter/api-key "sk-default"})
          cfg (spit-config!
               (str "{:api-key #profile {:default #secret/req :openrouter/api-key\n"
                    "                    :evals   #secret/req "
                    ":openrouter/evals-api-key}}"))]
      (secrets-aero/register! {:file enc :identity-file *key*})
      (is (= {:api-key "sk-default"} (aero/read-config cfg))
          "the :evals key is absent from the store, and the default profile does not care")
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo #"missing from the secrets file"
           (aero/read-config cfg {:profile :evals}))
          "selecting that profile does evaluate it, and it is genuinely missing"))))

(deftest register-returns-and-replaces-config-test
  (testing (str "register! returns the config map and is idempotent "
                "(replaces, not accumulates)")
    (let [a {:file "a" :identity-file "ka"}
          b {:file "b" :identity-file "kb"}]
      (is (= a (secrets-aero/register! a)))
      (is (= b (secrets-aero/register! b))))))
