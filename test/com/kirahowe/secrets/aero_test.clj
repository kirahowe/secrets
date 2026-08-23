(ns com.kirahowe.secrets.aero-test
  "Tests for the aero.core integration, exercising the real `age` binary and a
  real `aero.core/read-config` call, like the core suite. Each test runs in a
  throwaway temp directory with a freshly generated key.

  `register!` is compatibility state with a process-wide lifecycle, and the
  reader-functions cache is process-wide by design. `with-clean-registration`
  explicitly resets both before and after every test so their mutable state
  cannot bleed between scenarios."
  (:require [aero.core :as aero]
            [clojure.java.io :as io]
            [clojure.test :refer [deftest is testing use-fixtures]]
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
  (secrets-aero/reset-cache!)
  (secrets-aero/register! nil)
  (try
    (f)
    (finally
      (secrets-aero/reset-cache!)
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
