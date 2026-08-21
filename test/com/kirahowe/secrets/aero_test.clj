(ns com.kirahowe.secrets.aero-test
  "Tests for the aero.core integration, exercising the real `age` binary and a
  real `aero.core/read-config` call, like the core suite. Each test runs in a
  throwaway temp directory with a freshly generated key.

  `register!` and the reader-functions cache live in process-wide `defonce`
  atoms (that's the point of them — they need to survive a REPL/server's
  whole lifetime), so `with-clean-registration` resets both before and after
  every test to keep tests from bleeding state into each other."
  (:require [aero.core :as aero]
            [clojure.java.io :as io]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.aero :as secrets-aero]))

(def ^:dynamic *dir* nil)
(def ^:dynamic *key* nil)

(defn with-tmp-key [f]
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

(defn with-clean-registration [f]
  (secrets-aero/reset-cache!)
  (secrets-aero/register! nil)
  (try
    (f)
    (finally
      (secrets-aero/reset-cache!)
      (secrets-aero/register! nil))))

(use-fixtures :each with-tmp-key with-clean-registration)

(defn- encrypt-edn!
  "Write `m` as EDN, encrypt it to <dir>/<filename>, drop the plaintext, and
  return the ciphertext path. `filename` defaults to secrets.edn.age; tests
  that need two distinct secrets files (e.g. registered vs. per-read) pass
  their own."
  ([m] (encrypt-edn! m "secrets.edn.age"))
  ([m filename]
   (let [plain (str *dir* "/" filename ".plain.edn")
         enc   (str *dir* "/" filename)]
     (spit plain (pr-str m))
     (age/encrypt-file! *key* plain enc)
     (.delete (io/file plain))
     enc)))

(defn- spit-config! [contents]
  (let [f (str *dir* "/config.edn")]
    (spit f contents)
    f))

(deftest register-round-trip
  (testing "#secret/req and #secret/opt resolve through a real aero.core/read-config, config from register!"
    (let [enc (encrypt-edn! {:database/url "jdbc:x" :llm/api-key "sk-123"})
          cfg (spit-config! "{:url #secret/req :database/url
                              :key #secret/opt :llm/api-key
                              :absent #secret/opt :not-there}")]
      (secrets-aero/register! {:file enc :identity-file *key*})
      (let [read (aero/read-config cfg)]
        (is (= "jdbc:x" (:url read)))
        (is (= "sk-123" (:key read)))
        (is (nil? (:absent read)) "#secret/opt on a missing key is nil")))))

(deftest per-read-secrets-overrides-registered
  (testing "a per-read :secrets opt wins over the registered default"
    (let [registered-enc (encrypt-edn! {:v :registered} "registered.edn.age")
          override-enc   (encrypt-edn! {:v :override} "override.edn.age")
          cfg            (spit-config! "{:v #secret/req :v}")]
      (secrets-aero/register! {:file registered-enc :identity-file *key*})
      (is (= :registered (:v (aero/read-config cfg)))
          "with no :secrets opt, the registered default is used")
      (is (= :override (:v (aero/read-config
                             cfg {:secrets {:file override-enc :identity-file *key*}})))
          "a :secrets opt on the read overrides the registered default"))))

(deftest no-secrets-config-throws
  (testing "no registered default and no :secrets opt names both ways to supply one"
    (let [cfg (spit-config! "{:v #secret/opt :anything}")
          e   (is (thrown-with-msg?
                    clojure.lang.ExceptionInfo #"No secrets config found"
                    (aero/read-config cfg)))]
      (is (re-find #"register!" (ex-message e)))
      (is (re-find #":secrets" (ex-message e))))))

(deftest decrypts-once-across-tags-and-reads
  (testing "several #secret/... tags across multiple reads sharing one config decrypt exactly once"
    (let [enc   (encrypt-edn! {:a 1 :b 2 :c 3})
          calls (atom 0)
          real  age/decrypt]
      (with-redefs [age/decrypt (fn [& args] (swap! calls inc) (apply real args))]
        (secrets-aero/register! {:file enc :identity-file *key*})
        (let [cfg  (spit-config! "{:a #secret/req :a
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

(deftest reset-cache-picks-up-edits
  (testing "reset-cache! drops memoized readers so a later read decrypts the current file"
    (let [enc (encrypt-edn! {:v :old})
          cfg (spit-config! "{:v #secret/req :v}")]
      (secrets-aero/register! {:file enc :identity-file *key*})
      (is (= :old (:v (aero/read-config cfg))))
      ;; Edit the underlying secrets file in place, the way `bb secrets edit` would.
      (let [plain (str *dir* "/new-plain.edn")]
        (spit plain (pr-str {:v :new}))
        (age/encrypt-file! *key* plain enc)
        (.delete (io/file plain)))
      (is (= :old (:v (aero/read-config cfg)))
          "without reset-cache!, the memoized readers still serve the stale value")
      (secrets-aero/reset-cache!)
      (is (= :new (:v (aero/read-config cfg)))
          "after reset-cache!, the edited file is decrypted fresh"))))

(deftest register-returns-and-replaces-config
  (testing "register! returns the config map and is idempotent (replaces, not accumulates)"
    (let [a {:file "a" :identity-file "ka"}
          b {:file "b" :identity-file "kb"}]
      (is (= a (secrets-aero/register! a)))
      (is (= b (secrets-aero/register! b))))))
