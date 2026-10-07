(ns com.kirahowe.secrets.aero-test
  "Tests for the Aero integration. They run the real `age` binary and real
  Aero reads, each in a throwaway directory with a freshly generated key."
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

(use-fixtures :each with-tmp-key)

;;;; Helpers

(defn- encrypt-edn!
  "Encrypt `m` to <dir>/secrets.edn.age with `identity-file` (the test key by
  default) and return the options that read it back with the test key."
  ([m] (encrypt-edn! m *key*))
  ([m identity-file]
   (let [plain (str *dir* "/secrets.edn")
         enc (str plain ".age")]
     (spit plain (pr-str m))
     (age/encrypt-file! identity-file plain enc)
     (.delete (io/file plain))
     {:file enc :identity-file *key*})))

(defn- spit-config!
  ([contents] (spit-config! "config.edn" contents))
  ([filename contents]
   (let [f (str *dir* "/" filename)]
     (spit f contents)
     f)))

(defn- counting
  "Wrap `f` so each call also increments the atom `calls`."
  [calls f]
  (fn [& args] (swap! calls inc) (apply f args)))

(defn- thrown-by [f]
  (try (f) nil (catch clojure.lang.ExceptionInfo e e)))

;;;; One load per read

(deftest resolves-both-tags-test
  (let [store (encrypt-edn! {:database/url "jdbc:x" :llm/api-key "sk-123"})
        cfg (spit-config! "{:url #secret/req :database/url
                            :key #secret/opt :llm/api-key
                            :absent #secret/opt :not-there
                            :port 8080}")]
    (is (= {:url "jdbc:x" :key "sk-123" :absent nil :port 8080}
           (secrets-aero/read-config cfg {:secrets store})))))

(deftest several-tags-decrypt-once-test
  (let [store (encrypt-edn! {:a 1 :b 2 :c 3})
        cfg (spit-config! "{:a #secret/req :a
                            :b #secret/req :b
                            :c #secret/opt :c
                            :missing #secret/opt :missing}")
        calls (atom 0)]
    (with-redefs [age/decrypt (counting calls age/decrypt)]
      (is (= {:a 1 :b 2 :c 3 :missing nil}
             (secrets-aero/read-config cfg {:secrets store})))
      (is (= 1 @calls) "four tags share one decryption"))))

(deftest config-without-secret-tags-loads-nothing-test
  (let [store (encrypt-edn! {:a 1})
        cfg (spit-config! "{:port #long \"8080\" :host \"localhost\"}")
        calls (atom 0)]
    (with-redefs [age/decrypt (counting calls age/decrypt)
                  secrets/with-identity (counting calls secrets/with-identity)
                  secrets/load-secrets (counting calls secrets/load-secrets)]
      (is (= {:port 8080 :host "localhost"}
             (secrets-aero/read-config cfg {:secrets store})))
      (is (zero? @calls) "no identity is resolved and nothing is decrypted"))))

(deftest reads-are-independent-test
  (let [store (encrypt-edn! {:v :old})
        cfg (spit-config! "{:v #secret/req :v}")
        calls (atom 0)]
    (with-redefs [age/decrypt (counting calls age/decrypt)]
      (is (= {:v :old} (secrets-aero/read-config cfg {:secrets store})))
      (encrypt-edn! {:v :new})
      (is (= {:v :new} (secrets-aero/read-config cfg {:secrets store}))
          "the second read sees the edited store")
      (is (= 2 @calls) "each read decrypts for itself"))))

(deftest failed-read-leaves-nothing-behind-test
  (let [other-key (str *dir* "/other-key.txt")
        _ (age/keygen! other-key)
        store (encrypt-edn! {:v :unreadable} other-key)
        cfg (spit-config! "{:v #secret/req :v}")]
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"age decryption failed"
                          (secrets-aero/read-config cfg {:secrets store})))
    (encrypt-edn! {:v :repaired})
    (is (= {:v :repaired} (secrets-aero/read-config cfg {:secrets store}))
        "the same options succeed once the store is fixed")))

;;;; The tags are the core reader literals

(deftest unavailable-store-test
  (let [cfg-opt (spit-config! "{:v #secret/opt :v}")
        cfg-req (spit-config! "required.edn" "{:v #secret/req :v}")
        reason (fn [opts]
                 (:reason (ex-data (thrown-by #(secrets-aero/read-config cfg-req opts)))))
        store (encrypt-edn! {:v 1})]
    (testing "no store"
      (let [absent {:file (str *dir* "/absent.edn.age") :identity-file *key*}]
        (is (= {:v nil} (secrets-aero/read-config cfg-opt {:secrets absent})))
        (is (= :no-file (reason {:secrets absent})))))
    (testing "no :secrets options at all"
      (is (= {:v nil} (secrets-aero/read-config cfg-opt {})))
      (is (= :no-file (reason {}))))
    (testing "no identity"
      (let [keyless (assoc store :identity-file (str *dir* "/absent-key.txt"))]
        (is (= {:v nil} (secrets-aero/read-config cfg-opt {:secrets keyless})))
        (is (= :no-identity (reason {:secrets keyless})))))))

(deftest missing-required-key-is-the-core-error-test
  (let [store (encrypt-edn! {:present 1})
        cfg (spit-config! "{:v #secret/req :absent/key}")
        core-error (thrown-by #((get (secrets/reader-literals store) 'secret/req)
                                :absent/key))
        e (thrown-by #(secrets-aero/read-config cfg {:secrets store}))]
    (is (= :missing-key (:reason (ex-data e))))
    (is (= (ex-message core-error) (ex-message e)))
    (is (= (ex-data core-error) (ex-data e)))))

(deftest plain-aero-read-names-the-fix-test
  (let [sentinel "SENTINELaerooptsMUSTNEVERAPPEAR"
        cfg (spit-config! "{:v #secret/opt :v}")
        e (thrown-by #(aero/read-config cfg {:secrets (encrypt-edn! {:v 1})
                                             :vault-token sentinel}))]
    (is (str/includes? (ex-message e) "com.kirahowe.secrets.aero/read-config"))
    (is (= {:tag 'secret/opt} (ex-data e)) "the failure carries the tag only")
    (is (not (str/includes? (pr-str e) sentinel)))))

;;;; Composition with Aero's own tags

(deftest profile-reads-only-the-selected-branch-test
  (let [store (encrypt-edn! {:openrouter/api-key "sk-default"})
        cfg (spit-config!
             "{:api-key #profile {:default #secret/req :openrouter/api-key
                                  :evals   #secret/req :openrouter/evals-api-key}}")]
    (is (= {:api-key "sk-default"} (secrets-aero/read-config cfg {:secrets store}))
        "the :evals key is absent from the store and the default profile ignores it")
    (is (= :missing-key
           (:reason (ex-data (thrown-by #(secrets-aero/read-config
                                          cfg {:profile :evals :secrets store})))))
        "selecting :evals does read its key")))

(deftest ref-and-include-compose-test
  (let [store (encrypt-edn! {:db/password "pw" :api/token "tok"})
        calls (atom 0)
        _ (spit-config! "included.edn" "{:token #secret/req :api/token}")
        cfg (spit-config! "{:password #secret/req :db/password
                            :db {:password #ref [:password]
                                 :url #join [\"jdbc://u:\" #ref [:password] \"@h\"]}
                            :api #include \"included.edn\"}")]
    (with-redefs [age/decrypt (counting calls age/decrypt)]
      (is (= {:password "pw"
              :db {:password "pw" :url "jdbc://u:pw@h"}
              :api {:token "tok"}}
             (secrets-aero/read-config cfg {:secrets store})))
      (is (= 1 @calls) "the included file shares the read's one decryption"))))
