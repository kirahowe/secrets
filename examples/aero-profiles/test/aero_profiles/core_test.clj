(ns aero-profiles.core-test
  (:require [aero-profiles.bootstrap :as bootstrap]
            [aero-profiles.core :as app]
            [clojure.java.io :as io]
            [clojure.test :refer [deftest is testing use-fixtures]]))

(def ^:private secrets
  "Pin the disposable key explicitly, so the test depends neither on the
  environment nor on a key under ~/.config."
  {:file "tmp/secrets.edn.age" :identity-file "tmp/key.txt"})

(defn- with-disposable-secrets [f]
  (try
    (bootstrap/run!)
    (f)
    (finally
      (bootstrap/clean!)
      ;; Keep the directory itself disposable too, when empty.
      (.delete (io/file "tmp")))))

(use-fixtures :each with-disposable-secrets)

(deftest profiles-select-different-safe-results-test
  (testing "default and evals select their own required key branches"
    (let [default (app/run! secrets)
          evals (app/run! secrets "evals")]
      (is (= :default (:profile default)))
      (is (= "default" (:profile-name default)))
      (is (= :evals (:profile evals)))
      (is (= "evals" (:profile-name evals)))
      (is (not= (:profile-name default) (:profile-name evals)))
      (is (true? (:api-key-configured default)))
      (is (true? (:api-key-configured evals)))
      (is (false? (:optional-integration-configured default)))
      (is (false? (:optional-integration-configured evals))))))
