(ns aero-profiles.core-test
  (:require [clojure.java.io :as io]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [aero-profiles.bootstrap :as bootstrap]
            [aero-profiles.core :as app]))

(defn with-disposable-secrets [f]
  (try
    (bootstrap/run!)
    (f)
    (finally
      (bootstrap/clean!)
      ;; Keep the directory itself disposable too, when empty.
      (.delete (io/file "tmp")))))

(use-fixtures :each with-disposable-secrets)

(deftest source-is-loadable
  (testing "the starter exposes a REPL cache reset hook"
    (is (nil? (app/reset-cache!)))))

(deftest profiles-select-different-safe-results
  (testing "default and evals select their own required key branches"
    (let [default (app/run!)
          evals   (app/run! "evals")]
      (is (= :default (:profile default)))
      (is (= "default" (:profile-name default)))
      (is (= :evals (:profile evals)))
      (is (= "evals" (:profile-name evals)))
      (is (not= (:profile-name default) (:profile-name evals)))
      (is (true? (:api-key-configured default)))
      (is (true? (:api-key-configured evals)))
      (is (false? (:optional-integration-configured default)))
      (is (false? (:optional-integration-configured evals))))))
