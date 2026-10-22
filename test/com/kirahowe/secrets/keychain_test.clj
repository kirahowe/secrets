(ns com.kirahowe.secrets.keychain-test
  "Exit-status handling of the Keychain lookups, against a fake `security`.
  Nothing here reaches the real Keychain."
  (:require [clojure.test :refer [deftest is testing]]
            [com.kirahowe.secrets.fs :as fs]
            [com.kirahowe.secrets.keychain :as keychain]
            [com.kirahowe.secrets.test-env :as test-env]))

(defn- with-security
  "Call `f` with `fs/sh` answering every command with `result`."
  [result f]
  (with-redefs [fs/sh (fn [_argv & _] result)]
    (f)))

(deftest has-key?-test
  (testing "exit 0 means the item exists"
    (is (true? (with-security {:exit 0 :out "" :err ""} #(keychain/has-key? "app")))))
  (testing "exit 44 means there is no item"
    (is (false? (with-security {:exit 44 :out "" :err "not found"}
                  #(keychain/has-key? "app")))))
  (testing "any other exit is a failure, not absence"
    (let [e (test-env/thrown
             (fn [] (with-security {:exit 36 :out "" :err "User interaction is not allowed."}
                      #(keychain/has-key? "app"))))]
      (is (= {:reason :keychain-failed :service "com.kirahowe.secrets"
              :account "app" :exit 36}
             (ex-data e)))
      (is (re-find #"security exited 36: User interaction is not allowed" (ex-message e))))))

(deftest read-key-test
  (testing "exit 0 returns the trimmed key"
    (is (= "AGE-SECRET-KEY-1"
           (with-security {:exit 0 :out "AGE-SECRET-KEY-1\n" :err ""}
             #(keychain/read-key "app")))))
  (testing "exit 44 means there is no key"
    (is (nil? (with-security {:exit 44 :out "" :err ""} #(keychain/read-key "app")))))
  (testing "any other exit throws :keychain-failed"
    (let [e (test-env/thrown
             (fn [] (with-security {:exit 51 :out "" :err "denied"}
                      #(keychain/read-key "app"))))]
      (is (= :keychain-failed (:reason (ex-data e))))
      (is (= 51 (:exit (ex-data e)))))))
