(ns aero-profiles.bootstrap
  (:refer-clojure :exclude [run!])
  (:require [clojure.java.io :as io]
            [com.kirahowe.secrets.age :as age]))

(def ^:private dir "tmp")
(def ^:private key-file (str dir "/key.txt"))
(def ^:private plain-file (str dir "/secrets.edn"))
(def ^:private encrypted-file (str dir "/secrets.edn.age"))

(defn clean!
  "Remove only this example's disposable files; never touches other tmp data."
  []
  (doseq [path [key-file plain-file encrypted-file]]
    (.delete (io/file path)))
  nil)

(defn run!
  "Generate disposable fake credentials and encrypt them, without printing them."
  []
  (.mkdirs (io/file dir))
  ;; A rerun must not leave a ciphertext encrypted to a replaced key after a
  ;; partial failure. The exact files are disposable and safe to recreate.
  (clean!)
  (age/keygen! key-file)
  (spit plain-file (pr-str {:openrouter/api-key "fake-default-key"
                            :openrouter/evals-api-key "fake-evals-key"}))
  (try
    (age/encrypt-file! key-file plain-file encrypted-file)
    (finally (.delete (io/file plain-file))))
  (println "Bootstrap complete: disposable key and ciphertext are in tmp/ (gitignored).")
  (println "Run with: SECRETS_AGE_IDENTITY_FILE=tmp/key.txt bb run"))
