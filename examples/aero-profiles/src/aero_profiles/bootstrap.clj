(ns aero-profiles.bootstrap
  (:refer-clojure :exclude [run!])
  (:require [clojure.java.io :as io]
            [clojure.java.shell :as shell]))

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

(defn- age!
  "Run the `age` or `age-keygen` command line `argv`, throwing when it fails."
  [& argv]
  (let [{:keys [exit err]} (apply shell/sh argv)]
    (when-not (zero? exit)
      (throw (ex-info (str (first argv) " failed") {:exit exit :err err})))))

(defn run!
  "Generate disposable fake credentials and encrypt them, without printing them."
  []
  (.mkdirs (io/file dir))
  ;; A rerun must not leave a ciphertext encrypted to a replaced key after a
  ;; partial failure. The exact files are disposable and safe to recreate.
  (clean!)
  (age! "age-keygen" "-o" key-file)
  (spit plain-file (pr-str {:openrouter/api-key "fake-default-key"
                            :openrouter/evals-api-key "fake-evals-key"}))
  (try
    (age! "age" "-e" "-i" key-file "-o" encrypted-file plain-file)
    (finally (.delete (io/file plain-file))))
  (println "Bootstrap complete: disposable key and ciphertext are in tmp/ (gitignored).")
  (println "Run with: SECRETS_AGE_IDENTITY_FILE=tmp/key.txt bb run"))
