(ns aero-profiles.core
  (:refer-clojure :exclude [run!])
  (:require [com.kirahowe.secrets.aero :as secrets-aero]))

(defn run!
  "Read `config.edn` for `profile` and print a value-free status.

  `secrets` is the options map behind the `#secret/…` tags: where the
  ciphertext is, plus `:app` or `:identity-file` for the key. Aero needs it
  before it can read the file, so it cannot live in `config.edn`. This
  example's `bb.edn` supplies it, and the test passes its own."
  ([secrets] (run! secrets "default"))
  ([secrets profile]
   (let [profile (keyword profile)
         ;; Each read decrypts the store for itself, so calling `run!` again
         ;; after editing the secrets picks up the edit.
         config (secrets-aero/read-config "config.edn"
                                          {:profile profile :secrets secrets})
         status {:profile profile
                 :profile-name (:profile-name config)
                 :api-key-configured (some? (:api-key config))
                 :optional-integration-configured
                 (some? (:optional-integration config))}]
     (println (pr-str status))
     ;; Return only the derived status as well, so a REPL caller cannot
     ;; accidentally echo a resolved secret map.
     status)))
