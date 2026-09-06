(ns aero-profiles.core
  (:refer-clojure :exclude [run!])
  (:require [aero.core :as aero]
            [com.kirahowe.secrets.aero :as secrets-aero]))

;;; Requiring the optional integration installs #secret/req and #secret/opt.

(defn reset-cache!
  "Drop decrypted data so a REPL can observe a later secrets edit."
  []
  (secrets-aero/reset-cache!))

(defn run!
  "Read `config.edn` for `profile` and print a value-free status.

  `secrets` is the options map behind the `#secret/…` tags: where the
  ciphertext is, plus `:app` or `:identity-file` for the key. Aero needs it
  before it can read the file, so it cannot live in `config.edn`. This
  example's `bb.edn` supplies it, and the test passes its own."
  ([secrets] (run! secrets "default" nil))
  ([secrets profile] (run! secrets profile nil))
  ([secrets profile reset]
   (when (= "reset" reset) (reset-cache!))
   (let [profile (keyword (or profile "default"))
         config (aero/read-config "config.edn"
                                  {:profile profile
                                   ;; Per-read configuration is intentionally
                                   ;; explicit; no process-wide register! call.
                                   :secrets secrets})
         status {:profile profile
                 :profile-name (:profile-name config)
                 :api-key-configured (some? (:api-key config))
                 :optional-integration-configured
                 (some? (:optional-integration config))}]
     (println (pr-str status))
     ;; Return only the derived status as well, so a REPL caller cannot
     ;; accidentally echo a resolved secret map.
     status)))
