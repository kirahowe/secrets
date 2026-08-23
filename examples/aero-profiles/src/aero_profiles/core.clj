(ns aero-profiles.core
  (:refer-clojure :exclude [run!])
  (:require [aero.core :as aero]
            [com.kirahowe.secrets.aero :as secrets-aero]))

;; Requiring the optional integration installs #secret/req and #secret/opt.
(def ^:private secrets-config
  {:file "tmp/secrets.edn.age"
   :identity-file "tmp/key.txt"})

(defn reset-cache!
  "Drop decrypted data so a REPL can observe a later secrets edit."
  []
  (secrets-aero/reset-cache!))

(defn run!
  ([] (run! "default" nil))
  ([profile] (run! profile nil))
  ([profile reset]
   (when (= "reset" reset) (reset-cache!))
   (let [profile (keyword (or profile "default"))
         config (aero/read-config "config.edn"
                                  {:profile profile
                                   ;; Per-read configuration is intentionally
                                   ;; explicit; no process-wide register! call.
                                   :secrets secrets-config})
         status {:profile profile
                 :profile-name (:profile-name config)
                 :api-key-configured (some? (:api-key config))
                 :optional-integration-configured
                 (some? (:optional-integration config))}]
     (println (pr-str status))
     ;; Return only the derived status as well, so a REPL caller cannot
     ;; accidentally echo a resolved secret map.
     status)))

(defn -main [& args]
  (run! (first args) (second args)))
