(ns example.quickstart.core
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [com.kirahowe.secrets :as secrets]))

(defn read-config! []
  (let [readers (secrets/merge-readers {}
                                       {:file ".local/secrets.edn.age"
                                        :identity-file ".local/age-key.txt"})]
    (edn/read-string {:readers readers}
                     (slurp (io/file "config.edn")))))

(defn -main [& _]
  (let [{:keys [service]} (read-config!)
        api-key (:api-key service)]
    ;; Deliberately report only safe facts; the secret value never reaches stdout.
    (println "Endpoint configured?:" (boolean (and (string? (:endpoint service))
                                                   (not-empty (:endpoint service)))))
    (println "API key configured?:" (boolean (and (string? api-key)
                                                  (not-empty api-key))))))
