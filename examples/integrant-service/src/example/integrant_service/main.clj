(ns example.integrant-service.main
  (:gen-class)
  (:require [clojure.java.io :as io]
            [integrant.core :as ig]
            [example.integrant-service.system :as system]))

(defn- read-config []
  (if-let [resource (io/resource "config.edn")]
    (ig/read-string {:readers {}} (slurp resource))
    (throw (ex-info "No config.edn found on the classpath; choose :dev or :prod"
                    {:reason :missing-config}))))

(defn -main [& _]
  (let [app-system (ig/init (read-config))
        http        (get app-system system/http-key)]
    ;; This is deliberately the only application output: it contains no
    ;; secret data, just the bound port.
    (println "integrant-service listening on" (:port http))
    (.addShutdownHook (Runtime/getRuntime)
                      (Thread. ^Runnable #(ig/halt! app-system)))
    ;; Keep the tiny service alive until the process receives a signal.
    @(promise)))
