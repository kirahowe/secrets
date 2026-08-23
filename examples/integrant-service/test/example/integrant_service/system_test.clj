(ns example.integrant-service.system-test
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [com.kirahowe.secrets :as secrets]
            [example.integrant-service.system :as system]
            [integrant.core :as ig])
  (:import (java.net URI)
           (java.net.http HttpClient HttpRequest HttpResponse$BodyHandlers)))

(defn- get-health! [port]
  (let [request (-> (HttpRequest/newBuilder
                     (URI/create (str "http://127.0.0.1:" port "/health")))
                    .GET
                    .build)]
    (.body (.send (HttpClient/newHttpClient)
                  request
                  (HttpResponse$BodyHandlers/ofString)))))

(deftest ordinary-map-can-replace-secrets-component-test
  (testing "a test system can inject a map without initializing age"
    (let [fake-secret "never-return-this-value"
          app-system (ig/init {system/http-key {:port 0
                                                ;; This is an ordinary map,
                                                ;; not an Integrant ref.
                                                :secrets {:token fake-secret}}})]
      (try
        (let [body (get-health! (:port (get app-system system/http-key)))
              status (:status (get app-system system/http-key))]
          (is (= {:status "ok" :secrets-configured true :secret-count 1}
                 status))
          (is (str/includes? body "\"secretsConfigured\":true"))
          (is (str/includes? body "\"secretCount\":1"))
          (is (not (str/includes? body fake-secret))))
        (finally
          (ig/halt! app-system))))))

(deftest secrets-component-delegates-to-load-secrets-test
  (testing "the Integrant component passes the classpath resource and options"
    (let [called (atom nil)
          requested (atom nil)
          source (Object.)
          loaded {:example "test-value"}]
      (with-redefs [io/resource (fn [resource-name]
                                  (reset! requested resource-name)
                                  source)
                    secrets/load-secrets
                    (fn [source options]
                      (reset! called [source options])
                      loaded)]
        (let [app-system (ig/init {system/secrets-key {:resource "missing.age"
                                                       :app "example-app"}
                                   system/http-key {:port 0
                                                    :secrets (ig/ref system/secrets-key)}})]
          (try
            (is (= loaded (get app-system system/secrets-key)))
            (is (= "missing.age" @requested))
            (is (identical? source (first @called)))
            (is (= {:app "example-app"} (second @called)))
            (finally
              (ig/halt! app-system))))))))
