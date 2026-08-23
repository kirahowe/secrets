(ns example.integrant-service.build
  (:require [clojure.tools.build.api :as b]))

(def class-dir "target/classes")
(def uber-file "target/integrant-service-standalone.jar")
(def basis (delay (b/create-basis {:project "deps.edn" :aliases [:prod]})))

(defn clean [_]
  (b/delete {:path "target"}))

(defn uber [_]
  (clean nil)
  (b/copy-dir {:src-dirs ["resources/common" "resources/prod"]
               :target-dir class-dir})
  (b/compile-clj {:basis @basis
                  :src-dirs ["src"]
                  :class-dir class-dir})
  (b/uber {:class-dir class-dir
           :uber-file uber-file
           :basis @basis
           :main 'example.integrant-service.main})
  (println "Wrote" uber-file))
