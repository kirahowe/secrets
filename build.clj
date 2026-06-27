(ns build
  "Build, install, and publish the library.

    clojure -T:build jar       ; build target/secrets-<version>.jar
    clojure -T:build install   ; jar + install to ~/.m2 (resolves :mvn/version locally)
    clojure -T:build deploy    ; jar + push to Clojars (needs CLOJARS_USERNAME/PASSWORD)

  Consumers depend on the published coordinate:  com.kirahowe/secrets {:mvn/version \"…\"}."
  (:require [clojure.tools.build.api :as b]))

(def lib 'com.kirahowe/secrets)
(def version "0.1.0")
(def class-dir "target/classes")
(def basis (delay (b/create-basis {:project "deps.edn"})))
(def jar-file (format "target/%s-%s.jar" (name lib) version))

(defn clean [_]
  (b/delete {:path "target"}))

(defn jar [_]
  (clean nil)
  (b/write-pom {:class-dir class-dir
                :lib       lib
                :version   version
                :basis     @basis
                :src-dirs  ["src"]
                :scm       {:url "https://github.com/kirahowe/secrets"}
                :pom-data  [[:description
                             "Manage application secrets as a version-controlled, age-encrypted EDN file."]
                            [:licenses
                             [:license
                              [:name "MIT"]
                              [:url "https://opensource.org/license/mit"]]]]})
  (b/copy-dir {:src-dirs   ["src" "resources"]
               :target-dir class-dir})
  (b/jar {:class-dir class-dir
          :jar-file  jar-file})
  (println "Wrote" jar-file))

(defn install [_]
  (jar nil)
  (b/install {:basis     @basis
              :lib       lib
              :version   version
              :jar-file  jar-file
              :class-dir class-dir})
  (println "Installed" lib version "to ~/.m2"))

(defn deploy [_]
  (jar nil)
  ((requiring-resolve 'deps-deploy.deps-deploy/deploy)
   {:installer :remote
    :artifact  jar-file
    :pom-file  (b/pom-path {:lib lib :class-dir class-dir})})
  (println "Deployed" lib version "to Clojars"))
