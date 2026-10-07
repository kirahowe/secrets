(ns com.kirahowe.secrets.fs-property-test
  "Properties of owner-only temporary files: whatever name is asked for, the
  file exists empty, is readable and writable by its owner alone, and never
  collides with another."
  (:require [clojure.string :as str]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [com.kirahowe.secrets.fs :as fs]
            [com.kirahowe.secrets.test-env :as test-env]))

(def ^:private no-links (into-array java.nio.file.LinkOption []))

(defspec temp-files-are-private-empty-and-distinct 25
  (prop/for-all [prefix gen/string-alphanumeric
                 suffix (gen/elements ["" ".txt" ".age" ".plaintext"])]
    (let [a (fs/owner-only-temp-file! prefix suffix)
          b (fs/owner-only-temp-file! prefix suffix)]
      (try
        (and (not= (.getPath a) (.getPath b))
             (every? (fn [f]
                       (and (java.nio.file.Files/isRegularFile (.toPath f) no-links)
                            (zero? (.length f))
                            (str/starts-with? (.getName f) prefix)
                            (str/ends-with? (.getName f) suffix)
                            (= test-env/owner-only-names (test-env/permission-names f))))
                     [a b]))
        (finally
          (.delete a)
          (.delete b))))))
