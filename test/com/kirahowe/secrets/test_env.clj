(ns com.kirahowe.secrets.test-env
  "The one seam through which tests replace the environment the runtime reads,
  and the helpers the property suites share."
  (:require [com.kirahowe.secrets :as secrets]))

(defn getenv-redefs
  "Return a `with-redefs-fn` binding map that makes `environment`, a map of
  variable name to value, the whole environment the runtime sees. A variable
  absent from the map is unset. Only the raw read is replaced, so the blank
  check and everything else in identity resolution still runs."
  [environment]
  {#'secrets/getenv #(get environment %)})

(defn thrown
  "The `Exception` that calling `f` throws, or nil when it returns."
  [f]
  (try (f) nil (catch Exception e e)))

(defn rendered
  "Everything a reader of logs could see of `e`: the message and data of the
  throwable, of each cause, and of each suppressed throwable."
  [e]
  (let [walk (fn walk [t]
               (when t
                 (cons (str (ex-message t) " " (pr-str (ex-data t)))
                       (concat (walk (ex-cause t))
                               (mapcat walk (.getSuppressed ^Throwable t))))))]
    (apply str (interpose "\n" (walk e)))))

(defn permission-names
  "The POSIX permissions of `path` itself, as names such as \"OWNER_READ\"."
  [path]
  (set (map str (java.nio.file.Files/getPosixFilePermissions
                 (.toPath (java.io.File. (str path)))
                 (into-array java.nio.file.LinkOption [])))))

(def owner-only-names #{"OWNER_READ" "OWNER_WRITE"})
