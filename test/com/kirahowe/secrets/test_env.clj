(ns com.kirahowe.secrets.test-env
  "The one seam through which tests replace the environment the runtime reads."
  (:require [com.kirahowe.secrets :as secrets]))

(defn getenv-redefs
  "Return a `with-redefs-fn` binding map that makes `environment`, a map of
  variable name to value, the whole environment the runtime sees. A variable
  absent from the map is unset. Only the raw read is replaced, so the blank
  check and everything else in identity resolution still runs."
  [environment]
  {#'secrets/getenv #(get environment %)})
