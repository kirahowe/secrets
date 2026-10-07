(ns com.kirahowe.secrets.aero
  "Optional Aero integration: `#secret/req` and `#secret/opt` inside an Aero
  config.

  Aero is not a dependency of this library. Add it to your own project, then
  read the config with this namespace's `read-config` in place of
  `aero.core/read-config`, putting the secrets options under `:secrets`:

      (require '[com.kirahowe.secrets.aero :as secrets-aero])

      (secrets-aero/read-config \"config.edn\"
                                {:profile :dev
                                 :secrets {:app \"myapp\"
                                           :resource \"secrets.edn.age\"}})

  `:secrets` takes the options of `com.kirahowe.secrets/reader-literals`, and
  the two tags behave as they do there, with the same errors. Every other key
  goes to Aero untouched.

  Each call decrypts the store at most once, when it reaches the first secret
  tag, and a config without secret tags never opens it. Nothing is kept
  between calls, so a second read sees an edited store and a read that failed
  can be retried.

  Requiring this namespace registers the two tags on `aero.core/reader`. A
  config with secret tags read through `aero.core/read-config` directly throws
  an error that names `read-config` here."
  (:require [aero.core :as aero]
            [com.kirahowe.secrets :as secrets]))

(defn read-config
  "Read the Aero config `source` as `aero.core/read-config` does, resolving
  `#secret/req` and `#secret/opt` against the store that `(:secrets opts)`
  describes. See the namespace docstring."
  [source opts]
  (aero/read-config
   source
   (assoc opts ::readers (secrets/reader-literals (:secrets opts)))))

(defn- read-secret [opts tag value]
  (if-let [handler (get (::readers opts) tag)]
    (handler value)
    (throw (ex-info (str "#" tag " needs com.kirahowe.secrets.aero/read-config;"
                         " aero.core/read-config alone cannot load secrets.")
                    {:tag tag}))))

(defmethod aero/reader 'secret/req [opts tag value] (read-secret opts tag value))
(defmethod aero/reader 'secret/opt [opts tag value] (read-secret opts tag value))
