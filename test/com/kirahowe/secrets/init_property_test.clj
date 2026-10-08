(ns com.kirahowe.secrets.init-property-test
  "Properties of the initializer's names and options: an accepted name gives a
  configuration that reads back and that the CLI accepts, any other text is
  refused without being echoed, and parsed options read back."
  (:require [clojure.edn :as edn]
            [clojure.string :as str]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [com.kirahowe.secrets.cli :as cli]
            [com.kirahowe.secrets.generators :as g]
            [com.kirahowe.secrets.init :as init]))

(def ^:private plain-name
  "A name the initializer accepts: a letter, then letters, digits, dots,
  hyphens, or underscores."
  (gen/let [head gen/char-alpha
            tail (gen/vector (gen/one-of [gen/char-alphanumeric (gen/elements [\- \_ \.])])
                             0 15)]
    (str/join (cons head tail))))

(def ^:private not-plain-name
  (gen/such-that #(not (re-matches #"[A-Za-z][A-Za-z0-9._-]*" %)) g/text 100))

(defn- refused-without-echo? [opts text]
  (try
    (init/proposed-config opts)
    false
    (catch clojure.lang.ExceptionInfo e
      (and (str/includes? (ex-message e) "plain name")
           (or (str/blank? text) (not (str/includes? (ex-message e) text)))))))

(defspec a-name-that-is-not-plain-is-refused-without-being-echoed 200
  (prop/for-all [text not-plain-name]
    (and (refused-without-echo? {:app text} text)
         (refused-without-echo? {:app "reader" :env text} text))))

(defspec plain-names-give-a-task-that-reads-back-and-normalizes 100
  (prop/for-all [app plain-name
                 env plain-name]
    (let [config (init/proposed-config {:app app :env env})
          task (init/task-spec config)
          self-dependency (#'init/self-dependency app)
          environment (get-in (cli/normalize-config config) [:environments (keyword env)])]
      (and (= task (edn/read-string (pr-str task)))
           (= self-dependency (edn/read-string (pr-str self-dependency)))
           (= (keyword env) (:default-environment config))
           (= "secrets/secrets.edn.example" (:template environment))
           (= "secrets/secrets.edn.manifest" (:manifest environment))))))

(defspec parse-args-reads-back-the-options-it-was-given 100
  (prop/for-all [app plain-name
                 env plain-name
                 flags (gen/vector (gen/elements ["--keygen" "--apply"]) 0 2)]
    (let [opts (init/parse-args (into ["--app" app "--env" env] (distinct flags)))
          flag-set (set flags)]
      (and (= app (:app opts))
           (= env (:env opts))
           (= (contains? flag-set "--keygen") (true? (:keygen? opts)))
           (= (contains? flag-set "--apply") (true? (:apply? opts)))))))
