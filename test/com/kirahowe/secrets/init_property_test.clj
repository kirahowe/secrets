(ns com.kirahowe.secrets.init-property-test
  "Properties of the initializer's option handling: an accepted name reads back
  as the symbol and keyword it becomes, any other text is refused, the proposed
  configuration is one the CLI accepts, and parsed options read back."
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

(defspec self-dependency-is-the-app-name-as-a-symbol 200
  (prop/for-all [app plain-name]
    (let [dependency (init/self-dependency app)
          [sym coordinate] (first dependency)]
      (and (= 1 (count dependency))
           (= {:local/root "."} coordinate)
           (= app (name sym) (namespace sym))
           (= dependency (edn/read-string (pr-str dependency)))))))

(defspec a-name-that-is-not-plain-is-refused-without-being-echoed 200
  (prop/for-all [text not-plain-name]
    (try
      (init/self-dependency text)
      false
      (catch clojure.lang.ExceptionInfo e
        (and (str/includes? (ex-message e) "plain name")
             (or (str/blank? text) (not (str/includes? (ex-message e) text))))))))

(defspec proposed-configurations-read-back-and-normalize 100
  (prop/for-all [app plain-name
                 env plain-name
                 layout (gen/elements [:tracked :disposable])
                 team? gen/boolean]
    (let [config (init/proposed-config {:app app :env env :layout layout :team? team?})
          proposed (get-in config [:environments (keyword env)])
          environment (get-in (cli/normalize-config config) [:environments (keyword env)])
          disposable? (= :disposable layout)]
      (and (= config (edn/read-string (pr-str config)))
           (= (:secrets-file proposed) (:secrets-file environment))
           (= disposable? (str/starts-with? (:secrets-file environment) ".local/"))
           (= disposable? (contains? proposed :key-file))
           (= team? (some? (:recipients-file environment)))))))

(defspec parse-args-reads-back-the-options-it-was-given 100
  (prop/for-all [app plain-name
                 env plain-name
                 layout (gen/elements ["tracked" "disposable"])
                 flags (gen/vector (gen/elements ["--team" "--keygen" "--apply"]) 0 3)]
    (let [opts (init/parse-args (into ["--app" app "--env" env "--layout" layout]
                                      (distinct flags)))
          flag-set (set flags)]
      (and (= app (:app opts))
           (= env (:env opts))
           (= (keyword layout) (:layout opts))
           (= (contains? flag-set "--team") (true? (:team? opts)))
           (= (contains? flag-set "--keygen") (true? (:keygen? opts)))
           (= (contains? flag-set "--apply") (true? (:apply? opts)))))))
