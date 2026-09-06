(ns com.kirahowe.secrets.init-property-test
  "Properties of the initializer's pure parts: a preview never prints a
  planted credential or a control sequence, a hunk reconstructs both files,
  gitignore merging adds a line once, generated symbols read back, proposed
  configurations normalize, and merging into bb.edn or deps.edn keeps what
  was there."
  (:require [clojure.edn :as edn]
            [clojure.pprint :as pprint]
            [clojure.string :as str]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [com.kirahowe.secrets.cli :as cli]
            [com.kirahowe.secrets.generators :as g]
            [com.kirahowe.secrets.init :as init]))

(def ^:private escape-control @#'init/escape-control)
(def ^:private redact @#'init/redact)
(def ^:private render-line @#'init/render-line)
(def ^:private changed-region @#'init/changed-region)
(def ^:private merge-gitignore @#'init/merge-gitignore)
(def ^:private default-dependency @#'init/default-dependency)

;;;; Escaping

(defn- control-char?
  "A C0 or C1 control character, or DEL: what a terminal would act on."
  [c]
  (let [n (int c)]
    (or (< n 0x20) (= n 0x7f) (<= 0x80 n 0x9f))))

(defn- control-free? [s]
  (not-any? control-char? s))

(defspec escape-control-leaves-nothing-a-terminal-acts-on 200
  (prop/for-all [s g/text]
    (let [out (escape-control s)]
      (and (control-free? out)
           (>= (count out) (count s))
           (or (not (control-free? s)) (= s out))))))

;;;; Redaction

(defn- occurrences [s sub]
  (count (re-seq (re-pattern (java.util.regex.Pattern/quote sub)) s)))

(def ^:private secretish-name
  "A key name the redaction rules treat as naming a credential, in some of
  the spellings a config file uses."
  (gen/let [prefix (gen/elements ["" ":" ":db-" ":api_" "\"" "aws." "MY_"])
            word (gen/elements ["secret" "token" "password" "key" "credential"
                                "SECRET" "Password" "apikey"])
            suffix (gen/elements ["" "-id" "s" "_1" "\""])]
    (str prefix word suffix)))

(def ^:private planted-value
  (gen/fmap str/join (gen/vector gen/char-alphanumeric 4 24)))

(def ^:private keyed-line
  "A line holding a value under a credential-like key: `{:line :secret}`."
  (gen/let [name secretish-name
            separator (gen/elements [" " ": " "=" " = " ":" "\t"])
            value planted-value
            quoted? gen/boolean
            before (gen/elements ["" "{" " " "{:a 1 " "  "])
            after (gen/elements ["" "}" " :other 2}"])]
    {:line (str before name separator (if quoted? (pr-str value) value) after)
     :secret value}))

(def ^:private age-key-line
  (gen/let [key g/age-secret-key
            before (gen/elements ["" ":identity \"" "AGE=" "  "])
            after (gen/elements ["" "\"" " # mine"])]
    {:line (str before key after) :secret key}))

(def ^:private opaque-token
  "A long run of token characters holding at least one letter and one digit."
  (gen/such-that #(and (re-find #"[A-Za-z]" %) (re-find #"[0-9]" %))
                 (gen/fmap str/join
                           (gen/vector (gen/elements (vec (str "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                                               "abcdefghijklmnopqrstuvwxyz"
                                                               "0123456789+/=_-")))
                                       32 64))
                 50))

(def ^:private token-line
  (gen/let [token opaque-token
            before (gen/elements ["" ":build-id \"" "sha " "{:x "])
            after (gen/elements ["" "\"" "}" " trailing"])]
    {:line (str before token after) :secret token}))

(defspec redact-hides-every-planted-credential 300
  (prop/for-all [{:keys [line secret]} (gen/one-of [keyed-line age-key-line token-line])]
    (let [out (redact line)]
      (and (< (occurrences out secret) (occurrences line secret))
           (str/includes? out "[redacted ")))))

(def ^:private long-line
  (gen/fmap str/join (gen/vector (gen/one-of [g/wide-char gen/char-alphanumeric]) 0 300)))

(defspec rendered-lines-are-safe-to-print 200
  (prop/for-all [s long-line]
    (let [out (render-line s)]
      (and (control-free? out)
           (<= (count out) 200)))))

;;;; Hunks

(def ^:private file-lines
  "Lines over a tiny alphabet, so shared prefixes and suffixes are common."
  (gen/vector (gen/elements ["a" "b" "c" ""]) 0 12))

(defspec a-hunk-reconstructs-both-files 300
  (prop/for-all [olds file-lines
                 news file-lines]
    (let [{:keys [from before removed added after]} (changed-region olds news)
          prefix (+ from (count before))
          old-end (+ prefix (count removed))]
      (and (<= (count before) 3)
           (<= (count after) 3)
           (= olds (concat (subvec olds 0 from) before removed after
                           (subvec olds (+ old-end (count after)))))
           (= news (concat (subvec olds 0 prefix) added (subvec olds old-end)))
           (or (empty? removed) (empty? added)
               (and (not= (first removed) (first added))
                    (not= (peek removed) (peek added))))))))

;;;; .gitignore

(defn- has-line? [content line]
  (some #(= (str/trim %) (str/trim line)) (str/split-lines (or content ""))))

(def ^:private gitignore-line
  (gen/elements ["/.local/secrets/" "tmp/" "*.log" " /.local/secrets/ " ".DS_Store"]))

(def ^:private gitignore-noise
  (gen/elements ["" "# comment" "target/"]))

(def ^:private gitignore
  (gen/one-of [(gen/return nil)
               (gen/fmap (fn [[lines tail]] (str (str/join "\n" lines) tail))
                         (gen/tuple (gen/vector (gen/one-of [gitignore-line gitignore-noise]) 0 6)
                                    (gen/elements ["" "\n" "\n\n"])))]))

(defspec gitignore-merge-adds-a-line-once-and-keeps-the-rest 200
  (prop/for-all [old gitignore
                 line gitignore-line]
    (let [once (merge-gitignore old line)
          twice (merge-gitignore once line)]
      (and (= once twice)
           (str/starts-with? once (or old ""))
           (has-line? once line)
           (if (has-line? old line)
             (= old once)
             (and (str/ends-with? once line)
                  (contains? #{"" "\n"}
                             (subs once (count (or old "")) (- (count once) (count line))))))))))

;;;; Symbols and configurations

(defspec self-dependency-is-a-symbol-every-reader-accepts 200
  (prop/for-all [app g/text]
    (let [dependency (init/self-dependency app)
          [sym coordinate] (first dependency)]
      (and (= 1 (count dependency))
           (= {:local/root "."} coordinate)
           (symbol? sym)
           (= (name sym) (namespace sym))
           (some? (re-matches #"[A-Za-z_][A-Za-z0-9_-]*" (name sym)))
           (= dependency (edn/read-string (pr-str dependency)))))))

(def ^:private name-text
  (gen/fmap str/join
            (gen/vector (gen/one-of [gen/char-alphanumeric (gen/elements [\- \_ \.])]) 1 16)))

(defspec proposed-configurations-normalize 100
  (prop/for-all [app name-text
                 env name-text
                 layout (gen/elements [:tracked :disposable])
                 team? gen/boolean]
    (let [config (init/proposed-config {:app app :env env :layout layout :team? team?})
          proposed (get-in config [:environments (keyword env)])
          normalized (cli/normalize-config config)
          environment (get-in normalized [:environments (keyword env)])
          disposable? (= :disposable layout)]
      (and (= app (:app normalized))
           (= (keyword env) (:default-environment normalized))
           (= [(keyword env)] (keys (:environments normalized)))
           (= (:secrets-file proposed) (:secrets-file environment))
           (= disposable? (str/starts-with? (:secrets-file environment) ".local/"))
           (= disposable? (contains? proposed :key-file))
           (= team? (some? (:recipients-file environment)))))))

(def ^:private argument-text
  "A name given as an option value, which no option parser lets start with
  a dash."
  (gen/such-that #(not (str/starts-with? % "-")) name-text))

(def ^:private init-flags
  (gen/vector (gen/elements ["--team" "--keygen" "--apply" "--show-contents"]) 0 4))

(defspec parse-args-reads-back-the-options-it-was-given 100
  (prop/for-all [app argument-text
                 env argument-text
                 layout (gen/elements ["tracked" "disposable"])
                 flags init-flags]
    (let [opts (init/parse-args (into ["--app" app "--env" env "--layout" layout]
                                      (distinct flags)))
          flag-set (set flags)]
      (and (= app (:app opts))
           (= env (:env opts))
           (= (keyword layout) (:layout opts))
           (= (contains? flag-set "--team") (true? (:team? opts)))
           (= (contains? flag-set "--keygen") (true? (:keygen? opts)))
           (= (contains? flag-set "--apply") (true? (:apply? opts)))
           (= (contains? flag-set "--show-contents") (true? (:show-contents? opts)))))))

;;;; Merging bb.edn and deps.edn

(def ^:private library-name
  (gen/fmap (fn [[group artifact]] (symbol group (str "lib" artifact)))
            (gen/tuple (gen/elements ["org.example" "io.github.someone" "acme"])
                       gen/string-alphanumeric)))

(def ^:private coordinate
  (gen/one-of [(gen/fmap (fn [v] {:mvn/version v})
                         (gen/elements ["1.0.0" "2.3.4" "0.1.0-SNAPSHOT"]))
               (gen/fmap (fn [p] {:local/root p}) (gen/elements ["../lib" "libs/x"]))]))

(def ^:private task-name
  (gen/fmap #(symbol (str "task" %)) gen/string-alphanumeric))

(def ^:private task
  (gen/one-of [(gen/fmap (fn [s] (list 'println s)) gen/string-alphanumeric)
               (gen/fmap (fn [s] {:doc s :task (list 'shell "ls")}) gen/string-alphanumeric)]))

(defn- optional
  "Generator of `g`'s value, or nil to leave the key out."
  [g]
  (gen/one-of [(gen/return nil) g]))

(def ^:private bb-edn-map
  "A consumer's bb.edn before the initializer touches it. It never declares
  this library or a `:local/root \".\"` dependency, and never has a `secrets`
  task, so every merge has something to add."
  (gen/let [deps (optional (gen/map library-name coordinate {:max-elements 3}))
            tasks (optional (gen/map task-name task {:max-elements 3}))
            paths (optional (gen/vector (gen/elements ["src" "test"]) 0 2))
            min-bb (optional (gen/elements ["1.3.0" "1.12.0"]))]
    (cond-> {}
      deps (assoc :deps deps)
      tasks (assoc :tasks tasks)
      paths (assoc :paths paths)
      min-bb (assoc :min-bb-version min-bb))))

(def ^:private deps-edn-map
  (gen/let [deps (optional (gen/map library-name coordinate {:max-elements 3}))
            paths (optional (gen/vector (gen/elements ["src" "resources"]) 0 2))
            aliases (optional (gen/return {:test {:extra-paths ["test"]}}))]
    (cond-> {}
      deps (assoc :deps deps)
      paths (assoc :paths paths)
      aliases (assoc :aliases aliases))))

(defn- source-of
  "Generator of `m` as file text: printed on one line or pretty-printed, with
  or without a leading comment, so the merge has to preserve real layout."
  [m]
  (gen/fmap (fn [[comment pretty?]]
              (binding [*print-namespace-maps* false]
                (str comment (if pretty? (with-out-str (pprint/pprint m)) (pr-str m)) "\n")))
            (gen/tuple (gen/elements ["" ";; build tasks\n"]) gen/boolean)))

(def ^:private config (init/proposed-config {:app "reader"}))

(defn- keeps-existing-bb-edn?
  "Merging `source` under `owner` adds exactly the task and one dependency,
  keeps every other entry as it was, and changes nothing the second time."
  [source owner]
  (let [{:keys [content changed? added-task?]} (init/merge-bb-edn source config owner)
        original (edn/read-string source)
        merged (edn/read-string content)
        again (init/merge-bb-edn content config owner)
        [added-name added-coordinate] (if (= :bb.edn owner)
                                        (first default-dependency)
                                        (first (init/self-dependency "reader")))]
    (and changed?
         added-task?
         (= (init/task-spec config) (get-in merged [:tasks 'secrets]))
         (= (:tasks original {}) (dissoc (:tasks merged) 'secrets))
         (= added-coordinate (get-in merged [:deps added-name]))
         (= (:deps original {}) (dissoc (:deps merged) added-name))
         (= (dissoc original :deps :tasks) (dissoc merged :deps :tasks))
         (= content (:content again))
         (not (:changed? again)))))

(defspec merging-bb-edn-keeps-what-was-there 100
  (prop/for-all [source (gen/bind bb-edn-map source-of)
                 owner (gen/elements [:bb.edn :deps.edn])]
    (keeps-existing-bb-edn? source owner)))

(defspec merging-deps-edn-keeps-what-was-there 100
  (prop/for-all [source (gen/bind deps-edn-map source-of)]
    (let [{:keys [content changed? added-dependency?]} (init/merge-deps-edn source)
          original (edn/read-string source)
          merged (edn/read-string content)
          again (init/merge-deps-edn content)]
      (and changed?
           added-dependency?
           (= (merge (:deps original {}) default-dependency) (:deps merged))
           (= (dissoc original :deps) (dissoc merged :deps))
           (= content (:content again))
           (not (:changed? again))))))
