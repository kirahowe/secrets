(ns com.kirahowe.secrets.cli-property-test
  "Properties of the management CLI's pure edges: the quoting every suggested
  command goes through, the argv adapter, the key-path parser, the recipients
  reader, and the plaintext renderer."
  (:require [clojure.java.io :as io]
            [clojure.java.shell :as shell]
            [clojure.string :as str]
            [clojure.test :refer [use-fixtures]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [com.kirahowe.secrets.cli :as cli]
            [com.kirahowe.secrets.generators :as g]
            [com.kirahowe.secrets.safe-edn :as safe-edn]))

(def ^:private shell-quote @#'cli/shell-quote)
(def ^:private strip-trailing-newline @#'cli/strip-trailing-newline)
(def ^:private parse-key-path @#'cli/parse-key-path)
(def ^:private normalize-argv @#'cli/normalize-argv)
(def ^:private operand @#'cli/operand)
(def ^:private operand-token? @#'cli/operand-token?)
(def ^:private recipient-entries @#'cli/recipient-entries)
(def ^:private render-secrets @#'cli/render-secrets)
;;;; Fixtures

(def ^:private ^:dynamic *dir* nil)

(defn- with-temp-dir [f]
  (let [dir (str (java.nio.file.Files/createTempDirectory
                  "kira-secrets-cli-property-test"
                  (into-array java.nio.file.attribute.FileAttribute [])))]
    (binding [*dir* dir]
      (try
        (f)
        (finally
          (doseq [p (reverse (file-seq (io/file dir)))] (.delete p)))))))

(use-fixtures :each with-temp-dir)

;;;; Shell quoting

(defn- sh-words
  "Split `s` into words the way a POSIX shell reads a command line made of
  single quotes, backslashes, and blanks: inside `'...'` every character is
  literal, outside a backslash takes the next character literally, and blanks
  separate words. A reference model for `shell-quote`, checked against a real
  shell in `shell-quote-survives-a-real-shell`."
  [s]
  (loop [[c & more :as chars] (seq s)
         quoted? false
         word nil
         words []]
    (cond
      (nil? chars) (cond-> words word (conj word))
      quoted? (if (= \' c)
                (recur more false word words)
                (recur more true (str word c) words))
      (= \' c) (recur more true (or word "") words)
      (= \\ c) (recur (rest more) false (str word (first more)) words)
      (#{\space \tab \newline} c) (recur more false nil (cond-> words word (conj word)))
      :else (recur more false (str word c) words))))

(defspec shell-quote-makes-one-word-per-value 200
  (prop/for-all [values (gen/vector g/text 0 5)]
    (= values (sh-words (str/join " " (map shell-quote values))))))

(def ^:private shell-text
  "Text a shell receives on this platform without an encoding step in the
  way: any byte but NUL, plus a few multi-byte samples."
  (gen/fmap str/join
            (gen/vector (gen/one-of [(gen/fmap str (gen/fmap char (gen/choose 1 127)))
                                     (gen/elements ["é" "δοκιμή" "🔐" "→" "'" "'\\''"])])
                        0 12)))

(defn- posix-sh? []
  (.canExecute (io/file "/bin/sh")))

(def ^:private nul-separator
  (re-pattern (str (char 0))))

(defn- sh-argv
  "Hand `quoted` to /bin/sh as the arguments of `set --` and return the
  arguments it produced, written NUL-separated so a newline inside one is
  kept. The output path travels through the environment, so the script
  interpolates nothing but the words under test."
  [quoted]
  (let [out (io/file *dir* "argv")]
    (.delete out)
    (let [{:keys [exit err]} (shell/sh "/bin/sh" "-c"
                                       (str "set -- " quoted "\n"
                                            "printf '%s\\0' \"$@\" > \"$OUT_FILE\"\n")
                                       :env {"PATH" "/usr/bin:/bin"
                                             "OUT_FILE" (.getPath out)})]
      (when-not (zero? exit)
        (throw (ex-info "sh rejected the command line" {:exit exit :err err})))
      (vec (butlast (str/split (slurp out :encoding "UTF-8") nul-separator -1))))))

(defspec shell-quote-survives-a-real-shell 30
  (prop/for-all [values (gen/vector shell-text 1 4)]
    (or (not (posix-sh?))
        (= values (sh-argv (str/join " " (map shell-quote values)))))))

;;;; Trailing newline

(defspec strip-trailing-newline-removes-exactly-one 200
  (prop/for-all [s g/text]
    (let [stripped (strip-trailing-newline s)]
      (and (= s (strip-trailing-newline (str s "\r\n")))
           (or (str/ends-with? s "\r") (= s (strip-trailing-newline (str s "\n"))))
           (= (str s "\n") (strip-trailing-newline (str s "\n\n")))
           (or (str/ends-with? s "\n") (= s stripped))
           (str/starts-with? s stripped)
           (<= (- (count s) 2) (count stripped))))))

;;;; Key paths

(def ^:private key-path
  (gen/vector (gen/one-of [gen/keyword gen/keyword-ns gen/string-alphanumeric g/text]) 1 4))

(defspec key-paths-parse-from-their-printed-form 200
  (prop/for-all [path key-path]
    (= path (parse-key-path (pr-str path)))))

(defspec a-bare-keyword-is-a-one-element-path 100
  (prop/for-all [k (gen/one-of [gen/keyword gen/keyword-ns])]
    (= [k] (parse-key-path (pr-str k)))))

(def ^:private not-a-path-element
  (gen/one-of [gen/small-integer (gen/return nil) gen/boolean (gen/vector gen/keyword)]))

(def ^:private not-a-key-path
  "A value `parse-key-path` must refuse: the wrong type, an empty vector, or
  a vector with one element that is neither keyword nor string."
  (gen/one-of [gen/large-integer
               gen/string-alphanumeric
               gen/boolean
               (gen/return nil)
               (gen/return [])
               (gen/map gen/keyword gen/small-integer)
               (gen/set gen/keyword)
               (gen/list gen/keyword)
               (gen/let [path key-path
                         bad not-a-path-element
                         i gen/nat]
                 (let [i (mod i (inc (count path)))]
                   (into (subvec path 0 i) (cons bad (subvec path i)))))]))

(defn- refused?
  "True when `s` is rejected as a user-facing failure rather than parsed."
  [s]
  (try
    (parse-key-path s)
    false
    (catch clojure.lang.ExceptionInfo e
      (some? (ex-message e)))))

(defspec anything-else-is-refused-as-a-key 200
  (prop/for-all [v not-a-key-path
                 blank (gen/elements ["" " " "\n" "\t "])]
    (and (refused? (pr-str v))
         (refused? blank))))

;;;; argv

(def ^:private command
  "A command word: a real one in any case, or a made-up one that is not all
  digits, since a digit string is what an operand index looks like."
  (gen/one-of [(gen/elements ["set" "SET" "Set" "rm" "edit" "verify" "doctor" "help"])
               (gen/such-that #(not (re-matches #"\d+" %))
                              (gen/not-empty gen/string-alphanumeric))]))

(def ^:private token
  "An argv element, weighted toward the ones that mean something to an
  option parser: the terminator, the help and `--edn` flags, dash-leading
  values, and decimal strings that look like operand indexes."
  (gen/frequency [[3 (gen/elements ["--" "-h" "--help" "--edn" "-" "--verbose" "-x" "0" "1" ":k"])]
                  [1 g/text]]))

(defspec normalize-argv-hides-every-operand-from-the-option-parser 200
  (prop/for-all [cmd command
                 args (gen/vector token 0 8)]
    (let [{:keys [argv operands]} (normalize-argv (into [cmd] args))
          [before after] (split-with #(not= "--" %) args)
          known (cond-> #{"-h" "--help"} (= "set" (str/lower-case cmd)) (conj "--edn"))
          indexes (filter operand-token? (rest argv))
          options (remove operand-token? (rest argv))]
      (and (= (str/lower-case cmd) (first argv))
           (= (into (vec (remove known before)) (next after)) operands)
           (every? known options)
           (= (count (filter known before)) (count options))
           (= operands (mapv #(operand operands %) indexes))))))

;;;; Recipients files

(def ^:private blanks
  (gen/elements ["" " " "\t"]))

(def ^:private comment-line
  (gen/fmap (fn [[lead body]] (str lead "#" (str/replace body #"[\r\n]" "")))
            (gen/tuple blanks gen/string-ascii)))

(def ^:private entry-line
  (gen/fmap str/join
            (gen/tuple blanks
                       (gen/one-of [g/age-recipient (gen/not-empty gen/string-alphanumeric)])
                       blanks)))

(def ^:private recipients-line
  "One line of a recipients file, tagged with what the reader must make of
  it: nothing for a blank or a comment, a numbered trimmed entry otherwise."
  (gen/one-of [(gen/tuple (gen/return :blank) (gen/elements ["" " " "\t" " \t "]))
               (gen/tuple (gen/return :comment) comment-line)
               (gen/tuple (gen/return :entry) entry-line)]))

(defspec recipient-entries-are-numbered-as-written 200
  (prop/for-all [lines (gen/vector recipients-line 0 10)
                 newline (gen/elements ["\n" "\r\n"])]
    (= (keep-indexed (fn [i [kind line]]
                       (when (= :entry kind) [(inc i) (str/trim line)]))
                     lines)
       (recipient-entries (str/join newline (map second lines))))))

;;;; Rendering plaintext

(def ^:private print-bound
  (gen/one-of [(gen/return nil) (gen/choose 0 3)]))

(defspec rendered-plaintext-reads-back-under-any-print-settings 100
  (prop/for-all [m g/secrets-map
                 length print-bound
                 level print-bound]
    (= {:ok? true :value m}
       (safe-edn/parse (binding [*print-length* length *print-level* level]
                         (render-secrets m))))))
