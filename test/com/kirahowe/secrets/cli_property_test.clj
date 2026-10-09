(ns com.kirahowe.secrets.cli-property-test
  "Properties of the management CLI's pure edges: the quoting every suggested
  command goes through, the argv adapter, the key-path parser, the recipients
  reader, the plaintext renderer, and the store metadata written into the
  plaintext."
  (:require [clojure.java.io :as io]
            [clojure.java.shell :as shell]
            [clojure.string :as str]
            [clojure.test :refer [use-fixtures]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [com.kirahowe.secrets.cli :as cli]
            [com.kirahowe.secrets.generators :as g]
            [com.kirahowe.secrets.manifest :as manifest]
            [com.kirahowe.secrets.safe-edn :as safe-edn]))

(def ^:private shell-quote @#'cli/shell-quote)
(def ^:private strip-trailing-newline @#'cli/strip-trailing-newline)
(def ^:private parse-key-path @#'cli/parse-key-path)
(def ^:private recipient-entries @#'cli/recipient-entries)
(def ^:private render-secrets @#'cli/render-secrets)
(def ^:private with-metadata @#'cli/with-metadata)
(def ^:private metadata-line @#'cli/metadata-line)
(def ^:private user-plaintext @#'cli/user-plaintext)
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

;;;; Store metadata in the plaintext

(def ^:private manifest-key
  (gen/fmap str/join (gen/vector (gen/elements (vec "0123456789abcdef")) 64)))

(def ^:private comment-text
  "A `;` comment line holding the characters a scanner could mistake for
  structure."
  (gen/fmap #(str ";" (str/replace % #"[\r\n]" " ") "\n") g/delimiter-text))

(def ^:private preamble
  "What a store's plaintext may hold before its map: blanks, commas, and
  comments."
  (gen/fmap str/join (gen/vector (gen/one-of [(gen/elements [" " "\n" "\t" "," "\r\n"])
                                              comment-text])
                                 0 5)))

(defspec store-metadata-goes-in-and-comes-out-without-touching-the-users-text 200
  (prop/for-all [m g/secrets-map
                 before preamble
                 after preamble
                 k manifest-key
                 recorded (gen/one-of [(gen/return "identity") manifest-key])]
    (let [text (str before (render-secrets m) after)
          keyed (with-metadata text (metadata-line k recorded))]
      (and (= {:ok? true
               :value (assoc m manifest/store-key
                             {:version 1 :manifest-key k :recipients recorded})}
              (safe-edn/parse keyed))
           (nil? (manifest/store-problem (:value (safe-edn/parse keyed))))
           (= text (user-plaintext keyed))
           (= text (user-plaintext text))))))

(defspec the-reserved-key-written-anywhere-else-is-left-in-the-text 100
  ;; Only the library's own first line is taken out. The key anywhere else
  ;; stays, so the write that follows refuses it instead of losing text.
  (prop/for-all [m (gen/such-that seq g/secrets-map)
                 k (gen/one-of [manifest-key (gen/return nil) g/encodable-text])]
    (let [text (str (subs (render-secrets m) 0 (dec (count (str/trimr (render-secrets m)))))
                    " " (pr-str manifest/store-key) " " (pr-str k) "}")]
      (= text (user-plaintext text)))))

(defspec text-that-does-not-open-with-a-map-gets-no-metadata 100
  (prop/for-all [v (gen/one-of [g/scalar (gen/vector g/scalar) (gen/set g/scalar)])
                 k manifest-key]
    (nil? (with-metadata (pr-str v) (metadata-line k "identity")))))

(defspec a-path-at-or-under-a-reserved-key-is-refused 100
  (prop/for-all [reserved (gen/return manifest/store-key)
                 more (gen/vector (gen/one-of [gen/keyword gen/string-alphanumeric]) 0 3)]
    (and (refused? (pr-str (into [reserved] more)))
         (or (seq more) (refused? (pr-str reserved))))))
