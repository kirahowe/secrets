(ns com.kirahowe.secrets.safe-edn
  "Exact-one, depth-safe, content-free parsing for untrusted EDN.

  `clojure.edn/read-string` alone is insufficient at this security boundary:
  parser messages can echo secret tokens, it accepts only the first value while
  ignoring trailing values, and deeply nested input can overflow the stack
  before a catch can sanitize the failure. This namespace scans depth first,
  reads exactly one value, and returns only allowlisted failure metadata."
  (:require [clojure.edn :as edn]))

(def default-max-depth
  "The default maximum collection nesting accepted by [[parse]]."
  100)

(defn- skip-string
  "Return the index just past the EDN string literal whose opening quote sits at
  `i` - 1, so a `\\` escape cannot hide the closing quote."
  [^String s i]
  (let [n (.length s)]
    (loop [i i]
      (cond
        (>= i n) n
        (= \\ (.charAt s i)) (recur (+ i 2))
        (= \" (.charAt s i)) (inc i)
        :else (recur (inc i))))))

(defn- skip-comment
  "Return the index of the newline ending the `;` comment that starts at `i`, or
  the end of `s`."
  [^String s i]
  (let [n (.length s)]
    (loop [i i]
      (if (or (>= i n) (= \newline (.charAt s i)))
        i
        (recur (inc i))))))

(defn- max-depth
  "Return the deepest collection nesting the EDN text `s` reaches, scanning it
  once without parsing it.

  Only delimiters that are structure count: string literals (including their
  `\\` escapes), character literals such as `\\[`, and `;` comments are skipped,
  so a delimiter inside any of them is text rather than depth. `#{` needs no
  special case — its `{` is the opener. Surplus closing delimiters clamp at
  zero: balance is `clojure.edn`'s job, not this scanner's."
  [^String s]
  (let [n (.length s)]
    (loop [i 0 depth 0 deepest 0]
      (if (>= i n)
        deepest
        (case (.charAt s i)
          \" (recur (skip-string s (inc i)) depth deepest)
          \\ (recur (+ i 2) depth deepest)
          \; (recur (skip-comment s (inc i)) depth deepest)
          (\( \[ \{) (recur (inc i) (inc depth) (max deepest (inc depth)))
          (\) \] \}) (recur (inc i) (max 0 (dec depth)) deepest)
          (recur (inc i) depth deepest))))))

(defn- numeric-parser-location
  [data keys]
  (some (fn [k]
          (let [v (get data k)]
            (when (number? v) v)))
        keys))

(defn- parser-location
  "Extract only numeric line and column metadata from `e` and its causes."
  [e]
  (loop [cause e location {}]
    (if (or (nil? cause)
            (and (contains? location :line) (contains? location :column)))
      location
      (let [data (ex-data cause)
            line (numeric-parser-location data [:line :clojure.error/line])
            column (numeric-parser-location data [:column :clojure.error/column])]
        (recur (ex-cause cause)
               (cond-> location
                 (and line (not (contains? location :line))) (assoc :line line)
                 (and column (not (contains? location :column))) (assoc :column column)))))))

(defn parse
  "Parse exactly one untrusted EDN value from string `s` under `limits`.

  Ordinary `clojure.edn/read-string` is insufficient here: its parser messages
  can echo secret tokens, it accepts only the first value and ignores trailing
  values, and deeply nested input can overflow before a catch can sanitize the
  error. This function scans collection depth before parsing, reads once for the
  value and once for EOF, and never retains parser exceptions, messages,
  nonnumeric data, or causes.

  Returns `{:ok? true :value value}` on success. Failures are content-free maps
  with one stable `:reason`: `:edn-empty`, `:edn-extra-values`,
  `:edn-too-deep`, or `:edn-malformed`. Depth failures also carry numeric
  `:depth` and `:limit`; malformed failures carry only numeric `:line` and
  `:column` when the parser provides them.

  The one-argument arity uses [[default-max-depth]]. The two-argument arity
  reads only `:max-edn-depth`, so callers may pass a larger resolved limits map."
  ([s]
   (parse s {:max-edn-depth default-max-depth}))
  ([s limits]
   (let [limit (get limits :max-edn-depth default-max-depth)
         depth (max-depth s)]
     (if (> depth limit)
       {:ok? false :reason :edn-too-deep :depth depth :limit limit}
       (try
         (let [eof (Object.)
               reader (clojure.lang.LineNumberingPushbackReader.
                       (java.io.StringReader. s))
               value (edn/read {:eof eof} reader)
               extra (edn/read {:eof eof} reader)]
           (cond
             (identical? eof value) {:ok? false :reason :edn-empty}
             (not (identical? eof extra)) {:ok? false :reason :edn-extra-values}
             :else {:ok? true :value value}))
         (catch Exception e
           (merge {:ok? false :reason :edn-malformed}
                  (parser-location e))))))))
