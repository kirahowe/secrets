(ns com.kirahowe.secrets.safe-edn
  "Implementation namespace; not part of the public API and may change without notice.

  Exact-one, depth-bounded, content-free parsing for EDN that may hold secrets.

  `clojure.edn/read-string` alone does not fit: its messages can echo secret
  tokens, it ignores values after the first, and deeply nested input can
  overflow the stack before a catch can sanitize the failure."
  (:require [clojure.edn :as edn]))

(def ^:private max-depth
  "The deepest collection nesting [[parse]] accepts, checked before the
  recursive reader can overflow the stack."
  100)

(defn- skip-string
  "Return the index just past the string literal whose opening quote is at
  `i` - 1, skipping `\\` escapes."
  [^String s i]
  (let [n (.length s)]
    (loop [i i]
      (cond
        (>= i n) n
        (= \\ (.charAt s i)) (recur (+ i 2))
        (= \" (.charAt s i)) (inc i)
        :else (recur (inc i))))))

(defn- skip-comment
  "Return the index of the newline ending the comment at `i`, or the end of `s`."
  [^String s i]
  (let [n (.length s)]
    (loop [i i]
      (if (or (>= i n) (= \newline (.charAt s i)))
        i
        (recur (inc i))))))

(defn- nesting-depth
  "Return the deepest collection nesting in EDN text `s`, scanning once
  without parsing.

  Strings, character literals such as `\\[`, and `;` comments are skipped, so
  delimiters inside them are not depth. Surplus closers clamp at zero:
  balance is `clojure.edn`'s job."
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

(defn parse
  "Parse exactly one EDN value from string `s`. Parser exceptions are never
  retained.

  Returns `{:ok? true :value value}`, or a content-free failure map with
  `:ok? false` and a `:reason` of `:edn-empty`, `:edn-extra-values`,
  `:edn-too-deep` (with numeric `:depth` and `:limit`), or `:edn-malformed`
  (with the 1-based `:line` and `:column` where the reader gave up)."
  [s]
  (let [depth (nesting-depth s)]
    (if (> depth max-depth)
      {:ok? false :reason :edn-too-deep :depth depth :limit max-depth}
      (let [eof (Object.)
            reader (clojure.lang.LineNumberingPushbackReader. (java.io.StringReader. s))]
        (try
          (let [value (edn/read {:eof eof} reader)
                extra (edn/read {:eof eof} reader)]
            (cond
              (identical? eof value) {:ok? false :reason :edn-empty}
              (not (identical? eof extra)) {:ok? false :reason :edn-extra-values}
              :else {:ok? true :value value}))
          (catch Exception _
            {:ok? false
             :reason :edn-malformed
             :line (.getLineNumber reader)
             :column (.getColumnNumber reader)}))))))

(defn failure-data
  "Return the fields of a failed [[parse]] result that may enter exception
  data."
  [failure]
  (select-keys failure [:reason :line :column :depth :limit]))

(defn failure-message
  "Render a failed [[parse]] result as a clause, such as \"malformed EDN syntax
  at line 3, column 7\", with none of the input text."
  [{:keys [reason depth limit line column]}]
  (case reason
    :edn-empty "expected one EDN value, found empty input"
    :edn-extra-values "expected one EDN value, found another"
    :edn-too-deep (str "EDN nesting depth " depth " is past the limit of " limit)
    :edn-malformed (str "malformed EDN syntax at line " line ", column " column)))
