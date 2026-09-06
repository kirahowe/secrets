(ns com.kirahowe.secrets.safe-edn-property-test
  "Properties of the untrusted-EDN boundary: every value the printer produces
  reads back, the depth scanner counts structure and nothing else, and a
  failure never carries content."
  (:require [clojure.string :as str]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [com.kirahowe.secrets.generators :as g]
            [com.kirahowe.secrets.safe-edn :as safe-edn]))

;;;; Round trip

(defspec parse-reads-back-every-printable-value 200
  (prop/for-all [v (gen/one-of [gen/any-printable-equatable g/value])]
    (= {:ok? true :value v} (safe-edn/parse (pr-str v)))))

;;;; Depth

(def ^:private leaf
  "Generator of `[text value]`: printed text full of delimiters, and the value
  it reads back to. Strings, character literals, and the escape character are
  the places a scanner could mistake text for structure."
  (gen/one-of [(gen/fmap (fn [s] [(pr-str s) s]) g/delimiter-text)
               (gen/elements [["\\[" \[] ["\\{" \{] ["\\(" \(] ["\\;" \;]
                              ["\\\"" \"] ["\\\\" \\] ["42" 42] ["nil" nil]])]))

(def ^:private comment-text
  "A comment the reader skips and the scanner must skip too, or nothing."
  (gen/elements ["" "; [[[ {{{ (((\n" ";; \"unterminated [\n" "\n; }}}\n"]))

(defn- wrap
  "One collection layer around `text`, with `comment` just inside the opener."
  [[text value] [kind comment]]
  (case kind
    :vector [(str "[" comment text "]") [value]]
    :list [(str "(" comment text ")") (list value)]
    :set [(str "#{" comment text "}") #{value}]
    :map [(str "{" comment ":k " text "}") {:k value}]))

(def ^:private nested
  "Generator of `[text value depth]`: a leaf under `depth` collection layers,
  with comments scattered through the text."
  (gen/let [leaf leaf
            layers (gen/vector (gen/tuple (gen/elements [:vector :list :set :map])
                                          comment-text)
                               0 8)
            prefix comment-text]
    (let [[text value] (reduce wrap leaf layers)]
      [(str prefix text) value (count layers)])))

(defspec depth-counts-collections-and-nothing-else 200
  (prop/for-all [[text value depth] nested
                 limit (gen/choose 0 10)]
    (= (if (<= depth limit)
         {:ok? true :value value}
         {:ok? false :reason :edn-too-deep :depth depth :limit limit})
       (safe-edn/parse text {:max-edn-depth limit}))))

;;;; Exactly one value

(defspec a-second-value-is-rejected 100
  (prop/for-all [a gen/any-printable-equatable
                 b gen/any-printable-equatable
                 gap (gen/elements [" " "\n" " ; comment\n" ", "])]
    (= {:ok? false :reason :edn-extra-values}
       (safe-edn/parse (str (pr-str a) gap (pr-str b))))))

(defspec whitespace-and-comments-alone-are-empty 100
  (prop/for-all [pieces (gen/vector (gen/elements [" " "\n" "\t" "," "; text [\n" ";\n" "; {"]))]
    (= {:ok? false :reason :edn-empty} (safe-edn/parse (str/join pieces)))))

;;;; Content-free failures

(def ^:private corrupted
  "Printed EDN with one character inserted, removed, or replaced, which is
  malformed far more often than random text is, and malformed near a value
  that could be a secret."
  (gen/let [v gen/any-printable-equatable
            i gen/nat
            c (gen/one-of [gen/char
                           (gen/elements [\[ \] \{ \} \( \) \" \\ \# \; \newline])])
            op (gen/elements [:insert :delete :replace])]
    (let [s (pr-str v)
          i (mod i (max 1 (count s)))
          rest-from (fn [j] (subs s (min (count s) j)))]
      (case op
        :insert (str (subs s 0 i) c (rest-from i))
        :delete (str (subs s 0 i) (rest-from (inc i)))
        :replace (str (subs s 0 i) c (rest-from (inc i)))))))

(def ^:private unbalanced
  "Openers with nothing closing them, deeper than the default limit allows."
  (gen/fmap #(apply str (repeat % "[")) (gen/choose 0 300)))

(def ^:private allowed-keys #{:ok? :reason :depth :limit :line :column})

(def ^:private reasons #{:edn-empty :edn-extra-values :edn-too-deep :edn-malformed})

(defn- content-free?
  "True when `result` is a success, or a failure made only of the allowlisted
  keys with a known reason and numbers for everything else."
  [result]
  (or (true? (:ok? result))
      (and (false? (:ok? result))
           (every? allowed-keys (keys result))
           (contains? reasons (:reason result))
           (every? number? (vals (dissoc result :ok? :reason))))))

(defspec failures-carry-no-content 300
  (prop/for-all [s (gen/one-of [corrupted unbalanced g/text gen/string-ascii])]
    (content-free? (safe-edn/parse s))))
