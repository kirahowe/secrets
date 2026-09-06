(ns com.kirahowe.secrets.manifest-property-test
  "Properties of the manifest: the value encoding tells different values apart
  and ignores how equal ones were built, `entries` keeps every leaf, `render`
  reads back, `diff` partitions the key paths, and the HMAC key sees only key
  material."
  (:require [clojure.edn :as edn]
            [clojure.set :as set]
            [clojure.string :as str]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [com.kirahowe.secrets.generators :as g]
            [com.kirahowe.secrets.manifest :as manifest]))

(def ^:private encode @#'manifest/encode)

;;;; Encoding

(defn- rebuilt
  "`v` with every map rebuilt as an array map holding its entries in reverse,
  so iteration order differs from the original wherever a map can hold more
  than one entry."
  [v]
  (cond
    (map? v) (apply array-map (mapcat (fn [[k vv]] [(rebuilt k) (rebuilt vv)])
                                      (reverse (seq v))))
    (vector? v) (mapv rebuilt v)
    (seq? v) (apply list (map rebuilt v))
    (set? v) (into #{} (map rebuilt) v)
    :else v))

(defspec encoding-ignores-map-construction-order 200
  (prop/for-all [v g/value]
    (= (encode v) (encode (rebuilt v)))))

(defn- neighbors
  "Values built from `v` that a weaker encoding could confuse with it: `v`
  wrapped once, retyped to a sibling collection type, or a scalar recast as
  the scalar type that prints the same characters."
  [v]
  (cond-> [[v] (list v) #{v} {v v} (str v) (pr-str v)]
    (vector? v) (conj (apply list v) (set v) (zipmap v v))
    (seq? v) (conj (vec v) (set v))
    (set? v) (conj (vec v) (apply list v))
    (map? v) (conj (vec (mapcat identity v)) (set (keys v)))
    (string? v) (conj (keyword v) (symbol v) (str v " ") (str " " v))
    (keyword? v) (conj (symbol (name v)) (name v))
    (symbol? v) (conj (keyword (name v)) (name v))
    (integer? v) (conj (double v) (- v) (inc v))
    (double? v) (conj (- v) (inc v))))

(defn- same-shape?
  "Equal, and of one `value-type`. `[1]` and `(1)` are equal and must still
  encode differently; `\"a\"` and `(str \"a\")` are the same value."
  [a b]
  (and (= a b) (= (manifest/value-type a) (manifest/value-type b))))

(defspec distinct-values-encode-differently 200
  (prop/for-all [v (gen/one-of [gen/any-printable-equatable g/value])
                 other (gen/one-of [gen/any-printable-equatable g/value])]
    (let [e (encode v)]
      (and (or (= v other) (not= e (encode other)))
           (every? #(not= e (encode %))
                   (remove #(same-shape? v %) (neighbors v)))))))

;;;; Entries

(defn- leaves
  "Every `[path value]` a manifest must record for `v`, by the rule the
  docstring of `entries` states: a non-empty map is walked, anything else is
  a leaf."
  [path v]
  (if (and (map? v) (seq v))
    (mapcat (fn [[k vv]] (leaves (conj path k) vv)) v)
    [[path v]]))

(defn- describes?
  "True when descriptor `d` says of `v` what the manifest promises: its type,
  a count only for a collection, and a 16-hex-digit hash only under a key."
  [v hkey d]
  (and (= (manifest/value-type v) (:type d))
       (= (coll? v) (contains? d :count))
       (or (not (coll? v)) (= (count v) (:count d)))
       (= (some? hkey) (contains? d :vhash))
       (or (nil? hkey) (boolean (re-matches #"[0-9a-f]{16}" (:vhash d))))))

(def ^:private optional-key
  (gen/one-of [(gen/return nil) g/age-secret-key]))

(defspec entries-keep-every-leaf-in-one-order 200
  (prop/for-all [v g/secrets
                 key optional-key]
    (let [hkey (some-> key manifest/hmac-key)
          e (manifest/entries v hkey)
          expected (leaves [] v)]
      (and (= (count expected) (count e))
           (= (set (map first expected)) (set (keys e)))
           (every? (fn [[path leaf]] (describes? leaf hkey (get e path))) expected)
           (= (keys e) (keys (manifest/entries (rebuilt v) hkey)))))))

;;;; Render

(def ^:private sha256-hex
  (gen/fmap str/join (gen/vector (gen/elements (vec "0123456789abcdef")) 64)))

(defspec render-reads-back-as-the-same-entries 100
  (prop/for-all [v g/secrets
                 app g/text
                 sha (gen/one-of [(gen/return nil) sha256-hex])]
    (let [e (manifest/entries v nil)
          parsed (edn/read-string (manifest/render {:app app :ciphertext-sha sha} e))]
      (= (cond-> {:version 2 :app app :keys e}
           sha (assoc :ciphertext-sha sha))
         parsed))))

;;;; Diff

(def ^:private mutation
  "One edit to a secrets map: a new key, a removed key, or a replaced value.
  Indexes pick among the keys present when the edit is applied."
  (gen/one-of [(gen/tuple (gen/return :assoc) g/secret-key g/secrets)
               (gen/tuple (gen/return :dissoc) gen/nat)
               (gen/tuple (gen/return :replace) gen/nat g/secrets)]))

(defn- key-at
  "The key of `m` that index `i` picks, wrapping around, or nil when empty."
  [m i]
  (when (seq m)
    (nth (vec (keys m)) (mod i (count m)))))

(defn- mutate [m [op a b]]
  (case op
    :assoc (assoc m a b)
    :dissoc (if (seq m) (dissoc m (key-at m a)) m)
    :replace (if (seq m) (assoc m (key-at m a) b) m)))

(defn- sorted-by-rendering? [paths]
  (= paths (sort-by pr-str paths)))

(defspec diff-partitions-the-key-paths 200
  (prop/for-all [a g/secrets-map
                 mutations (gen/vector mutation 0 4)]
    (let [b (reduce mutate a mutations)
          before (manifest/entries a nil)
          after (manifest/entries b nil)
          {:keys [added removed changed]} (manifest/diff before after)
          backwards (manifest/diff after before)
          bks (set (keys before))
          aks (set (keys after))
          unchanged (filter #(and (aks %) (= (before %) (after %))) (keys before))]
      (and (= {:added [] :removed [] :changed []} (manifest/diff before before))
           (= added (:removed backwards))
           (= removed (:added backwards))
           (= changed (:changed backwards))
           (= (set added) (set/difference aks bks))
           (= (set removed) (set/difference bks aks))
           (= (set changed) (set (filter #(and (bks %) (not= (before %) (after %))) aks)))
           (= (count after) (+ (count added) (count changed) (count unchanged)))
           (every? sorted-by-rendering? [added removed changed])))))

;;;; HMAC key

(def ^:private two-identities
  "Two renderings of one key, and a rendering of another key."
  (gen/let [key g/age-secret-key
            other (gen/such-that #(not= key %) g/age-secret-key)
            a (g/decorated-identity key)
            b (g/decorated-identity key)
            c (g/decorated-identity other)]
    {:a a :b b :c c}))

(defspec hmac-key-sees-only-the-secret-key-line 100
  (prop/for-all [{:keys [a b c]} two-identities]
    (and (= (vec (manifest/hmac-key a)) (vec (manifest/hmac-key b)))
         (not= (vec (manifest/hmac-key a)) (vec (manifest/hmac-key c))))))
