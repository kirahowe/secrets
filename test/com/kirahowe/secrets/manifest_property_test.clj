(ns com.kirahowe.secrets.manifest-property-test
  "Properties of the manifest: the value encoding tells different values apart
  and ignores how equal ones were built, `entries` keeps every leaf, `render`
  reads back, `diff` partitions the key paths, and a value's hash depends on
  the store's manifest key and on nothing about how the value was built."
  (:require [clojure.edn :as edn]
            [clojure.set :as set]
            [clojure.string :as str]
            [clojure.test :refer [deftest is]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [com.kirahowe.secrets.generators :as g]
            [com.kirahowe.secrets.manifest :as manifest]))

(def ^:private encode @#'manifest/encode)

(def ^:private hex-chars (vec "0123456789abcdef"))

(def ^:private sha256-hex
  (gen/fmap str/join (gen/vector (gen/elements hex-chars) 64)))

(def ^:private manifest-key
  "A manifest key: 64 lowercase hex characters, each drawn independently."
  sha256-hex)

(deftest generated-manifest-keys-have-the-shape-the-properties-assume
  (is (every? manifest/valid-key? (gen/sample manifest-key 20)))
  (is (every? #(re-matches #"[0-9a-f]{64}" %) (repeatedly 20 manifest/generate-key))))

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
  a count only for a collection, and a 16-hex-digit hash."
  [v d]
  (and (= (manifest/value-type v) (:type d))
       (= (coll? v) (contains? d :count))
       (or (not (coll? v)) (= (count v) (:count d)))
       (boolean (re-matches #"[0-9a-f]{16}" (str (:vhash d))))))

(defspec entries-keep-every-leaf-in-one-order 200
  (prop/for-all [v g/secrets
                 k manifest-key]
    (let [e (manifest/entries v k)
          expected (leaves [] v)]
      (and (= (count expected) (count e))
           (= (set (map first expected)) (set (keys e)))
           (every? (fn [[path leaf]] (describes? leaf (get e path))) expected)
           (= (keys e) (keys (manifest/entries (rebuilt v) k)))))))

(defspec reserved-keys-get-no-entry 100
  (prop/for-all [m g/secrets-map
                 k manifest-key
                 recorded (gen/one-of [(gen/return nil) g/text sha256-hex])]
    (= (manifest/entries m k)
       (manifest/entries (assoc m manifest/store-key k manifest/store-recipients recorded) k))))

;;;; Render

(defspec render-reads-back-as-a-complete-manifest 100
  (prop/for-all [v g/secrets
                 k manifest-key
                 app g/text
                 sha sha256-hex]
    (let [e (manifest/entries v k)
          parsed (edn/read-string (manifest/render {:app app :ciphertext-sha sha} e))]
      (and (= {:version 3 :app app :ciphertext-sha sha :keys e} parsed)
           (nil? (manifest/problem app parsed))))))

(def ^:private damage
  "One way a complete manifest can stop being complete."
  (gen/elements [#(dissoc % :keys)
                 #(assoc % :keys (vec (:keys %)))
                 #(assoc % :keys nil)
                 #(dissoc % :ciphertext-sha)
                 #(assoc % :ciphertext-sha (subs (:ciphertext-sha %) 1))
                 #(update % :keys update-vals (fn [d] (dissoc d :vhash)))
                 #(update % :keys update-vals (fn [d] (dissoc d :type)))
                 #(update % :keys update-vals (fn [d] (update d :vhash str "0")))
                 #(update % :keys update-vals :type)
                 #(update % :version dec)
                 #(update % :version inc)
                 #(dissoc % :version)
                 #(update % :app str "x")
                 vector]))

(defspec a-damaged-manifest-is-never-complete 200
  (prop/for-all [m (gen/such-that seq g/secrets-map)
                 k manifest-key
                 sha sha256-hex
                 damaged damage]
    (let [complete {:version manifest/supported-version
                    :app "app"
                    :ciphertext-sha sha
                    :keys (into {} (manifest/entries m k))}]
      (and (nil? (manifest/problem "app" complete))
           (some? (:reason (manifest/problem "app" (damaged complete))))))))

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
                 mutations (gen/vector mutation 0 4)
                 k manifest-key]
    (let [b (reduce mutate a mutations)
          before (manifest/entries a k)
          after (manifest/entries b k)
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

;;;; Value hashes

(defn- vhashes
  "The `:vhash` of every leaf of `v` under `k`, by path."
  [v k]
  (update-vals (manifest/entries v k) :vhash))

(defspec one-key-hashes-equal-values-equally-however-they-were-built 200
  (prop/for-all [v g/secrets
                 k manifest-key]
    (= (vhashes v k) (vhashes (rebuilt v) k))))

(defspec one-key-hashes-a-value-the-same-at-every-path 100
  (prop/for-all [v g/value
                 k manifest-key
                 a g/secret-key
                 b g/secret-key]
    ;; Wrapped in a vector so the value is one leaf whatever it is.
    (= (get (vhashes {a [v]} k) [a])
       (get (vhashes {b [v]} k) [b]))))

(defspec independent-keys-give-unrelated-hashes 200
  (prop/for-all [m (gen/such-that seq g/secrets-map)
                 k manifest-key
                 other manifest-key]
    (let [mine (vhashes m k)
          theirs (vhashes m other)]
      (or (= k other)
          ;; Same paths, and no leaf's hash under one key appears anywhere
          ;; under the other, so holding one key identifies nothing hashed
          ;; under the other.
          (and (= (keys mine) (keys theirs))
               (empty? (set/intersection (set (vals mine)) (set (vals theirs)))))))))

(defspec a-changed-value-changes-its-hash-and-no-other 200
  (prop/for-all [m (gen/such-that seq g/secrets-map)
                 k manifest-key
                 i gen/nat
                 replacement g/scalar]
    (let [path (nth (keys (manifest/entries m k)) (mod i (count (manifest/entries m k))))
          before (vhashes m k)
          after (vhashes (assoc-in m path [::replaced replacement]) k)]
      (and (not= (before path) (after path))
           (= (dissoc before path) (dissoc after path))))))
