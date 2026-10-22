(ns com.kirahowe.secrets.manifest
  "Implementation namespace; not part of the public API and may change without notice.

  Pure functions for the plaintext manifest committed next to each encrypted
  secrets file (`secrets.edn.age` → `secrets.edn.manifest`), and for the store
  metadata that produces it.

  The manifest lists every key path with its value type and a keyed hash of
  its value (`:vhash`), never the value. A `git diff` of it shows which keys
  were added, removed, retyped, or changed.

  A `:vhash` is an HMAC keyed by the store's manifest key, 256 random bits
  kept in the encrypted EDN under `store-key`. Everyone who can decrypt
  computes the same hashes; someone with only the repository cannot test
  guesses against them.

  A manifest is a review aid, not an authorization check (see
  `doc/threat-model.md`). Only core Clojure and the JDK crypto classes are
  used, so it runs the same under JVM Clojure and babashka."
  (:require [clojure.string :as str]))

;;;; Store metadata

(def store-key
  "The reserved top-level key of a store. Its value is the library's metadata,
  `{:version 1 :manifest-key \"<64 hex>\" :recipients \"<record>\"}`, never
  user data."
  :com.kirahowe.secrets/store)

(def store-version
  "The store metadata `:version` this library writes and reads."
  1)

(defn user-data
  "Return decrypted store `value` without `store-key`. A non-map is returned
  unchanged."
  [value]
  (if (map? value)
    (dissoc value store-key)
    value))

(defn- hex ^String [bs]
  (apply str (map #(format "%02x" (bit-and % 0xff)) bs)))

(defn generate-key
  "Return a new manifest key: 32 `SecureRandom` bytes as 64 lowercase hex."
  []
  (let [bs (byte-array 32)]
    (.nextBytes (java.security.SecureRandom.) bs)
    (hex bs)))

(defn- valid-key?
  "True when `x` is a string of 64 lowercase hex characters."
  [x]
  (boolean (and (string? x) (re-matches #"[0-9a-f]{64}" x))))

(defn store-problem
  "Return nil when `value` is a map with well-formed `store-key` metadata of
  the `store-version`, otherwise why not: `:not-a-map`, `:missing`,
  `:unsupported-version` (an integer `:version` other than this one), or
  `:malformed`."
  [value]
  (let [found (when (map? value) (get value store-key))]
    (cond
      (not (map? value)) :not-a-map
      (nil? found) :missing
      (not (map? found)) :malformed

      (and (integer? (:version found)) (not= store-version (:version found)))
      :unsupported-version

      (not (and (= #{:version :manifest-key :recipients} (set (keys found)))
                (= store-version (:version found))
                (valid-key? (:manifest-key found))
                (string? (:recipients found))))
      :malformed)))

(defn recipients-id
  "Return the string a store records for its recipient set: the SHA-256 hex of
  the distinct `recipients`, sorted and newline-joined. Single-key mode passes
  nil and gets the fixed word `identity`, since the decrypting identity is
  the one encrypted to."
  [recipients]
  (if (nil? recipients)
    "identity"
    (hex (.digest (java.security.MessageDigest/getInstance "SHA-256")
                  (.getBytes ^String (str/join "\n" (sort (distinct recipients)))
                             "UTF-8")))))

;;;; Hashing

(defn- key-bytes
  "Decode manifest key `k` to its 32 bytes. A malformed key throws
  `:invalid-manifest-key`, so a missing key can never yield unhashed entries."
  ^bytes [k]
  (when-not (valid-key? k)
    (throw (ex-info "Not a well-formed manifest key." {:reason :invalid-manifest-key})))
  (byte-array (map #(unchecked-byte (Integer/parseInt (apply str %) 16))
                   (partition 2 k))))

(defn- hmac-sha256 ^bytes [^bytes k ^bytes msg]
  (let [mac (javax.crypto.Mac/getInstance "HmacSHA256")]
    (.init mac (javax.crypto.spec.SecretKeySpec. k "HmacSHA256"))
    (.doFinal mac msg)))

;;;; Shape

(defn value-type
  "Return a keyword naming the EDN type of `v`, so a type change shows in the
  manifest diff."
  [v]
  (cond
    (nil? v) :nil
    (boolean? v) :boolean
    (string? v) :string
    (keyword? v) :keyword
    (symbol? v) :symbol
    (integer? v) :integer
    (float? v) :float
    (inst? v) :inst
    (map? v) :map
    (set? v) :set
    (vector? v) :vector
    (sequential? v) :list
    :else :other))

(def ^:private tags
  "The frame tag of each `value-type`, so a vector, list, and set of equal
  elements encode differently."
  {:nil "n" :boolean "b" :string "s" :keyword "k" :symbol "y" :integer "i"
   :float "f" :inst "t" :map "m" :set "S" :vector "V" :list "L" :other "o"})

(defn- frame
  "Return `payload` framed as `<tag>:<code-unit-count>:<payload>`."
  ^String [tag ^String payload]
  (str tag \: (count payload) \: payload))

(defn- encode
  "Return the canonical encoding of `v`: one `frame` per value, nested for
  collections. Map entries and set elements are sorted; vector and list
  elements keep their order. Tags and lengths make the encoding unambiguous,
  so two values the EDN reader can produce share one only when equal."
  ^String [v]
  (let [t (value-type v)
        tag (tags t)]
    (case t
      :map (frame tag (apply str (sort (map (fn [[k vv]] (str (encode k) (encode vv))) v))))
      :set (frame tag (apply str (sort (map encode v))))
      (:vector :list) (frame tag (apply str (map encode v)))
      (frame tag (pr-str v)))))

(defn- utf16-bytes
  "Return the UTF-16 code units of `s` as big-endian byte pairs. A charset
  encoder would replace an unpaired surrogate (which `clojure.edn` can read),
  making two different strings hash alike."
  ^bytes [^String s]
  (let [n (count s)
        out (byte-array (* 2 n))]
    (dotimes [i n]
      (let [c (int (.charAt s i))
            j (* 2 i)]
        (aset-byte out j (unchecked-byte (bit-shift-right c 8)))
        (aset-byte out (inc j) (unchecked-byte (bit-and c 0xff)))))
    out))

(defn- vhash
  "Return the first 8 bytes of the keyed HMAC of `v` as 16 hex characters.
  At 64 bits it can collide, so an unchanged hash is strong evidence of an
  unchanged value, not proof. The path is not an input, so equal values at
  different paths hash equally."
  [^bytes hkey v]
  (hex (take 8 (hmac-sha256 hkey (utf16-bytes (encode v))))))

(defn- descriptor [v hkey]
  (cond-> (array-map :type (value-type v))
    (coll? v) (assoc :count (count v))
    true (assoc :vhash (vhash hkey v))))

(defn- collect-leaves [entries path v hkey]
  (if (and (map? v) (seq v))
    (reduce (fn [entries [k vv]]
              (collect-leaves entries (conj path k) vv hkey))
            entries
            v)
    (assoc entries path (descriptor v hkey))))

(defn entries
  "Map a store's value to an ordered `{path-vector descriptor}` map. Non-empty
  maps are recursed into; every other value is a leaf with `:type`, `:count`
  (collections only), and `:vhash` under `manifest-key`. `store-key` gets no
  entry. Throws `:invalid-manifest-key` for a malformed key."
  [secrets manifest-key]
  (collect-leaves (sorted-map-by (fn [a b] (compare (encode a) (encode b))))
                  []
                  (user-data secrets)
                  (key-bytes manifest-key)))

;;;; The manifest file

(def ^:private supported-version
  "The manifest `:version` this library writes and reads."
  3)

(defn- hex-string?
  "True when `x` is a string of exactly `n` lowercase hex characters."
  [n x]
  (and (string? x)
       (= n (count x))
       (some? (re-matches #"[0-9a-f]*" x))))

(defn problem
  "Return nil when parsed manifest `value` is complete, otherwise a map with
  the `:reason`: `:manifest-malformed`, `:unsupported-version`, or
  `:wrong-app`.

  Complete means the `supported-version`, `expected-app` under `:app`, a
  SHA-256 hex `:ciphertext-sha`, and a `:keys` map of vector paths to entries
  with a keyword `:type` and a 16-hex `:vhash`. The `:app` check catches a
  manifest copied from another project, a wrong-file mistake rather than a
  forgery (see `doc/threat-model.md`, B1)."
  [expected-app value]
  (cond
    (not (map? value))
    {:reason :manifest-malformed}

    (not= supported-version (:version value))
    {:reason :unsupported-version :version (:version value)}

    (not= expected-app (:app value))
    {:reason :wrong-app :app (:app value)}

    (not (and (hex-string? 64 (:ciphertext-sha value))
              (map? (:keys value))
              (every? (fn [[path entry]]
                        (and (vector? path)
                             (map? entry)
                             (keyword? (:type entry))
                             (hex-string? 16 (:vhash entry))))
                      (:keys value))))
    {:reason :manifest-malformed}))

(defn print-whole
  "Call `f` with print length, level, and namespace-map shorthand off. A REPL
  that set `*print-length*` would otherwise write `...` into a store or
  manifest."
  [f]
  (binding [*print-length* nil *print-level* nil *print-namespace-maps* false]
    (f)))

(defn render
  "Render `entries` as manifest file text, one key path per line so diffs read
  well. `ciphertext-sha` (SHA-256 hex of the `.age` file) lets CI check the
  manifest is fresh without holding a key."
  [{:keys [app ciphertext-sha]} entries]
  (print-whole
   #(str ";; Auto-generated by `bb secrets`. SAFE TO COMMIT (holds no secret values).\n"
         ";; The shape of the encrypted secrets: each key path, its value type, and a\n"
         ";; keyed hash that changes when the value does. Check with `bb secrets verify`.\n"
         "{:version " supported-version "\n"
         " :app " (pr-str app) "\n"
         " :ciphertext-sha " (pr-str ciphertext-sha) "\n"
         " :keys\n"
         (if (empty? entries)
           " {}}\n"
           (str " {"
                (str/join "\n  " (map (fn [[p d]] (str (pr-str p) " " (pr-str d))) entries))
                "}}\n")))))

(defn diff
  "Compare manifest `entries` maps and return `{:added :removed :changed}` as
  sorted seqs of key paths. `:changed` means present in both with a different
  descriptor."
  [before after]
  (let [bks (set (keys before)) aks (set (keys after))
        srt #(sort-by pr-str %)]
    {:added (srt (remove bks (keys after)))
     :removed (srt (remove aks (keys before)))
     :changed (srt (filter #(and (bks %) (not= (before %) (after %))) (keys after)))}))
