(ns com.kirahowe.secrets.manifest
  "Pure functions for the plaintext manifest that ships next to each encrypted
  secrets file (`secrets.edn.age` → `secrets.edn.manifest`), and for the
  library metadata a store carries to produce it.

  The manifest records the shape of the secrets: every key path, its value
  type, and a keyed hash of its value (`:vhash`). It never records a value. It
  is safe to commit, so a `git diff` of the manifest shows which keys were
  added, removed, retyped, or had their value change, while the ciphertext
  diffs opaquely.

  A `:vhash` is an HMAC keyed by the store's manifest key: 256 random bits
  held inside the encrypted EDN under `store-key`. Everyone who can decrypt the
  store computes the same hashes, and someone who has only the repository
  cannot test guesses of a low-entropy value against them. Solo and team stores
  work the same way.

  A manifest is a review aid, not an authorization check. It records what a
  ciphertext contains, never who produced it. See `doc/threat-model.md` in the
  repository.

  Everything here depends only on `clojure.core` and the platform's
  `java.security`/`javax.crypto`, so it loads and runs identically under JVM
  Clojure and babashka."
  (:require [clojure.string :as str]))

;;;; Store metadata

(def store-key
  "The reserved top-level key under which a store holds its manifest key."
  :com.kirahowe.secrets/manifest-key)

(def store-recipients
  "The reserved top-level key under which a store records the `recipients-id`
  of the recipient set it was last encrypted to."
  :com.kirahowe.secrets/manifest-recipients)

(def reserved-keys
  "The top-level keys of a store that are library metadata and never user data."
  #{store-key store-recipients})

(defn user-data
  "Return decrypted store `value` without the library's `reserved-keys`. A
  value that is not a map is returned unchanged."
  [value]
  (if (map? value)
    (apply dissoc value reserved-keys)
    value))

(defn- hex ^String [bs]
  (apply str (map #(format "%02x" (bit-and % 0xff)) bs)))

(defn generate-key
  "Return a new manifest key: 32 bytes from `SecureRandom` as 64 lowercase hex
  characters."
  []
  (let [bs (byte-array 32)]
    (.nextBytes (java.security.SecureRandom.) bs)
    (hex bs)))

(defn valid-key?
  "True when `x` is a well-formed manifest key: a string of 64 lowercase hex
  characters."
  [x]
  (boolean (and (string? x) (re-matches #"[0-9a-f]{64}" x))))

(defn recipients-id
  "Return the string a store records for the recipient set it is encrypted to:
  the SHA-256 hex of the distinct `recipients`, sorted and joined by newlines.
  Single-key mode has no list and passes nil, which gives the fixed word
  `identity`: the identity that decrypts such a store is the one it is
  encrypted to."
  [recipients]
  (if (nil? recipients)
    "identity"
    (hex (.digest (java.security.MessageDigest/getInstance "SHA-256")
                  (.getBytes ^String (str/join "\n" (sort (distinct recipients)))
                             "UTF-8")))))

;;;; Hashing

(defn- key-bytes
  "Decode manifest key `k` to its 32 bytes. Anything that is not a well-formed
  key throws, so a missing key can never produce a manifest without hashes."
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
  "Return a keyword naming the EDN type of `v`, recorded in the manifest so a
  change of type (e.g. string → set) is visible in the diff."
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
  "The frame tag of every `value-type` result. One tag per type, so a vector, a
  list and a set holding equal elements encode differently."
  {:nil "n" :boolean "b" :string "s" :keyword "k" :symbol "y" :integer "i"
   :float "f" :inst "t" :map "m" :set "S" :vector "V" :list "L" :other "o"})

(defn- frame
  "Return `payload` framed as `<tag>:<code-unit-count>:<payload>`."
  ^String [tag ^String payload]
  (str tag \: (count payload) \: payload))

(defn- encode
  "Return the canonical manifest encoding of `v` as a `String`: exactly one
  `frame` per value, nested for collections. Because every frame declares the
  length of its payload in code units, and every character the framing itself
  uses (the tag, the digits, `:`) is a single code unit, a delimiter character
  *inside* a value can never be read as structure, so nothing needs escaping;
  because every frame carries its `tags` entry, `[[1]]` and `[(1)]` differ. Map
  entries (each the key frame followed by the value frame) and set elements are
  sorted with `compare` so hash-map and hash-set iteration order cannot leak in;
  vector and list elements keep their order, which is significant.

  The encoding is unambiguous: two values the EDN reader can produce share an
  encoding only when they are equal. `vhash` feeds this string to the HMAC as
  `utf16-bytes`, a lossless code-unit stream, so that holds for every Java
  String and not only for the ones a charset encoder round-trips. Within a
  single scalar tag it rests on `pr-str`, which is exact for every value the
  EDN reader can produce: a `Float` and a `Double` of the same magnitude would
  encode alike, but `clojure.edn` only ever produces `Double`. Likewise
  `:other` is a best-effort tag for values EDN cannot produce.

  The `:vhash` is a different matter. It is a 64-bit truncation of the HMAC, so
  two different values can share one."
  ^String [v]
  (let [t (value-type v)
        tag (tags t)]
    (case t
      :map (frame tag (apply str (sort (map (fn [[k vv]] (str (encode k) (encode vv))) v))))
      :set (frame tag (apply str (sort (map encode v))))
      (:vector :list) (frame tag (apply str (map encode v)))
      (frame tag (pr-str v)))))

(defn- utf16-bytes
  "Return the code units of `s` as big-endian byte pairs. A charset encoder is
  deliberately not used: every JDK charset substitutes an unpaired surrogate
  (`?` under UTF-8, U+FFFD under UTF-16BE), so two distinct Strings would encode
  to the same bytes, and `clojure.edn` reads a lone surrogate back, so such a
  String can reach here from a real secrets file. Copying the code units out
  directly is lossless for any Java String."
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
  "Return the first 8 bytes of the keyed HMAC of `v` as 16 hex characters. A
  changed hash shows that a value changed without revealing the value or
  letting someone who has only the repository test guesses against it. At 64
  bits the hash can collide, so an unchanged hash is strong evidence of an
  unchanged value, not proof. The key is the only other input, so equal values
  at different paths in one store hash equally."
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
  "Map a store's value to an ordered {path-vector -> descriptor} manifest map.
  Recurses into non-empty maps; every other value is a leaf with its `:type`,
  a `:count` when it is a collection, and its `:vhash` under `manifest-key`.
  The store's `reserved-keys` get no entry. Throws when `manifest-key` is not
  a well-formed key."
  [secrets manifest-key]
  (collect-leaves (sorted-map-by (fn [a b] (compare (encode a) (encode b))))
                  []
                  (user-data secrets)
                  (key-bytes manifest-key)))

;;;; The manifest file

(def supported-version
  "The one manifest `:version` this library writes and reads."
  3)

(defn- hex-string?
  "True when `x` is a string of exactly `n` lowercase hex characters."
  [n x]
  (and (string? x)
       (= n (count x))
       (some? (re-matches #"[0-9a-f]*" x))))

(defn problem
  "Return nil when `value`, a parsed manifest, is complete, and otherwise a
  map with the `:reason` it is not.

  A complete manifest is a map with the `supported-version`, `expected-app`
  under `:app`, a SHA-256 hex `:ciphertext-sha`, and a `:keys` map in which
  every path is a vector and every entry has a keyword `:type` and a 16 hex
  character `:vhash`. The `:version` check keeps a manifest in another format
  from being compared at all. The `:app` check catches a manifest copied from
  another project, which is an operator's wrong-file mistake and not a forged
  manifest (see `doc/threat-model.md`, B1)."
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

(defn render
  "Render `entries` to the committed manifest file text, one key path per
  line, so `git diff` is line-oriented and readable. `ciphertext-sha` is the
  SHA-256 hex of the encrypted `.age` file: recording it lets CI check that the
  manifest is fresh against the ciphertext alone, without holding any key."
  [{:keys [app ciphertext-sha]} entries]
  (str ";; Auto-generated by `bb secrets`. SAFE TO COMMIT (holds no secret values).\n"
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
              "}}\n"))))

(defn diff
  "Compare two manifest `entries` maps (`before` = committed, `after` = fresh);
  return {:added :removed :changed} as sorted seqs of key paths. `:changed` =
  present in both with a different descriptor (type, count, or value hash)."
  [before after]
  (let [bks (set (keys before)) aks (set (keys after))
        srt #(sort-by pr-str %)]
    {:added (srt (remove bks (keys after)))
     :removed (srt (remove aks (keys before)))
     :changed (srt (filter #(and (bks %) (not= (before %) (after %))) (keys after)))}))
