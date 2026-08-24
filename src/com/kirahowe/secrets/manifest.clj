(ns com.kirahowe.secrets.manifest
  "Pure functions for the plaintext *manifest* that ships next to each encrypted
  secrets file (`secrets.edn.age` → `secrets.edn.manifest`).

  The manifest records the *shape* of the secrets — every key path and its value
  type (and, in single-key mode, a keyed hash of the value) — but never a secret
  value. It is safe to commit, so a `git diff` of the manifest shows which keys
  were added, removed, retyped, or (via the hash) had their value change — even
  though the ciphertext itself diffs opaquely.

  Value hashes (`:vhash`) are an HMAC keyed by a secret derived from the age
  private key *material* — comments and whitespace in the identity file don't
  matter (see `hmac-key`): identical for everyone who shares that key, but
  not reproducible by someone who has only the repo — so a low-entropy secret
  cannot be brute-forced from its hash. In multi-recipient mode there is no
  single shared private key, so callers pass `nil` and the manifest is
  structure-only.

  Everything here is pure and depends only on `clojure.core` + the platform's
  `java.security`/`javax.crypto`, so it loads and runs identically under JVM
  Clojure and babashka."
  (:require [clojure.string :as str]))

;;;; Hashing

(defn- sha256 ^bytes [^bytes bs]
  (.digest (java.security.MessageDigest/getInstance "SHA-256") bs))

(defn- hmac-sha256 ^bytes [^bytes k ^bytes msg]
  (let [mac (javax.crypto.Mac/getInstance "HmacSHA256")]
    (.init mac (javax.crypto.spec.SecretKeySpec. k "HmacSHA256"))
    (.doFinal mac msg)))

(defn- secret-material
  "Return the secret-key lines of an age identity file's contents: every line
  whose trimmed form starts with AGE-SECRET-KEY, joined with newlines. Fall back
  to the whole contents trimmed when no such line exists (e.g. an SSH identity)."
  ^String [identity-contents]
  (let [ks (->> (str/split-lines (str identity-contents))
                (map str/trim)
                (filter #(str/starts-with? % "AGE-SECRET-KEY")))]
    (if (seq ks)
      (str/join "\n" ks)
      (str/trim (str identity-contents)))))

(defn hmac-key
  "Derive the manifest HMAC key from an age identity file's *contents*. Only the
  secret key material is hashed (see `secret-material`), so the derivation is
  insensitive to age-keygen's `# created:` / `# public key:` comment lines and
  to surrounding whitespace — two copies of the same key always agree. It is
  domain-separated from every other use of the key material, and bound to the
  manifest encoding version (see `encode`): the same value hashed under two
  encoding versions can never produce the same `:vhash`."
  ^bytes [identity-contents]
  (sha256 (.getBytes (str "com.kirahowe.secrets/manifest-v2\n"
                          (secret-material identity-contents))
                     "UTF-8")))

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
  "Return the canonical manifest-v2 encoding of `v` as a `String`: exactly one
  `frame` per value, nested for collections. Because every frame declares the
  length of its payload in code units, and every character the framing itself
  uses (the tag, the digits, `:`) is a single code unit, a delimiter character
  *inside* a value can never be read as structure, so nothing needs escaping;
  because every frame carries its `tags` entry, `[[1]]` and `[(1)]` differ. Map
  entries (each the key frame followed by the value frame) and set elements are
  sorted with `compare` so hash-map and hash-set iteration order cannot leak in;
  vector and list elements keep their order, which is significant.

  `vhash` hashes this string as `utf16-bytes`, a lossless code-unit stream, so
  injectivity holds for every Java String rather than only for the ones a
  charset encoder round-trips. Within a single scalar tag it rests on `pr-str`,
  which is exact for every value the EDN reader can produce: a `Float` and a
  `Double` of the same magnitude would collide, but `clojure.edn` only ever
  produces `Double`. Likewise `:other` is a best-effort tag for values EDN
  cannot produce."
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
  to the same bytes — and `clojure.edn` reads a lone surrogate back, so such a
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
  "Return the first 8 bytes of the keyed HMAC of `v` as 16 hex characters. This
  reveals that a value changed without revealing it or letting a repo-only attacker brute-force it."
  [^bytes hkey v]
  (->> (hmac-sha256 hkey (utf16-bytes (encode v)))
       (take 8)
       (map #(format "%02x" (bit-and % 0xff)))
       (apply str)))

(defn- descriptor [v hkey]
  (cond-> (array-map :type (value-type v))
    (coll? v) (assoc :count (count v))
    hkey (assoc :vhash (vhash hkey v))))

(defn- collect-leaves [entries path v hkey]
  (if (and (map? v) (seq v))
    (reduce (fn [entries [k vv]]
              (collect-leaves entries (conj path k) vv hkey))
            entries
            v)
    (assoc entries path (descriptor v hkey))))

(defn entries
  "Map a secrets value to an ordered {path-vector -> descriptor} manifest map.
  Recurses into non-empty maps; every other value is a leaf. `hkey` is the HMAC
  key (from `hmac-key`) or nil for a structure-only manifest."
  [secrets hkey]
  (collect-leaves (sorted-map-by (fn [a b] (compare (encode a) (encode b))))
                  []
                  secrets
                  hkey))

(defn render
  "Render `entries` to the committed manifest file text — one key path per line,
  so `git diff` is line-oriented and readable. The header map supplies `:app`
  and an optional `:ciphertext-sha`, the SHA-256 hex of the encrypted `.age`
  file: recording it lets CI check that the manifest is fresh against the
  ciphertext alone, without holding any private key. When `:ciphertext-sha` is
  nil the line is omitted."
  [{:keys [app ciphertext-sha]} entries]
  (str ";; Auto-generated by `bb secrets` — SAFE TO COMMIT (holds no secret values).\n"
       ";; The shape of the encrypted secrets: each key path and its value type,\n"
       ";; so `git diff` shows which keys changed. Check with `bb secrets verify`.\n"
       "{:version 2\n"
       " :app " (pr-str app) "\n"
       (when ciphertext-sha
         (str " :ciphertext-sha " (pr-str ciphertext-sha) "\n"))
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
