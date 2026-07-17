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

;; ---------- hashing (javax.crypto.Mac — available on the JVM and in bb) ----------

(defn- sha256 ^bytes [^bytes bs]
  (.digest (java.security.MessageDigest/getInstance "SHA-256") bs))

(defn- hmac-sha256 ^bytes [^bytes k ^bytes msg]
  (let [mac (javax.crypto.Mac/getInstance "HmacSHA256")]
    (.init mac (javax.crypto.spec.SecretKeySpec. k "HmacSHA256"))
    (.doFinal mac msg)))

(defn- secret-material
  "The secret-key lines of an age identity file's contents — every line whose
  trimmed form starts with AGE-SECRET-KEY, joined with newlines. Falls back to
  the whole contents trimmed when no such line exists (e.g. an SSH identity)."
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
  to surrounding whitespace — two copies of the same key always agree. Domain-
  separated so it can never collide with any other use of the key material."
  ^bytes [identity-contents]
  (sha256 (.getBytes (str "com.kirahowe.secrets/manifest-v1\n"
                          (secret-material identity-contents))
                     "UTF-8")))

;; ---------- shape ----------

(defn value-type
  "A keyword naming the EDN type of `v`, recorded in the manifest so a change of
  type (e.g. string → set) is visible in the diff."
  [v]
  (cond
    (nil? v)        :nil
    (boolean? v)    :boolean
    (string? v)     :string
    (keyword? v)    :keyword
    (symbol? v)     :symbol
    (integer? v)    :integer
    (float? v)      :float
    (inst? v)       :inst
    (map? v)        :map
    (set? v)        :set
    (vector? v)     :vector
    (sequential? v) :list
    :else           :other))

(defn- canonical
  "A deterministic string for a value: sets and map keys are ordered, so equal
  values serialize identically regardless of hash-map iteration order."
  [v]
  (cond
    (map? v)        (->> v (sort-by (comp pr-str key))
                         (map (fn [[k vv]] (str (pr-str k) \= (canonical vv))))
                         (str/join ";") (format "{%s}"))
    (set? v)        (->> v (map canonical) sort (str/join ";") (format "#{%s}"))
    (sequential? v) (->> v (map canonical) (str/join ";") (format "[%s]"))
    :else           (pr-str v)))

(defn- vhash
  "An 8-byte (16 hex char) keyed HMAC of `v` — enough to reveal that a value
  changed, without revealing or letting a repo-only attacker brute-force it."
  [^bytes hkey v]
  (->> (hmac-sha256 hkey (.getBytes (canonical v) "UTF-8"))
       (take 8)
       (map #(format "%02x" (bit-and % 0xff)))
       (apply str)))

(defn- descriptor [v hkey]
  (cond-> (array-map :type (value-type v))
    (coll? v) (assoc :count (count v))
    hkey      (assoc :vhash (vhash hkey v))))

(defn- leaf-seq [path v hkey]
  (if (and (map? v) (seq v))
    (mapcat (fn [[k vv]] (leaf-seq (conj path k) vv hkey)) v)
    [[path (descriptor v hkey)]]))

(defn entries
  "Map a secrets value to an ordered {path-vector -> descriptor} manifest map.
  Recurses into (non-empty) maps; every other value is a leaf. `hkey` is the
  HMAC key (from `hmac-key`) or nil for a structure-only manifest."
  [secrets hkey]
  (into (sorted-map-by (fn [a b] (compare (pr-str a) (pr-str b))))
        (leaf-seq [] secrets hkey)))

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
       "{:version 1\n"
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
    {:added   (srt (remove bks (keys after)))
     :removed (srt (remove aks (keys before)))
     :changed (srt (filter #(and (bks %) (not= (before %) (after %))) (keys after)))}))
