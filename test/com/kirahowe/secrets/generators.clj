(ns com.kirahowe.secrets.generators
  "test.check generators shared by the property suites.

  Each generator describes one shape from the domain: what an age key looks
  like, what a secrets file may hold, which strings are hard on a delimiter
  scanner. Keeping them in one place means every suite draws the same shapes,
  so a case covered here is covered wherever the generator is used."
  (:require [clojure.string :as str]
            [clojure.test.check.generators :as gen]))

;;;; Text

(def wide-char
  "Any UTF-16 code unit, so strings can carry non-Latin text and lone
  surrogates. The EDN reader accepts a lone surrogate, and no charset encoder
  round-trips one, which is why the manifest hashes code units."
  (gen/fmap char (gen/choose 0 0xFFFF)))

(def text
  "A string over the whole UTF-16 range, or over Latin-1, weighted so the
  common case is not always buried under unusual code units."
  (gen/frequency [[3 gen/string]
                  [1 (gen/fmap str/join (gen/vector wide-char 0 12))]]))

(def encodable-text
  "A string every charset encoder keeps: Latin-1, or any run of code units that
  holds no lone surrogate. Text that must survive a file written as UTF-8
  draws from here rather than from `text`."
  (gen/frequency [[3 gen/string]
                  [1 (gen/fmap str/join
                               (gen/vector (gen/fmap char
                                                     (gen/one-of [(gen/choose 0 0xD7FF)
                                                                  (gen/choose 0xE000 0xFFFF)]))
                                           0 12))]]))

(def marker
  "A distinctive alphanumeric string to plant in an input and then look for in
  everything a failure says. Upper-case, so no generated host or path (which
  are lower-case) and no fixed message can contain it by chance."
  (gen/fmap #(str "PLANTED" (str/join %)) (gen/vector gen/char-alphanumeric 6 16)))

(def delimiter-text
  "A string made of the characters a depth scanner must ignore inside a
  literal: every EDN delimiter, the comment marker, the escape character, the
  quote itself, and whitespace."
  (gen/fmap str/join
            (gen/vector (gen/elements [\[ \] \{ \} \( \) \# \; \\ \" \space \newline \tab \a \1])
                        0 10)))

;;;; EDN values

(defn- bounded
  "`generator` with its size capped at 30. A property's cost under babashka
  grows faster than the size test.check hands it, and what these shapes cover
  (nesting, key kinds, awkward strings) is all present well below the default
  of 200."
  [generator]
  (gen/scale #(min % 30) generator))

(defn scalar-of
  "Generator of scalar EDN values that print and read back to themselves, with
  strings drawn from `string-gen`."
  [string-gen]
  (gen/one-of [(gen/return nil)
               gen/boolean
               gen/large-integer
               (gen/double* {:NaN? false :infinite? false})
               string-gen
               delimiter-text
               gen/keyword
               gen/keyword-ns
               gen/symbol
               gen/symbol-ns]))

(def scalar
  "A scalar EDN value that prints and reads back to itself."
  (scalar-of text))

(def value
  "Any EDN value: scalars nested in vectors, lists, sets, and maps, including
  collections used as map keys."
  (bounded
   (gen/recursive-gen (fn [inner]
                        (gen/one-of [(gen/vector inner)
                                     (gen/list inner)
                                     (gen/set inner)
                                     (gen/map inner inner)]))
                      scalar)))

(def secret-key
  "A map key as a secrets file would use one."
  (gen/one-of [gen/keyword gen/keyword-ns gen/string-alphanumeric gen/small-integer]))

(defn secrets-of
  "Generator of a secrets value whose leaves are built from `scalar-gen`."
  [scalar-gen]
  (bounded
   (gen/recursive-gen (fn [inner]
                        (gen/map secret-key inner {:max-elements 5}))
                      (gen/one-of [scalar-gen
                                   (gen/vector scalar-gen)
                                   (gen/set scalar-gen)
                                   (gen/list scalar-gen)]))))

(def secrets
  "A secrets value: maps under `secret-key` keys whose leaves are scalars or
  collections of scalars, or such a leaf on its own. An empty map is a leaf
  of the manifest, so it appears here too."
  (secrets-of scalar))

(def secrets-map
  "A secrets file's top-level map."
  (bounded (gen/map secret-key secrets {:max-elements 5})))

(def encodable-secrets-map
  "A secrets file's top-level map whose strings survive a UTF-8 file, for
  properties that write the printed map to disk."
  (bounded (gen/map secret-key (secrets-of (scalar-of encodable-text)) {:max-elements 5})))

;;;; age keys and identity files

(def ^:private bech32-alphabet
  (vec "qpzry9x8gf2tvdw0s3jn54khce6mua7l"))

(def age-secret-key
  "An identity line as age-keygen writes it: the `AGE-SECRET-KEY-1` prefix
  and 58 upper-case bech32 characters."
  (gen/fmap #(str "AGE-SECRET-KEY-1" (str/upper-case (str/join %)))
            (gen/vector (gen/elements bech32-alphabet) 58)))

(def age-recipient
  "A public key as age prints it: `age1` and 58 lower-case bech32 characters."
  (gen/fmap #(str "age1" (str/join %))
            (gen/vector (gen/elements bech32-alphabet) 58)))

(def ^:private noise-line
  "A line an identity file may hold beside its key: a comment, as age-keygen's
  `# created:` and `# public key:` lines are, or a blank one."
  (gen/one-of [(gen/fmap #(str "# " (str/replace % #"[\r\n]" " ")) gen/string-ascii)
               (gen/elements ["" " " "\t"])]))

(defn decorated-identity
  "Generator of identity file text holding `key-line` the way age-keygen and a
  careless copy might write it: comment lines before and after, blank lines,
  blanks around the key, either line ending, and an optional final newline."
  [key-line]
  (gen/let [before (gen/vector noise-line 0 3)
            after (gen/vector noise-line 0 3)
            left (gen/elements ["" " " "\t"])
            right (gen/elements ["" " " "\t"])
            newline (gen/elements ["\n" "\r\n"])
            trailing (gen/elements ["" "\n"])]
    (str (str/join newline (concat before [(str left key-line right)] after))
         trailing)))
