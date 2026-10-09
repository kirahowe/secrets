(ns com.kirahowe.secrets.secrets-property-test
  "Properties of the runtime namespace. Only `~` and a leading `~/` expand to
  the home directory. Identity sources resolve in their documented order, and
  a blank or malformed variable is refused instead of skipped, and a
  designated identity file that does not exist is refused by name. An injected
  identity is private, exact, and gone after the call, whether the callback
  returns or throws. A caller's own identity file is never touched, and a path setting that holds
  key contents or a locator is refused without repeating it. `get-secret`
  returns what is stored and falls back only for an absent key. A load that
  fails never repeats the text it rejected, and a generated secrets file
  survives a real encrypt and load."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.fs :as fs]
            [com.kirahowe.secrets.generators :as g]
            [com.kirahowe.secrets.safe-edn]
            [com.kirahowe.secrets.test-env :as test-env :refer [rendered thrown]]))

(defn- with-env
  "Call `f` with `environment` as the whole identity environment."
  [environment f]
  (with-redefs-fn (test-env/getenv-redefs environment) f))

(defn- encode [text]
  (.encodeToString (java.util.Base64/getEncoder) (.getBytes ^String text "UTF-8")))

(def ^:private identity-text
  "Identity file text, comments and blank lines included."
  (gen/bind g/age-secret-key g/decorated-identity))

(defn- key-line [text]
  (first (filter #(str/starts-with? % "AGE-SECRET-KEY-1") (map str/trim (str/split-lines text)))))

(def ^:private key-dir
  "A temporary directory for the identity files these properties name. A
  designated identity path has to exist, so a path-text value must be real."
  (delay
    (let [dir (java.nio.file.Files/createTempDirectory
               "kira-secrets-identity-property-test"
               (into-array java.nio.file.attribute.FileAttribute []))]
      (.deleteOnExit (.toFile dir))
      (str dir))))

(def ^:private missing-path-text
  "A path under `key-dir` that no property creates."
  (gen/fmap #(str @key-dir "/missing-" %) (gen/not-empty gen/string-alphanumeric)))

(def ^:private path-text
  "A path under `key-dir`. Call `touch!` on it where the file must exist."
  (gen/fmap #(str @key-dir "/" %) (gen/not-empty gen/string-alphanumeric)))

(defn- touch!
  "Create the empty file at `path` unless it exists, and return `path`."
  [path]
  (let [f (io/file path)]
    (when-not (.exists f)
      (spit f "")
      (.deleteOnExit f))
    path))

(def ^:private word (gen/not-empty gen/string-alphanumeric))

(def ^:private scheme-word
  "A word that starts with a letter, so `scheme-word:rest` reads as a URI scheme."
  (gen/fmap #(str "k" %) word))

;;;; expand-home

(defspec only-tilde-and-tilde-slash-expand-to-the-home-directory 200
  (prop/for-all [rest-of-path g/text
                 name word
                 other (gen/elements ["/" "x" " " "./"])]
    (let [home (System/getProperty "user.home")]
      (and (= home (fs/expand-home "~"))
           (= (str home "/" rest-of-path) (fs/expand-home (str "~/" rest-of-path)))
           (every? #(= % (fs/expand-home %))
                   [(str "~" name "/" rest-of-path)
                    (str "~" name)
                    (str "~~/" rest-of-path)
                    (str other "~/" rest-of-path)
                    (str other rest-of-path)])))))

;;;; Identity resolution

(def ^:private whitespace-run
  (gen/fmap str/join (gen/vector (gen/elements [\space \tab \return \newline]) 0 3)))

(defn- wrapped-b64
  "Generator of `text` base64-encoded, then cut into up to seven pieces with
  runs of the four tolerated whitespace characters between and around them."
  [text]
  (let [encoded (encode text)]
    (gen/let [cuts (gen/vector (gen/choose 0 (count encoded)) 0 6)
              breaks (gen/vector whitespace-run 8)
              trailing whitespace-run]
      (let [bounds (sort (distinct (concat [0 (count encoded)] cuts)))
            pieces (map #(subs encoded %1 %2) bounds (rest bounds))]
        (str (apply str (map str breaks pieces)) trailing)))))

(def ^:private identity-and-wrapped
  "Generator of `[identity-text base64-of-it-with-whitespace]`."
  (gen/let [text identity-text
            wrapped (wrapped-b64 text)]
    [text wrapped]))

(def ^:private resolution
  "Generator of which identity sources are present, with the values they hold,
  as `{:arg :env :expected}`: the argument for `with-identity`, the
  environment, and what the documented order hands the callback, as a path and
  source or as a source and file contents."
  (gen/let [[explicit? file? raw? b64? key-file? app?] (gen/vector gen/boolean 6)
            bare? gen/boolean
            explicit path-text
            file-path path-text
            key-file path-text
            app word
            [text wrapped] identity-and-wrapped]
    (let [bare-explicit? (and explicit? bare?)
          candidates [[explicit? {:path explicit :source :identity-file}]
                      [file? {:path file-path :source :secrets-age-identity-file}]
                      [raw? {:contents text :source :secrets-age-identity}]
                      [b64? {:contents text :source :secrets-age-identity-b64}]
                      [(and key-file? (not bare-explicit?))
                       {:path key-file :source :configured-key-file}]
                      [(and app? (not bare-explicit?))
                       {:path (fs/default-key-file app) :source :default-key-file}]]]
      {:arg (if bare-explicit?
              explicit
              (cond-> {}
                explicit? (assoc :identity-file explicit)
                key-file? (assoc :key-file key-file)
                app? (assoc :app app)))
       :env (cond-> {}
              file? (assoc "SECRETS_AGE_IDENTITY_FILE" file-path)
              raw? (assoc "SECRETS_AGE_IDENTITY" text)
              b64? (assoc "SECRETS_AGE_IDENTITY_B64" wrapped))
       :expected (or (some (fn [[present? expected]] (when present? expected)) candidates)
                     {:path nil :source nil})})))

(defspec identity-sources-resolve-in-documented-order 300
  (prop/for-all [{:keys [arg env expected]} resolution]
    (let [_ (when (and (:path expected) (not= :default-key-file (:source expected)))
              (touch! (:path expected)))
          seen (with-env env
                 #(secrets/with-identity
                    arg
                    (fn [{:keys [identity-file identity-source]}]
                      (cond-> {:source identity-source}
                        (:contents expected) (assoc :contents (slurp identity-file))
                        (not (:contents expected)) (assoc :path identity-file)))))]
      (and (= (:source expected) (:source seen))
           (= (:path expected) (:path seen))
           (= (:contents expected) (:contents seen))))))

(def ^:private identity-vars
  ["SECRETS_AGE_IDENTITY_FILE" "SECRETS_AGE_IDENTITY" "SECRETS_AGE_IDENTITY_B64"])

(def ^:private blank-text
  (gen/elements ["" " " "\n" "\t" " \r\n "]))

(defspec a-blank-identity-variable-is-refused-not-skipped 200
  (prop/for-all [index (gen/choose 0 2)
                 blank blank-text
                 later-set? (gen/vector gen/boolean 2)
                 text identity-text
                 key-file path-text
                 app word]
    (let [blank-var (nth identity-vars index)
          later (drop (inc index) identity-vars)
          later-values {"SECRETS_AGE_IDENTITY_FILE" "/keys/later"
                        "SECRETS_AGE_IDENTITY" text
                        "SECRETS_AGE_IDENTITY_B64" (encode text)}
          environment (into {blank-var blank}
                            (for [[v set?] (map vector later later-set?) :when set?]
                              [v (later-values v)]))
          called? (atom false)
          e (thrown #(with-env environment
                       (fn [] (secrets/with-identity {:key-file key-file :app app}
                                (fn [_] (reset! called? true))))))]
      (and (instance? clojure.lang.ExceptionInfo e)
           (= blank-var (:env (ex-data e)))
           (str/includes? (ex-message e) blank-var)
           (not @called?)
           (not (str/includes? (rendered e) (key-line text)))))))

(defspec a-blank-variable-is-ignored-when-an-explicit-path-is-given 100
  (prop/for-all [index (gen/choose 0 2)
                 blank blank-text
                 explicit path-text
                 form (gen/elements [:string :opts])]
    (let [arg (if (= :string form) (touch! explicit) {:identity-file (touch! explicit)})
          seen (with-env {(nth identity-vars index) blank}
                 #(secrets/with-identity arg identity))]
      (and (= explicit (:identity-file seen))
           (= :identity-file (:identity-source seen))))))

(def ^:private invalid-b64-pieces
  "Characters that are neither base64 alphabet nor the tolerated whitespace:
  the URL-safe variants, other ASCII whitespace, and non-ASCII."
  (gen/elements [\! \- \_ \. \* \formfeed \u000b \u0000 (char 0xa0) (char 0x2003) (char 0xe9)]))

(defn- invalid-b64
  "Generator of a base64 encoding of `text` that no canonical decoder accepts:
  a foreign character inserted, one character deleted, or one character
  appended. A canonical encoding is a multiple of four characters long, so
  the last two can never produce another one."
  [text]
  (let [encoded (encode text)]
    (gen/let [op (gen/elements [:insert :delete :append])
              i (gen/choose 0 (dec (count encoded)))
              foreign invalid-b64-pieces
              extra (gen/elements (vec "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/="))]
      (case op
        :insert (str (subs encoded 0 i) foreign (subs encoded i))
        :delete (str (subs encoded 0 i) (subs encoded (inc i)))
        :append (str encoded extra)))))

(defn- windows
  "Every `size`-character substring of `s`."
  [size s]
  (map #(subs s % (+ % size)) (range 0 (inc (- (count s) size)))))

(defspec an-invalid-base64-variable-is-refused-without-repeating-it 150
  (prop/for-all [[text input] (gen/let [text identity-text
                                        bad (invalid-b64 text)]
                                [text bad])
                 key-file path-text]
    (let [called? (atom false)
          e (thrown #(with-env {"SECRETS_AGE_IDENTITY_B64" input}
                       (fn [] (secrets/with-identity {:key-file key-file}
                                (fn [_] (reset! called? true))))))
          shown (rendered e)]
      (and (instance? clojure.lang.ExceptionInfo e)
           (= "SECRETS_AGE_IDENTITY_B64" (:env (ex-data e)))
           (nil? (ex-cause e))
           (not @called?)
           (not (str/includes? shown (key-line text)))
           (not-any? #(str/includes? shown %) (windows 6 input))))))

;;;; Injected identities

(defn- observe
  "What a callback sees of the identity file it is handed."
  [{:keys [identity-file identity-source]}]
  {:path identity-file
   :source identity-source
   :exists? (.exists (io/file identity-file))
   :permissions (test-env/permission-names identity-file)
   :contents (slurp identity-file)})

(defspec an-injected-identity-is-private-exact-and-gone-after-the-call 60
  (prop/for-all [[text wrapped] identity-and-wrapped
                 kind (gen/elements [:raw :b64])
                 outcome (gen/elements [:return :throw])]
    (let [environment (if (= :raw kind)
                        {"SECRETS_AGE_IDENTITY" text}
                        {"SECRETS_AGE_IDENTITY_B64" wrapped})
          seen (atom nil)
          failure (ex-info "callback failed" {:reason :callback-failed})
          result (atom nil)
          error (thrown #(with-env environment
                           (fn []
                             (reset! result
                                     (secrets/with-identity
                                       nil
                                       (fn [identity]
                                         (reset! seen (observe identity))
                                         (if (= :throw outcome)
                                           (throw failure)
                                           [:returned text])))))))
          {:keys [path source exists? permissions contents]} @seen]
      (and (= (if (= :raw kind) :secrets-age-identity :secrets-age-identity-b64) source)
           exists?
           (= test-env/owner-only-names permissions)
           (= text contents)
           (not (.exists (io/file path)))
           (if (= :throw outcome)
             (identical? failure error)
             (and (nil? error) (= [:returned text] @result)))))))

(defspec a-caller-owned-identity-path-is-never-deleted 40
  (prop/for-all [text identity-text
                 via (gen/elements [:string :opts :env :key-file])
                 outcome (gen/elements [:return :throw])]
    (let [file (fs/owner-only-temp-file! "kira-identity-" ".txt")
          path (.getAbsolutePath file)]
      (try
        (spit file text)
        (let [seen (atom nil)
              f (fn [identity]
                  (reset! seen identity)
                  (when (= :throw outcome) (throw (Exception.))))
              arg (case via
                    :string path
                    :opts {:identity-file path}
                    :env nil
                    :key-file {:key-file path})
              environment (when (= :env via) {"SECRETS_AGE_IDENTITY_FILE" path})
              error (thrown #(with-env environment (fn [] (secrets/with-identity arg f))))]
          (and (= path (:identity-file @seen))
               (= (some? error) (= :throw outcome))
               (.exists file)
               (= text (slurp file))))
        (finally
          (.delete file))))))

(def ^:private refused-path
  "Generator of `[value secret]`: a path setting that holds key contents or a
  locator carrying a credential, and the text no failure may repeat."
  (gen/let [kind (gen/elements [:key :locator :bare])
            key g/age-secret-key
            marker g/marker
            scheme (gen/elements ["http" "https" "s3" "file" "HTTPS"])
            prefix (gen/elements ["" "/keys/" "x"])
            name scheme-word]
    (case kind
      :key [(str prefix key) key]
      :locator [(str scheme "://user:" marker "@host/key.txt?token=" marker) marker]
      :bare [(str name ":" marker) marker])))

(defspec a-path-setting-holding-a-key-or-a-locator-is-refused-whole 200
  (prop/for-all [[value secret] refused-path
                 via (gen/elements [:string :opts :env :key-file])]
    (let [called? (atom false)
          arg (case via
                :string value
                :opts {:identity-file value}
                :env nil
                :key-file {:key-file value})
          environment (when (= :env via) {"SECRETS_AGE_IDENTITY_FILE" value})
          e (thrown #(with-env environment
                       (fn [] (secrets/with-identity arg (fn [_] (reset! called? true))))))]
      (and (instance? clojure.lang.ExceptionInfo e)
           (= :disallowed-identity (:reason (ex-data e)))
           (not @called?)
           (not (str/includes? (rendered e) secret))))))

(defspec a-relative-name-with-a-colon-is-a-path-only-with-a-dot-slash 100
  (prop/for-all [name scheme-word
                 rest-of-name word]
    (let [bare (str name ":" rest-of-name)
          refused (thrown #(secrets/with-identity bare identity))
          ;; Only the dot-slash form gets past the locator check, to the
          ;; existence check that the missing file then fails.
          kept (thrown #(secrets/with-identity (str "./" bare) identity))]
      (and (= :disallowed-identity (:reason (ex-data refused)))
           (= :no-identity (:reason (ex-data kept)))
           (= (str "./" bare) (:identity-file (ex-data kept)))))))

(def ^:private designation-sources
  "Each way to designate an identity file, and the `:identity-source` it reports."
  {:string :identity-file
   :opts :identity-file
   :env :secrets-age-identity-file})

(defspec a-designated-identity-that-does-not-exist-is-refused-by-name 200
  (prop/for-all [path missing-path-text
                 via (gen/elements (keys designation-sources))
                 tilde? gen/boolean
                 name word]
    (let [home (System/getProperty "user.home")
          value (if tilde? (str "~/.kira-secrets-property-missing/" name) path)
          expanded (if tilde? (str home "/.kira-secrets-property-missing/" name) path)
          called? (atom false)
          arg (case via
                :string value
                :opts {:identity-file value}
                :env nil)
          environment (when (= :env via) {"SECRETS_AGE_IDENTITY_FILE" value})
          e (thrown #(with-env environment
                       (fn [] (secrets/with-identity arg (fn [_] (reset! called? true))))))]
      (and (instance? clojure.lang.ExceptionInfo e)
           (= :no-identity (:reason (ex-data e)))
           (= expanded (:identity-file (ex-data e)))
           (= (designation-sources via) (:identity-source (ex-data e)))
           (str/includes? (ex-message e) expanded)
           (not @called?)))))

(defspec a-default-key-location-need-not-exist 50
  (prop/for-all [app word
                 path missing-path-text]
    (let [seen (with-env {} #(secrets/with-identity {:app (str "kira-missing-" app)} identity))
          configured (with-env {} #(secrets/with-identity {:key-file path :app app} identity))]
      (and (= :default-key-file (:identity-source seen))
           (= (fs/default-key-file (str "kira-missing-" app)) (:identity-file seen))
           (= {:identity-file path :identity-source :configured-key-file} configured)))))

;;;; get-secret

(def ^:private small-secrets
  "A non-recursive secrets map: scalars, and maps of scalars one level down."
  (gen/not-empty
   (gen/map g/secret-key
            (gen/one-of [g/scalar (gen/map g/secret-key g/scalar {:max-elements 3})])
            {:max-elements 4})))

(defn- node-paths
  "Every key path from `m` into nested maps, intermediate paths included."
  [m]
  (mapcat (fn [[k v]]
            (cons [k] (when (and (map? v) (seq v)) (map #(into [k] %) (node-paths v)))))
          m))

(defn- map-node-paths
  "The paths of `m` itself and of every non-empty map inside it."
  [m]
  (cons [] (filter #(map? (get-in m %)) (node-paths m))))

(defspec get-secret-returns-what-was-stored-even-when-it-is-falsy 50
  (prop/for-all [m small-secrets
                 stored (gen/one-of [(gen/return nil) (gen/return false) g/scalar])
                 index gen/nat
                 default (gen/elements [::default 0 "default" :other])]
    (let [paths (vec (node-paths m))
          path (nth paths (mod index (count paths)))]
      (= stored (secrets/get-secret (assoc-in m path stored) path default)))))

(defspec get-secret-falls-back-only-for-an-absent-key 50
  (prop/for-all [m small-secrets
                 index gen/nat
                 default (gen/elements [nil ::default false 0 "default"])]
    (let [parents (vec (map-node-paths m))
          parent (nth parents (mod index (count parents)))
          absent (conj parent ::absent)]
      (and (= default (secrets/get-secret m absent default))
           (nil? (secrets/get-secret m absent))))))

(defspec a-single-key-reads-as-a-one-element-path 50
  (prop/for-all [m small-secrets
                 default (gen/elements [nil ::default false])]
    (every? (fn [k] (= (secrets/get-secret m k default) (secrets/get-secret m [k] default)))
            (cons ::absent (keys m)))))

;;;; Loading

(def ^:private fixture
  "One identity in a temporary directory, made on first use."
  (delay
    (let [dir (java.nio.file.Files/createTempDirectory
               "kira-secrets-property-test"
               (into-array java.nio.file.attribute.FileAttribute []))
          key (str dir "/key.txt")]
      (.deleteOnExit (.toFile dir))
      (age/keygen! key)
      (.deleteOnExit (io/file key))
      {:dir (str dir) :key key})))

(defn- with-ciphertext
  "Encrypt `text` to the fixture identity, call `f` with the ciphertext path,
  and delete the files afterwards."
  [text f]
  (let [{:keys [dir key]} @fixture
        id (str (random-uuid))
        plain (str dir "/" id ".edn")
        encrypted (str dir "/" id ".age")]
    (try
      (spit plain text)
      (age/encrypt-file! {:identity-file key} plain encrypted)
      (f encrypted)
      (finally
        (.delete (io/file plain))
        (.delete (io/file encrypted))))))

(def ^:private max-edn-depth
  "The nesting depth the loader refuses past. It is a fixed private constant,
  so the deep template reads it rather than guessing."
  @#'com.kirahowe.secrets.safe-edn/max-depth)

(defn- malformed
  "Generator of malformed secrets text that repeats `marker` inside a string
  or token, and loading it must fail."
  [marker]
  (gen/let [extra (gen/choose 1 5)
            template (gen/elements [:unclosed :odd-map :duplicate-set :duplicate-key :bad-tag
                                    :bad-instant :bad-escape :bad-char :extra :deep])]
    (case template
      :unclosed (str "{:k [\"" marker "\"")
      :odd-map (str "{:k \"" marker "\" :v}")
      :duplicate-set (str "#{\"" marker "\" \"" marker "\"}")
      :duplicate-key (str "{\"" marker "\" 1 \"" marker "\" 2}")
      :bad-tag (str "#" marker " 1")
      :bad-instant (str "{:at #inst \"" marker "\"}")
      :bad-escape (str "[1 " marker "\\")
      :bad-char (str "{:k \\" marker "}")
      :extra (str "{:k \"" marker "\"} [\"" marker "\"]")
      :deep (let [layers (+ max-edn-depth extra)]
              (str (str/join (repeat layers "[")) "\"" marker "\""
                   (str/join (repeat layers "]")))))))

(def ^:private edn-reasons #{:edn-empty :edn-extra-values :edn-too-deep :edn-malformed})

(defspec a-load-of-malformed-text-never-repeats-it 30
  (prop/for-all [[marker text] (gen/let [marker g/marker
                                         failing (malformed marker)]
                                 [marker failing])]
    (with-ciphertext text
      (fn [encrypted]
        (let [e (thrown #(secrets/load-secrets encrypted {:identity-file (:key @fixture)}))]
          (and (instance? clojure.lang.ExceptionInfo e)
               (contains? edn-reasons (:reason (ex-data e)))
               (not (str/includes? (rendered e) marker))))))))

(defspec an-identity-age-rejects-is-not-repeated-and-its-file-is-deleted 15
  (prop/for-all [[text wrapped] identity-and-wrapped
                 kind (gen/elements [:raw :b64])]
    (with-ciphertext (pr-str {:k 1})
      (fn [encrypted]
        (let [environment (if (= :raw kind)
                            {"SECRETS_AGE_IDENTITY" text}
                            {"SECRETS_AGE_IDENTITY_B64" wrapped})
              e (thrown #(with-env environment (fn [] (secrets/load-secrets encrypted))))
              path (:identity-file (ex-data e))]
          (and (instance? clojure.lang.ExceptionInfo e)
               (string? path)
               (not (.exists (io/file path)))
               (not (str/includes? (rendered e) (key-line text)))))))))

(defspec a-generated-secrets-file-loads-back-as-it-was-encrypted 12
  (prop/for-all [m (gen/resize 30 g/encodable-secrets-map)]
    (with-ciphertext (pr-str m)
      (fn [encrypted]
        (= m (secrets/load-secrets encrypted (:key @fixture)))))))
