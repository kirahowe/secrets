(ns com.kirahowe.secrets.source-property-test
  "Properties of source classification. A descriptor keeps a locator's scheme,
  host, port, and path and nothing a credential could sit in. A string with a
  scheme is a locator even after leading whitespace, and `./` makes any
  relative name a path. Only local `file:` and `jar:file:` locators are
  accepted, and a refusal names the source without repeating its credential."
  (:require [clojure.string :as str]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [com.kirahowe.secrets.fs :as fs]
            [com.kirahowe.secrets.generators :as g]
            [com.kirahowe.secrets.source :as source]
            [com.kirahowe.secrets.test-env :refer [rendered thrown]]))

;;;; Shapes

(def ^:private word
  (gen/fmap str/join (gen/vector (gen/elements (vec "abcdefghijklmnopqrstuvwxyz")) 1 8)))

(def ^:private host
  (gen/fmap #(str/join "." %) (gen/vector word 1 3)))

(def ^:private path
  "A URI path: empty, or segments each led by a slash."
  (gen/fmap #(apply str (map (partial str "/") %)) (gen/vector word 0 4)))

(def ^:private port
  (gen/one-of [(gen/return nil) (gen/choose 1 65535)]))

(def ^:private leading-space
  (gen/elements ["" " " "\t" "\n" "  \r\n"]))

(defn- credentialed
  "Generator of `[string expected credential]`: a locator with `scheme`, host,
  port, and path, wrapped in userinfo, query, and fragment that carry a
  planted credential, and the descriptor that keeps none of it."
  [schemes]
  (gen/let [scheme (gen/elements schemes)
            cred g/marker
            user word
            where (gen/such-that seq (gen/set (gen/elements [:userinfo :query :fragment])))
            userinfo-form (gen/elements [:cred :user-cred :cred-pass])
            host host
            port port
            path path]
    (let [userinfo (when (:userinfo where)
                     (case userinfo-form
                       :cred cred
                       :user-cred (str user ":" cred)
                       :cred-pass (str cred ":" user)))]
      [(str scheme "://" (when userinfo (str userinfo "@")) host (when port (str ":" port)) path
            (when (:query where) (str "?token=" cred "&x=1"))
            (when (:fragment where) (str "#" cred)))
       (cond-> {:kind :url :scheme scheme :host host}
         port (assoc :port port)
         (seq path) (assoc :path path))
       cred])))

(def ^:private remote-schemes ["http" "https" "ftp" "s3" "gopher" "HTTP" "Https"])

(def ^:private jar-locator
  "Generator of `[string expected credential]` for a `jar:file:` locator whose
  inner authority and entry query may carry a planted credential."
  (gen/let [cred g/marker
            authority? gen/boolean
            host host
            archive (gen/fmap #(str "/" (str/join "/" %) ".jar") (gen/vector word 1 3))
            entry word
            query? gen/boolean
            fragment? gen/boolean]
    [(str "jar:file:" (when authority? (str "//user:" cred "@" host)) archive "!/" entry
          (when query? (str "?token=" cred))
          (when fragment? (str "#" cred)))
     (cond-> {:kind :url :scheme "jar:file" :path (str archive "!/" entry)}
       authority? (assoc :host host))
     cred]))

(defn- as-form
  "`s` as a `form` of source, keeping the expected descriptor in step: a URL
  reports its protocol in lower case, and a string may lead with whitespace."
  [form space [s expected cred]]
  (case form
    :string [(str space s) expected cred]
    :uri [(java.net.URI. s) expected cred]
    :url [(java.net.URL. s) (update expected :scheme str/lower-case) cred]))

(def ^:private credentialed-source
  "Generator of `[source expected-descriptor credential]` over strings, URIs,
  and (for schemes Java has a handler for) URLs."
  (gen/one-of
   [(gen/let [form (gen/elements [:string :uri])
              space leading-space
              locator (credentialed remote-schemes)]
      (as-form form space locator))
    (gen/let [form (gen/elements [:string :uri :url])
              space leading-space
              locator (credentialed ["http" "https"])]
      (as-form form space locator))
    (gen/let [form (gen/elements [:string :uri])
              space leading-space
              locator jar-locator]
      (as-form form space locator))]))

(defn- acquire-failure
  "The exception `source/acquire!` throws for `input`, or nil when it returns.
  A returned copy is cleaned up first."
  [input]
  (let [result (atom nil)
        e (thrown #(reset! result (source/acquire! input (source/descriptor input) 1024)))]
    (when-let [[_ cleanup!] @result] (cleanup!))
    e))

;;;; Descriptors

(defspec descriptors-keep-the-locator-and-drop-its-credential 300
  (prop/for-all [[input expected cred] credentialed-source]
    (let [d (source/descriptor input)]
      (and (= expected d)
           (not (str/includes? (pr-str d) cred))))))

(defspec a-source-object-is-described-by-its-class-alone 100
  (prop/for-all [cred g/marker]
    (let [d (source/descriptor (reify Object (toString [_] cred)))]
      (and (= :object (:kind d))
           (string? (:class d))
           (not (str/includes? (pr-str d) cred))))))

;;;; Paths and locators

(def ^:private segments
  (gen/fmap #(str/join "/" %) (gen/vector word 1 4)))

(def ^:private plain-path
  "A string with no scheme: absolute, home-relative, dot-relative, or bare
  relative, with a colon allowed after the first segment."
  (gen/one-of [(gen/fmap #(str "/" %) segments)
               (gen/fmap #(str "~/" %) segments)
               (gen/fmap #(str "./" %) segments)
               (gen/fmap #(str "../" %) segments)
               (gen/let [first-segment word
                         more segments
                         tail (gen/elements ["" ":v1" ":2:3"])]
                 (str first-segment "/" more tail))]))

(def ^:private windows-path
  "A drive path, which names a file, not a one-letter URI scheme."
  (gen/let [drive (gen/elements (vec "abcxyzABCXYZ"))
            separator (gen/elements ["\\" "/"])
            rest-of-path (gen/one-of [segments
                                      g/delimiter-text
                                      (gen/fmap #(str "//u:" % "@h/x?q=" %) word)])]
    (str drive ":" separator rest-of-path)))

(defspec a-path-is-a-file-however-much-it-looks-like-a-locator 300
  (prop/for-all [s (gen/one-of [plain-path windows-path])
                 space (gen/elements ["" " " "\t"])]
    (let [padded (str space s)
          e (acquire-failure padded)]
      (and (nil? (source/locator-scheme padded))
           (= {:kind :file :path padded} (source/descriptor padded))
           (not= :disallowed-source (:reason (ex-data e)))))))

(defspec a-name-with-a-colon-is-a-locator-unless-it-starts-with-dot-slash 150
  (prop/for-all [scheme (gen/fmap #(str "k" %) word)
                 drive (gen/elements (vec "abcxyzABCXYZ"))
                 rest-of-name word
                 space leading-space]
    (every? (fn [[name expected-scheme]]
              (let [refused (acquire-failure (str space name))
                    kept (acquire-failure (str "./" name))]
                (and (= expected-scheme (source/locator-scheme (str space name)))
                     (= :disallowed-source (:reason (ex-data refused)))
                     (nil? (source/locator-scheme (str "./" name)))
                     (= :no-file (:reason (ex-data kept))))))
            [[(str scheme ":" rest-of-name) scheme]
             [(str drive ":" rest-of-name) (str/lower-case (str drive))]])))

(defspec local-file-locators-are-accepted-in-every-form 60
  (prop/for-all [form (gen/elements [:string :uri :url])]
    (let [file (fs/owner-only-temp-file! "kira-source-" ".age")
          locator (str "file:" (.getAbsolutePath file))
          input (case form
                  :string locator
                  :uri (java.net.URI. locator)
                  :url (java.net.URL. locator))]
      (try
        (let [[found cleanup!] (source/acquire! input (source/descriptor input) 1024)]
          (cleanup!)
          (and (= (.getAbsolutePath file) (.getAbsolutePath ^java.io.File found))
               (.exists file)))
        (finally
          (.delete file))))))

;;;; Refusals

(def ^:private refused-source
  "Generator of `[source credential]` that local-only policy must refuse."
  (gen/one-of
   [(gen/let [[s _ cred] (credentialed remote-schemes)
              space leading-space]
      [(str space s) cred])
    (gen/fmap (fn [[s _ cred]] [(java.net.URI. s) cred]) (credentialed remote-schemes))
    (gen/fmap (fn [[s _ cred]] [(java.net.URL. s) cred]) (credentialed ["http" "https"]))
    (gen/let [cred g/marker
              host host
              space leading-space
              shape (gen/elements [:authority :query :fragment :remote-jar :nested-jar])]
      [(str space
            (case shape
              :authority (str "file://user:" cred "@" host "/store.age")
              :query (str "file:/store.age?token=" cred)
              :fragment (str "file:/store.age#" cred)
              :remote-jar (str "jar:http://user:" cred "@" host "/app.jar!/store.age")
              :nested-jar (str "jar:jar:file:/a.jar!/b.jar!/store.age?token=" cred)))
       cred])
    (gen/fmap (fn [cred] [(reify Object (toString [_] cred)) cred]) g/marker)]))

(defspec a-non-local-source-is-refused-without-its-credential 300
  (prop/for-all [[input cred] refused-source]
    (let [e (acquire-failure input)]
      (and (instance? clojure.lang.ExceptionInfo e)
           (= :disallowed-source (:reason (ex-data e)))
           (= (source/descriptor input) (:source (ex-data e)))
           (nil? (ex-cause e))
           (not (str/includes? (rendered e) cred))))))
