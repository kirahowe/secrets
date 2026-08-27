(ns com.kirahowe.secrets.publish-policy-test
  "The credential-bearing classpath, and one real upload of a fixture artifact.

  Two things are checked here. First, what `clojure -M:deploy` resolves: the set
  reviewed in `doc/release-dependency-review.md`, and nothing from the S3 and
  legacy-wagon branches the previous publisher dragged onto the classpath that
  holds the Clojars token. Second, that the publisher running on that classpath
  uploads exactly the bytes a receipt names — against a local recorder, never
  Clojars — and discloses no credential while doing it.

  Nothing here requires `com.kirahowe.secrets.publish`: it needs maven-resolver,
  which the `:test` alias deliberately does not have, so loading it would fail.
  Every assertion is made against the output of a subprocess run on the
  `:deploy` classpath instead. `com.kirahowe.secrets.release` is required, for
  the receipt the publisher reads; it needs nothing but the JDK.

  Every credential here is a fixture, every repository is a local server, and
  nothing is published."
  (:require [clojure.java.io :as io]
            [clojure.java.shell :as sh]
            [clojure.set :as set]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [com.kirahowe.secrets.release :as release])
  (:import [com.sun.net.httpserver HttpExchange HttpHandler HttpServer]
           [java.io ByteArrayOutputStream]
           [java.net InetSocketAddress]
           [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]
           [java.util Arrays]
           [java.util.concurrent TimeUnit]
           [java.util.zip ZipEntry ZipOutputStream]))

;;;; Subprocesses

(def ^:private command-timeout-ms
  "How long any one `clojure` invocation may take before it is killed.

  Dependency resolution reaches the network on a cold cache; a resolution that
  hangs must fail this test rather than block the suite."
  180000)

(defn- clojure-cli?
  "Whether a `clojure` CLI is on the PATH at all."
  []
  (zero? (:exit (sh/sh "sh" "-c" "command -v clojure"))))

(defn- skipped
  "Reports a check skipped for `reason` and passes.

  `clojure.test` has no skip, and a subprocess-driven check cannot run without
  the subprocess. A stated reason beats a silent pass."
  [reason]
  (println "SKIP" (str *ns*) "-" reason)
  (is true reason))

(defn- run-process
  "Runs `command` under `dir` with `env` added to the environment.

  Returns `{:exit :out :err}`, or throws once [[command-timeout-ms]] has passed.
  Both streams are drained while the process runs, so a chatty resolver cannot
  fill a pipe and deadlock."
  [dir env command]
  (let [builder (doto (ProcessBuilder. ^java.util.List command)
                  (.directory (io/file dir)))
        _ (.putAll (.environment builder) env)
        process (.start builder)
        out (future (slurp (.getInputStream process)))
        err (future (slurp (.getErrorStream process)))]
    (when-not (.waitFor process command-timeout-ms TimeUnit/MILLISECONDS)
      (.destroyForcibly process)
      (throw (ex-info (str "Timed out after " command-timeout-ms "ms: "
                           (str/join " " command))
                      {:command command :dir (str dir)})))
    {:exit (.exitValue process) :out @out :err @err}))

(defn- run-clojure
  "Runs `args` through the Clojure CLI under `dir` with `env` additions."
  [dir env args]
  (run-process dir env (into ["clojure"] args)))

;;;; The reviewed classpath

(def ^:private reviewed-dependencies
  "Every dependency `clojure -M:deploy` may resolve, by coordinate and version.

  This is the exact set `doc/release-dependency-review.md` records a disposition
  for: Maven's own deploy code path and the HTTP transport it publishes through.
  An addition nothing has reviewed fails the check below, as does a stale entry
  or a version change, so the list cannot describe a graph that has moved on."
  '{commons-codec/commons-codec "1.17.1"
    org.apache.httpcomponents/httpclient "4.5.14"
    org.apache.httpcomponents/httpcore "4.4.16"
    org.apache.maven.resolver/maven-resolver-api "1.9.22"
    org.apache.maven.resolver/maven-resolver-connector-basic "1.9.22"
    org.apache.maven.resolver/maven-resolver-impl "1.9.22"
    org.apache.maven.resolver/maven-resolver-named-locks "1.9.22"
    org.apache.maven.resolver/maven-resolver-spi "1.9.22"
    org.apache.maven.resolver/maven-resolver-supplier "1.9.22"
    org.apache.maven.resolver/maven-resolver-transport-file "1.9.22"
    org.apache.maven.resolver/maven-resolver-transport-http "1.9.22"
    org.apache.maven.resolver/maven-resolver-util "1.9.22"
    org.apache.maven/maven-artifact "3.9.8"
    org.apache.maven/maven-builder-support "3.9.8"
    org.apache.maven/maven-model "3.9.8"
    org.apache.maven/maven-model-builder "3.9.8"
    org.apache.maven/maven-repository-metadata "3.9.8"
    org.apache.maven/maven-resolver-provider "3.9.8"
    org.clojure/clojure "1.12.4"
    org.clojure/core.specs.alpha "0.4.74"
    org.clojure/spec.alpha "0.5.238"
    org.codehaus.plexus/plexus-interpolation "1.27"
    org.codehaus.plexus/plexus-utils "3.6.2"
    org.slf4j/jcl-over-slf4j "1.7.36"
    org.slf4j/slf4j-api "1.7.36"})

(def ^:private forbidden-fragments
  "Artifact-name fragments the old publisher's graph carried and this one must
  not, each named so a failure says which branch came back."
  ["s3" "aws" "logback" "ion-java" "jackson" "joda-time" "commons-logging"])

(def ^:private deploy-classpath
  "The credential-bearing classpath, resolved once, or nil with no `clojure` CLI.

  A delay rather than a top-level value: resolving dependencies is I/O, and a
  suite run that skips these checks must not pay for it."
  (delay
    (when (clojure-cli?)
      (let [{:keys [exit out err]} (run-clojure "." {} ["-Spath" "-M:deploy"])]
        (when-not (zero? exit)
          (throw (ex-info (str "clojure -Spath -M:deploy failed: " err) {:exit exit})))
        (str/split (str/trim out) (re-pattern java.io.File/pathSeparator))))))

(def ^:private deploy-tree
  "The resolved coordinates of the deploy classpath, from `clojure -Stree`.

  The classpath names jar files; the tree names the coordinates that put them
  there, which is what the review records and what the allow-list holds."
  (delay
    (when (clojure-cli?)
      (let [{:keys [exit out err]} (run-clojure "." {} ["-Stree" "-M:deploy"])]
        (when-not (zero? exit)
          (throw (ex-info (str "clojure -Stree -M:deploy failed: " err) {:exit exit})))
        out))))

(defn- tree-dependencies
  "The coordinate-to-version map `clojure -Stree` output `s` says was used.

  A line is `<coordinate> <version>` at the top level and `. <coordinate>
  <version>` below it; `X` marks a candidate the resolver rejected, which is on
  no classpath and reviewed nowhere."
  [s]
  (into {}
        (keep (fn [line]
                (let [[marker coordinate version] (str/split (str/trim line) #"\s+")]
                  (cond
                    (= "X" marker) nil
                    (= "." marker) [(symbol coordinate) version]
                    :else [(symbol marker) coordinate]))))
        (remove str/blank? (str/split-lines s))))

(defn- jar-names
  "The file name of every jar on `classpath`."
  [classpath]
  (into #{} (comp (filter #(str/ends-with? % ".jar")) (map #(.getName (io/file %))))
        classpath))

(deftest release-classpath-has-no-unused-transports-test
  (if-let [classpath @deploy-classpath]
    (testing "no S3, AWS, logging, or serialization branch reaches the token"
      (doseq [fragment forbidden-fragments]
        (is (empty? (filter #(str/includes? (str/lower-case %) fragment)
                            (jar-names classpath)))
            (str "the deploy classpath carries an artifact matching " (pr-str fragment)
                 "; Clojars is a plain Maven HTTP repository and needs none of it"))))
    (skipped "no `clojure` CLI on the PATH to resolve the deploy classpath")))

(deftest release-classpath-matches-the-reviewed-set-test
  (if-let [tree @deploy-tree]
    (let [resolved (tree-dependencies tree)
          resolved-coordinates (set (keys resolved))
          reviewed-coordinates (set (keys reviewed-dependencies))
          classpath @deploy-classpath]
      (testing "every resolved coordinate has a reviewed disposition"
        (is (empty? (set/difference resolved-coordinates reviewed-coordinates))
            (str "unreviewed additions to the credential-bearing classpath: "
                 (pr-str (sort (set/difference resolved-coordinates
                                               reviewed-coordinates))))))
      (testing "the allow-list has nothing left in it that is no longer resolved"
        (is (empty? (set/difference reviewed-coordinates resolved-coordinates))
            (str "reviewed entries that are no longer on the classpath: "
                 (pr-str (sort (set/difference reviewed-coordinates
                                               resolved-coordinates))))))
      (testing "every reviewed coordinate resolves its reviewed exact version"
        (is (= reviewed-dependencies resolved)
            (str "reviewed dependency versions differ from the resolved graph: "
                 (pr-str resolved))))
      (testing "one jar per reviewed coordinate, and the publisher's own path"
        (is (= (count reviewed-dependencies) (count (jar-names classpath))))
        (is (some #{"build"} classpath))))
    (skipped "no `clojure` CLI on the PATH to resolve the deploy classpath")))

(deftest release-classpath-uses-fixed-plexus-utils-test
  (if-let [classpath @deploy-classpath]
    (let [jars (jar-names classpath)]
      (testing "the reviewed fixed Plexus Utils replaces the advisory match"
        (is (contains? jars "plexus-utils-3.6.2.jar"))
        (is (not (contains? jars "plexus-utils-3.5.1.jar")))))
    (skipped "no `clojure` CLI on the PATH to resolve the deploy classpath")))

(deftest deploy-alias-excludes-the-build-tooling-test
  (if-let [classpath @deploy-classpath]
    (testing "the credential-bearing JVM cannot load the build tooling or the library"
      (is (empty? (filter #(str/includes? % "tools.build") classpath))
          "tools.build is on the classpath that holds the Clojars token")
      (is (empty? (filter #(#{"src" "." "test"} %) classpath))
          "the deploy alias replaces :paths, so only \"build\" may appear")
      (is (= ["build"] (remove #(str/ends-with? % ".jar") classpath))))
    (skipped "no `clojure` CLI on the PATH to resolve the deploy classpath")))

;;;; A fixture release, receipted exactly as `release` leaves one

(def ^:private pom-entry
  (str "META-INF/maven/" (namespace release/lib) "/" (name release/lib) "/pom.xml"))

(def ^:private properties-entry
  (str "META-INF/maven/" (namespace release/lib) "/" (name release/lib) "/pom.properties"))

(defn- temp-dir!
  "A fresh temporary directory."
  []
  (io/file (str (Files/createTempDirectory "secrets-publish-test"
                                           (make-array FileAttribute 0)))))

(defn- delete-tree! [file]
  (doseq [child (reverse (file-seq (io/file (str file))))]
    (.delete child)))

(defn- git!
  "Runs `git` in `dir`, returning trimmed stdout and throwing on failure."
  [dir & args]
  (let [{:keys [exit out err]} (apply sh/sh "git" (concat args [:dir (io/file dir)]))]
    (when-not (zero? exit)
      (throw (ex-info (str "git " (str/join " " args) " failed: " err) {:args (vec args)})))
    (str/trim out)))

(defn- copy-tree!
  "Copies every file under `source` into `target`, keeping the layout."
  [source target]
  (let [root (.toPath (io/file source))]
    (doseq [file (file-seq (io/file source))
            :when (.isFile file)]
      (let [destination (io/file target (str (.relativize root (.toPath file))))]
        (io/make-parents destination)
        (io/copy file destination)))))

(def ^:private fixture-pom
  "The pom of a release the guards would accept: the version everywhere, and the
  `<scm><tag>` it claims to have been built from."
  (str "<project><groupId>" (namespace release/lib) "</groupId>"
       "<artifactId>" (name release/lib) "</artifactId>\n  "
       "<version>" release/version "</version>\n  "
       "<scm><tag>" (release/release-tag) "</tag>"
       "<url>https://github.com/kirahowe/secrets</url></scm>\n  "
       "</project>\n"))

(defn- fixture-jar!
  "Writes the fixture artifact under `dir`, returning its path.

  Constructed rather than built: this test is about what the publisher uploads,
  not about tools.build, and it must not depend on the developer's git state."
  [dir]
  (let [file (io/file dir "target" (str (name release/lib) "-" release/version ".jar"))]
    (io/make-parents file)
    (with-open [out (ZipOutputStream. (io/output-stream file))]
      (doseq [[entry text] {pom-entry fixture-pom
                            properties-entry (str "version=" release/version "\n")
                            "com/kirahowe/secrets.clj" "(ns com.kirahowe.secrets)\n"}]
        (.putNextEntry out (ZipEntry. ^String entry))
        (.write out (.getBytes ^String text "UTF-8"))
        (.closeEntry out)))
    file))

(defn- fixture-release!
  "A disposable repository holding a receipted release the publisher will accept.

  It carries the project's own `deps.edn` and `build` tree, so the subprocess
  runs the committed `:deploy` alias rather than a copy of it, and one commit
  tagged for the authoritative version, because the publisher re-verifies the
  receipt against the repository before it uploads anything."
  [dir]
  (copy-tree! "build" (io/file dir "build"))
  (io/copy (io/file "deps.edn") (io/file dir "deps.edn"))
  (git! dir "init" "-q" "-b" "main")
  (doseq [[k v] {"user.email" "publish-test@example.invalid" "user.name" "Publish Test"
                 "commit.gpgsign" "false" "tag.gpgsign" "false"}]
    (git! dir "config" k v))
  (git! dir "add" "-A")
  (git! dir "commit" "-qm" "Release commit")
  (git! dir "tag" (release/release-tag))
  (let [jar (fixture-jar! dir)
        pom (doto (io/file dir "target" "classes" pom-entry)
              io/make-parents
              (spit fixture-pom))]
    (release/write-receipt! (release/receipt (assoc (release/exact-tag! {:dir dir})
                                                    :dir dir :jar jar :pom pom))
                            {:dir dir})
    {:jar jar :pom pom}))

;;;; A local repository that records what it is sent

(defn- record!
  "Records `exchange` in `requests` and answers it.

  A `PUT` is accepted, and a `GET` of the repository metadata answers 404 —
  which is what a repository with no such artifact yet says, and what makes the
  deploy write fresh metadata instead of updating something."
  [requests ^HttpExchange exchange]
  (let [body (with-open [in (.getRequestBody exchange)
                         out (ByteArrayOutputStream.)]
               (io/copy in out)
               (.toByteArray out))
        method (.getRequestMethod exchange)]
    (swap! requests conj {:method method
                          :path (.getPath (.getRequestURI exchange))
                          :authorization (.getFirst (.getRequestHeaders exchange)
                                                    "Authorization")
                          :body body})
    (.sendResponseHeaders exchange (if (= "PUT" method) 201 404) -1)
    (.close exchange)))

(defn- recorder!
  "An HTTP server on a free loopback port recording every request into `requests`."
  [requests]
  (doto (HttpServer/create (InetSocketAddress. "127.0.0.1" 0) 0)
    (.createContext "/" (reify HttpHandler
                          (handle [_ exchange] (record! requests exchange))))
    (.start)))

(def ^:private fixture-username "fixture-user")

(def ^:private fixture-password "not-a-real-token-a41f9c")

(defn- deploy-fixture!
  "Calls the lower-level deploy seam in `dir` against `url`.

  The fixture target and credentials are values in this test-only expression;
  neither can participate in the production entry point's target selection."
  [dir url]
  (let [credentials {:username fixture-username :password fixture-password}
        form (str "(do (require '[com.kirahowe.secrets.publish :as publish]"
                  " '[com.kirahowe.secrets.release :as release])"
                  " (let [receipt (release/verified-artifact!)]"
                  " (publish/deploy! receipt " (pr-str url) " " (pr-str credentials) ")"
                  " (println \"Uploaded receipted fixture\" (:sha256 receipt))))")
        java (str (io/file (System/getProperty "java.home") "bin" "java"))
        classpath (str/join java.io.File/pathSeparator @deploy-classpath)]
    (run-process dir {} [java "-cp" classpath "clojure.main" "-e" form])))

(defn- invoke-publisher!
  "Runs the production entry point in `dir`, with fixed fixture credentials."
  [dir env args]
  (run-clojure dir
               (merge {"CLOJARS_USERNAME" fixture-username
                       "CLOJARS_PASSWORD" fixture-password
                       "SECRETS_DEPLOY_REPOSITORY_URL" ""}
                      env)
               (into ["-M:deploy"] args)))

(defn- expected-uploads
  "Every path a complete deploy of the fixture writes under `prefix`.

  The jar, the pom served beside it, a SHA-1 and an MD5 for each, and the
  coordinate's `maven-metadata.xml` with its own two checksums: a Maven
  repository, which is all Clojars is."
  [prefix]
  (let [dir (str prefix "/" (str/replace (namespace release/lib) "." "/")
                 "/" (name release/lib))
        artifact (str dir "/" release/version "/" (name release/lib) "-" release/version)]
    (set (for [base [(str artifact ".jar") (str artifact ".pom")
                     (str dir "/maven-metadata.xml")]
               suffix ["" ".sha1" ".md5"]]
           (str base suffix)))))

(deftest lower-level-deploy-uploads-the-receipted-bytes-test
  (if-not (clojure-cli?)
    (skipped "no `clojure` CLI on the PATH to run the publisher")
    (let [dir (temp-dir!)
          requests (atom [])
          server (recorder! requests)]
      (try
        (let [{:keys [jar]} (fixture-release! dir)
              url (str "http://127.0.0.1:" (.getPort (.getAddress server)) "/repository")
              {:keys [exit out err]} (deploy-fixture! dir url)
              recorded @requests]
          (testing "the lower-level seam uploads to the fixture repository"
            (is (zero? exit) (str "fixture deploy failed: " err)))
          (testing "exactly the artifacts, checksums, and metadata of one deploy"
            (is (= (expected-uploads "/repository")
                   (set (map :path (filter #(= "PUT" (:method %)) recorded))))))
          (testing "every request authenticated, none anonymous"
            (is (every? :authorization recorded))
            (is (seq recorded)))
          (testing "the bytes uploaded are the bytes the receipt named"
            (let [uploaded (some #(when (str/ends-with? (:path %) ".jar") (:body %)) recorded)]
              (is (Arrays/equals ^bytes (Files/readAllBytes (.toPath (io/file jar)))
                                 ^bytes uploaded))))
          (testing "fixture credentials appear in no output"
            (is (not (str/includes? (str out err) fixture-password)))
            (is (not (str/includes? (str out err) fixture-username)))
            (is (str/includes? out "Uploaded receipted fixture"))
            (is (str/includes? out (:sha256 (release/read-receipt! {:dir dir}))))))
        (finally
          (.stop server 0)
          (delete-tree! dir))))))

(deftest production-repository-target-is-fixed-test
  (if-not (clojure-cli?)
    (skipped "no `clojure` CLI on the PATH to run the publisher")
    (let [dir (temp-dir!)
          requests (atom [])
          server (recorder! requests)]
      (try
        (fixture-release! dir)
        (let [url (str "http://127.0.0.1:" (.getPort (.getAddress server)) "/repository")
              invocations [["the command line" (invoke-publisher! dir {} [url])]
                           ["SECRETS_DEPLOY_REPOSITORY_URL"
                            (invoke-publisher! dir {"SECRETS_DEPLOY_REPOSITORY_URL" url} [])]]]
          (doseq [[source {:keys [exit out err]}] invocations]
            (testing (str source " cannot select a recorder")
              (is (= 1 exit))
              (is (str/includes? err (str "Repository target from " source " is rejected")))
              (is (str/includes? err "host=\"127.0.0.1\""))
              (is (not (str/includes? (str out err) "/repository")))
              (is (not (str/includes? (str out err) fixture-password)))
              (is (not (str/includes? (str out err) fixture-username)))))
          (testing "target rejection happens before any request"
            (is (empty? @requests))))
        (finally
          (.stop server 0)
          (delete-tree! dir))))))

(deftest production-rejects-disallowed-repository-targets-test
  (if-not (clojure-cli?)
    (skipped "no `clojure` CLI on the PATH to run the publisher")
    (let [dir (temp-dir!)
          targets [["an explicit fixed origin" "https://repo.clojars.org"]
                   ["plaintext HTTP" "http://repo.clojars.org"]
                   ["another host" "https://example.invalid"]
                   ["userinfo" (str "https://" fixture-username ":" fixture-password
                                    "@repo.clojars.org")]
                   ["a changed port" "https://repo.clojars.org:8443"]
                   ["a changed path" "https://repo.clojars.org/repository"]
                   ["a query" (str "https://repo.clojars.org?token=" fixture-password)]
                   ["a fragment" (str "https://repo.clojars.org#" fixture-password)]
                   ["a lookalike" "https://repo.clojars.org.example"]]]
      (try
        (fixture-release! dir)
        (doseq [[kind target] targets
                :let [{:keys [exit out err]} (invoke-publisher! dir {} [target])]]
          (testing (str kind " is not a production target input")
            (is (= 1 exit))
            (is (str/includes? err "Repository target from the command line is rejected"))
            (is (str/includes? err "Rejected target:"))
            (is (not (str/includes? (str out err) fixture-password)))
            (is (not (str/includes? (str out err) fixture-username)))))
        (finally
          (delete-tree! dir))))))

(deftest publish-refuses-before-it-uploads-anything-test
  (if-not (clojure-cli?)
    (skipped "no `clojure` CLI on the PATH to run the publisher")
    (let [dir (temp-dir!)
          requests (atom [])
          server (recorder! requests)]
      (try
        (let [{:keys [jar]} (fixture-release! dir)
              url (str "http://127.0.0.1:" (.getPort (.getAddress server)) "/repository")
              blank (invoke-publisher! dir {"CLOJARS_PASSWORD" ""} [])]
          (testing "a set-but-blank credential is a broken release, not an anonymous upload"
            (is (= 1 (:exit blank)))
            (is (str/includes? (:err blank) "CLOJARS_PASSWORD is set but empty")))
          (testing "a mutated artifact is refused after inspection"
            (let [content (Files/readAllBytes (.toPath (io/file jar)))]
              (aset-byte content 0 (unchecked-byte (bit-xor (aget content 0) 1)))
              (io/copy content (io/file jar)))
            (let [{:keys [exit err]} (deploy-fixture! dir url)]
              (is (= 1 exit))
              (is (str/includes? err "changed after it was inspected"))))
          (testing "no receipt means nothing to publish"
            (.delete (release/receipt-path {:dir dir}))
            (let [{:keys [exit err]} (deploy-fixture! dir url)]
              (is (= 1 exit))
              (is (str/includes? err "No release receipt at"))))
          (testing "not one request reached the repository"
            (is (empty? @requests))))
        (finally
          (.stop server 0)
          (delete-tree! dir))))))
