(ns com.kirahowe.secrets.publish
  "Uploads the receipted release artifact to a Maven repository, and nothing else.

  This is the only step that ever sees the Clojars credentials, so it runs on a
  classpath of its own: `clojure -M:deploy` *replaces* `:deps` and `:paths`
  rather than adding to them, leaving the credential-bearing JVM holding this
  namespace, the release guards beside it, and Maven's own deploy code — no
  `tools.build`, no `src`, no test dependencies. Clojars is a plain Maven HTTP
  repository, so the upload runs through `maven-resolver` directly instead of
  through a wagon-based publisher whose resolved graph carries an S3 transport
  this project can never reach; see `doc/release-dependency-review.md`.

  Everything the release guards checked is re-checked here, on this side of the
  credential boundary, before a single byte is uploaded. Nothing builds: an
  artifact that no longer matches its receipt fails rather than being published.

      clojure -T:build release   # writes target/release.edn
      CLOJARS_USERNAME=… CLOJARS_PASSWORD=… clojure -M:deploy

  The production entry point has one fixed target: the exact HTTPS Clojars
  repository [[clojars-url]]. It rejects every argument and the former
  repository environment override before reading credentials or inspecting an
  artifact. Tests exercise other repositories only through [[deploy!]], below
  production target selection.

  Unlike `com.kirahowe.secrets.release`, this namespace needs maven-resolver on
  the classpath: it is JVM-only and does not load under babashka."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [com.kirahowe.secrets.release :as release])
  (:import [java.net URI URISyntaxException]
           [org.apache.maven.repository.internal MavenRepositorySystemUtils]
           [org.eclipse.aether RepositorySystem]
           [org.eclipse.aether.artifact Artifact DefaultArtifact]
           [org.eclipse.aether.deployment DeployRequest]
           [org.eclipse.aether.repository LocalRepository RemoteRepository$Builder]
           [org.eclipse.aether.supplier RepositorySystemSupplier]
           [org.eclipse.aether.util.artifact SubArtifact]
           [org.eclipse.aether.util.repository AuthenticationBuilder]))

;;;; The publication target

(def clojars-url
  "The repository a release is actually published to."
  "https://repo.clojars.org")

(def ^:private repository-url-env
  "The retired repository override variable, rejected if it is nonblank."
  "SECRETS_DEPLOY_REPOSITORY_URL")

(defn- target-description
  "A secret-safe description of repository `target`.

  It identifies the origin and which URI components are present without
  echoing userinfo, paths, queries, fragments, or malformed input."
  [target]
  (if (str/blank? target)
    "<blank>"
    (try
      (let [uri (URI. target)]
        (str "scheme=" (pr-str (or (.getScheme uri) "<none>"))
             ", host=" (pr-str (or (.getHost uri) "<none>"))
             ", port=" (if (neg? (.getPort uri)) "<default>" (.getPort uri))
             ", userinfo=" (if (.getRawUserInfo uri) "<present>" "<absent>")
             ", path=" (if (seq (.getRawPath uri)) "<present>" "<absent>")
             ", query=" (if (.getRawQuery uri) "<present>" "<absent>")
             ", fragment=" (if (.getRawFragment uri) "<present>" "<absent>")))
      (catch URISyntaxException _
        (str "<malformed target, " (count target) " characters>")))))

(defn- rejected-repository!
  "Rejects `target` selected through `source` without retaining its raw value."
  [source target]
  (throw (ex-info
          (str "Repository target from " source " is rejected; publication is fixed at "
               clojars-url ". Rejected target: " (target-description target) ".")
          {:reason ::repository-override :source source})))

(defn- production-repository-url!
  "Returns [[clojars-url]], rejecting every former target-selection input."
  [args]
  (when (seq args)
    (rejected-repository! "the command line" (first args)))
  (when-let [target (not-empty (str/trim (or (System/getenv repository-url-env) "")))]
    (rejected-repository! repository-url-env target))
  clojars-url)

;;;; Credentials

(def ^:private credential-help
  "What each credential variable must contain, for the set-but-blank error."
  {"CLOJARS_USERNAME" "the Clojars username the deploy token belongs to"
   "CLOJARS_PASSWORD" "a Clojars deploy token scoped to this coordinate"})

(defn- credential
  "The value of credential variable `k`, failing when it is unset or blank.

  Takes the value rather than reading it, so the rule is testable without
  setting process environment, and names the variable without ever echoing what
  it held. A CI runner expands a missing or misnamed secret to the empty string
  (`CLOJARS_PASSWORD: ${{ secrets.CLOJARS_TOKEN }}` with no such secret), so
  blank means a broken release environment rather than an absent one, and the
  alternative is an upload attempt that presents an empty token to a repository
  and fails far downstream as an authentication error nobody attributes to a
  misnamed secret."
  [k v]
  (when (str/blank? v)
    (throw (ex-info (str k " is " (if (nil? v) "not set" "set but empty")
                         ". Set it to " (credential-help k)
                         "; an upload needs both credentials, and refuses to try without them.")
                    {:reason ::missing-credential :env k})))
  v)

(defn- credentials-from-env
  "`credential` applied to the live environment, before anything else happens."
  []
  {:username (credential "CLOJARS_USERNAME" (System/getenv "CLOJARS_USERNAME"))
   :password (credential "CLOJARS_PASSWORD" (System/getenv "CLOJARS_PASSWORD"))})

;;;; The upload

(def ^:private local-repository-dir
  "Where the resolver's session keeps the local repository a deploy requires.

  Under `target/` rather than at its `~/.m2` default: the credential-bearing
  step has no business reading or writing the developer's local repository, and
  nothing it touches should outlive the build directory the release produced."
  "target/deploy-repository")

(defn- session
  "A repository session for `system` whose local repository is under `target/`."
  [^RepositorySystem system]
  (let [session (MavenRepositorySystemUtils/newSession)
        local (LocalRepository. (io/file local-repository-dir))]
    (.setLocalRepositoryManager session (.newLocalRepositoryManager system session local))))

(defn- remote-repository
  "The deploy target at `url`, authenticated with `:username` and `:password`."
  [url {:keys [username password]}]
  (-> (RemoteRepository$Builder. "release" "default" url)
      (.setAuthentication (-> (AuthenticationBuilder.)
                              (.addUsername ^String username)
                              (.addPassword ^String password)
                              (.build)))
      (.build)))

(defn deploy!
  "Uploads `receipt`'s `:jar` and `:pom` to `url`, authenticated by `credentials`.

  The coordinate and version come from [[release/lib]] and [[release/version]],
  the one authoritative source, rather than being read back out of the pom that
  is being uploaded. Maven's own deploy code writes the artifacts, their
  checksums, and the repository metadata; returns `url`."
  [{:keys [jar pom]} url credentials]
  (let [system (.get (RepositorySystemSupplier.))
        ^Artifact artifact (-> (DefaultArtifact. (namespace release/lib) (name release/lib)
                                                 "" "jar" release/version)
                               (.setFile (io/file jar)))
        request (-> (DeployRequest.)
                    (.setRepository (remote-repository url credentials))
                    (.addArtifact artifact)
                    (.addArtifact (.setFile (SubArtifact. artifact "" "pom") (io/file pom))))]
    (.deploy system (session system) request)
    url))

;;;; The entry point

(defn- report!
  "Prints what was published. Never prints a credential."
  [{:keys [jar tag sha256]}]
  (println "Published" (str release/lib) release/version "from" tag)
  (println "  jar       " jar)
  (println "  sha-256   " sha256)
  (println "  repository" clojars-url))

(defn- failed!
  "Reports `e` on stderr and exits non-zero, so a failed upload cannot read as a
  success to whatever ran this."
  [e]
  (binding [*out* *err*]
    (println "Release publication failed:" (ex-message e)))
  (shutdown-agents)
  (System/exit 1))

(defn -main
  "Publishes the receipted release artifact; see the namespace docstring."
  [& args]
  (try
    (let [url (production-repository-url! args)
          credentials (credentials-from-env)
          receipt (release/verified-artifact!)]
      (deploy! receipt url credentials)
      (report! receipt)
      (shutdown-agents)
      (System/exit 0))
    (catch Exception e
      (failed! e))))
