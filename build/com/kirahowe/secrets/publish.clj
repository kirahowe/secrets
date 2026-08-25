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

  A repository URL given as an argument, or in `SECRETS_DEPLOY_REPOSITORY_URL`,
  overrides [[clojars-url]] so the dry-run test can point an upload at a local
  server. Any other repository is reported as an override and never as a
  publication.

  Unlike `com.kirahowe.secrets.release`, this namespace needs maven-resolver on
  the classpath: it is JVM-only and does not load under babashka."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [com.kirahowe.secrets.release :as release])
  (:import [org.apache.maven.repository.internal MavenRepositorySystemUtils]
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

(def repository-url-env
  "The environment variable that overrides [[clojars-url]].

  Exists for the local dry run, which needs a real upload against a repository
  that is not Clojars. An overridden upload is reported as an override, so a
  fixture run cannot be read as a publication."
  "SECRETS_DEPLOY_REPOSITORY_URL")

(defn repository-url
  "The repository to upload to: `arg`, else [[repository-url-env]], else Clojars."
  [arg]
  (or (not-empty (str/trim (or arg "")))
      (not-empty (str/trim (or (System/getenv repository-url-env) "")))
      clojars-url))

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
  "Prints what was uploaded and where. Never prints a credential."
  [{:keys [jar tag sha256]} url]
  (let [clojars? (= url clojars-url)]
    (when-not clojars?
      (println "*** OVERRIDE: the repository was overridden by an argument or"
               (str repository-url-env ",") "so this is NOT a publication of"
               (str release/lib) "***"))
    (println (if clojars? "Published" "Uploaded") (str release/lib) release/version "from" tag)
    (println "  jar       " jar)
    (println "  sha-256   " sha256)
    (println "  repository" url)))

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
    (let [credentials (credentials-from-env)
          url (repository-url (first args))
          receipt (release/verified-artifact!)]
      (report! receipt (deploy! receipt url credentials))
      (shutdown-agents)
      (System/exit 0))
    (catch Exception e
      (failed! e))))
