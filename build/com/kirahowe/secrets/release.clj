(ns com.kirahowe.secrets.release
  "Guards that make publishing a release accountable.

  A release is built once, from a clean working tree whose `HEAD` is exactly the
  tag naming the declared [[version]], out of a snapshot of that commit rather
  than live files that can change afterwards — and the bytes that were inspected
  are the bytes that get uploaded. Every check returns data and throws `ex-info`
  naming what it expected and what it found; nothing here warns and continues.

  This namespace lives under `build/` rather than `src/`, so it never ships in
  the library jar. It uses only `clojure.core`, `clojure.java.shell`, and the
  JDK, so it loads and runs identically under JVM Clojure and babashka."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.java.shell :as sh]
            [clojure.string :as str])
  (:import [java.io ByteArrayOutputStream]
           [java.security MessageDigest]
           [java.util Arrays]
           [java.util.zip ZipFile]))

;;;; The authoritative coordinates

(def coordinate-file
  "Where the library's coordinates are written, relative to the repository, and
  the only place they are: the release version, the Maven coordinate, and the
  git tag and commit the initializer scaffolds. It sits under `src/` so the
  initializer ships with the same facts these guards check."
  "src/com/kirahowe/secrets/coordinate.edn")

(defn read-coordinates
  "The coordinates written in [[coordinate-file]] under `dir`, failing when the
  file is missing rather than falling back to values nobody wrote."
  [dir]
  (let [file (io/file dir coordinate-file)]
    (when-not (.isFile file)
      (throw (ex-info (str "No coordinate file at " file
                           "; the library's version and coordinates are written there.")
                      {:reason ::missing-coordinates :file (str file)})))
    (edn/read-string (slurp file))))

(def ^:private coordinates (read-coordinates "."))

(def ^:private version-pattern
  #"\d+\.\d+\.\d+(-[A-Za-z0-9.]+)?")

(defn- checked-version
  "Returns `s` when it is a well-formed release version, else throws.
  A typo must not become a tag name."
  [s]
  (when-not (and (string? s) (re-matches version-pattern s))
    (throw (ex-info (str "Malformed release version: expected " version-pattern
                         ", found " (pr-str s))
                    {:reason ::malformed-version :version s})))
  s)

(def lib
  "The published Maven coordinate, from [[coordinate-file]].

  Its group and artifact also name the `META-INF/maven` descriptors embedded in
  the jar, so the deployed coordinate and the artifact's own metadata cannot
  drift apart."
  (:lib coordinates))

(def version
  "The authoritative release version, from [[coordinate-file]].

  Every other appearance — the git tag, the jar file name, the pom, the embedded
  `pom.properties`, the CHANGELOG heading — is checked against this string
  rather than maintained beside it."
  (checked-version (:version coordinates)))

(def git-coordinate
  "The git coordinate the initializer scaffolds, from [[coordinate-file]]: the
  last released `:tag`, the `:sha` it names, and the `:lib` it is declared
  under. See [[git-coordinate!]] for what has to hold between them."
  (:git coordinates))

(defn release-tag
  "The git tag that must name the release commit for a version."
  ([] (release-tag version))
  ([version] (str "v" (checked-version version))))

(defn- config
  "Fills in the defaults every guard shares: the repository at `.`, the
  authoritative [[version]], and the scaffolded [[git-coordinate]]."
  [opts]
  (merge {:dir "." :version version :git git-coordinate} opts))

;;;; Repository state

(defn- git
  "Runs `git` with the argv `args` in the repository at `dir`.

  Returns `clojure.java.shell/sh`'s result map, so a caller can read a non-zero
  exit as an answer rather than a failure. No shell is involved: `args` is an
  argv vector, never a command string."
  [dir args]
  (apply sh/sh "git" (concat args [:dir (io/file dir)])))

(defn- git!
  "Runs `git` in `dir` and returns its trimmed stdout, throwing when it fails."
  [dir args]
  (let [{:keys [exit out err]} (git dir args)]
    (when-not (zero? exit)
      (throw (ex-info (str "git " (str/join " " args) " failed in " dir ": " (str/trim err))
                      {:reason ::git-failed :dir (str dir) :args (vec args) :exit exit})))
    (str/trim out)))

(defn clean-tree!
  "Fails unless the working tree at `:dir` is clean; returns `:dir`.

  Untracked files count as dirty, because an untracked file is exactly how
  content nobody reviewed reaches a build."
  ([] (clean-tree! nil))
  ([opts]
   (let [{:keys [dir]} (config opts)
         status (git! dir ["status" "--porcelain"])]
     (when (seq status)
       (throw (ex-info (str "Release requires a clean working tree, but `git status --porcelain` "
                            "in " dir " reported (untracked files count as dirty):\n" status)
                       {:reason ::dirty-tree :dir (str dir) :status status})))
     dir)))

(defn- resolve-tag
  "The commit that `tag` names in `dir`, or nil when no such tag exists."
  [dir tag]
  (let [{:keys [exit out]} (git dir ["rev-parse" "--verify" (str "refs/tags/" tag "^{commit}")])]
    (when (zero? exit)
      (str/trim out))))

(defn- tagged-commit
  "The commit that `tag` names in `dir`; throws when no such tag exists."
  [dir tag]
  (or (resolve-tag dir tag)
      (throw (ex-info (str "Release tag " tag " does not exist in " dir
                           "; create it on the release commit first.")
                      {:reason ::missing-tag :dir (str dir) :tag tag}))))

(defn exact-tag!
  "Fails unless `HEAD` in `:dir` is exactly the release tag for `:version`.

  Returns `{:tag :commit}`. A descendant of the tag is a failure, not a pass: the
  published bytes must come from the commit the tag advertises, not from whatever
  landed after it."
  ([] (exact-tag! nil))
  ([opts]
   (let [{:keys [dir version]} (config opts)
         tag (release-tag version)
         commit (tagged-commit dir tag)
         head (git! dir ["rev-parse" "HEAD"])]
     (when-not (= head commit)
       (throw (ex-info (str "HEAD in " dir " is not the release tag " tag ": expected commit "
                            commit ", found " head)
                       {:reason ::head-not-tag :dir (str dir) :tag tag
                        :expected commit :found head})))
     {:tag tag :commit commit})))

(defn git-coordinate!
  "Fails unless the git coordinate the initializer scaffolds resolves in `:dir`:
  its `:tag` must exist, and the commit that tag names must be its `:sha`.
  Returns the coordinate.

  This is the last *released* tag, not the release tag for `:version`, and it
  lags by design, since a commit cannot contain its own hash. What has to hold
  is that the two halves agree, so a consumer who takes the initializer's pin
  resolves exactly the tree the tag advertises."
  ([] (git-coordinate! nil))
  ([opts]
   (let [{:keys [dir] pin :git} (config opts)
         {:keys [tag sha]} pin
         commit (resolve-tag dir tag)]
     (when-not commit
       (throw (ex-info (str "The initializer pins git tag " tag ", which does not exist in "
                            dir ".")
                       {:reason ::missing-pinned-tag :dir (str dir) :tag tag})))
     (when-not (= sha commit)
       (throw (ex-info (str "The initializer pins " tag " at " sha ", but that tag names "
                            commit " in " dir ".")
                       {:reason ::pinned-sha-mismatch :dir (str dir) :tag tag
                        :expected commit :found sha})))
     pin)))

(defn changelog-entry!
  "Fails unless `CHANGELOG.md` under `:dir` documents `:version`.

  Returns the `## [<version>]` heading line. Cheap, and it catches the common
  mistake of tagging a release before writing its entry."
  ([] (changelog-entry! nil))
  ([opts]
   (let [{:keys [dir version]} (config opts)
         file (io/file dir "CHANGELOG.md")
         heading (str "## [" version "]")
         lines (when (.isFile file) (str/split-lines (slurp file)))]
     (or (some #(when (str/starts-with? % heading) %) lines)
         (throw (ex-info (str "CHANGELOG.md in " dir " has no " heading
                              " heading; document the release before tagging it.")
                         {:reason ::missing-changelog-entry :dir (str dir) :version version
                          :heading heading :changelog-exists? (some? lines)}))))))

;;;; The verified source snapshot

(defn- export-dir
  "Where [[verified-source!]] exports the release tag: `:source-dir` when given,
  otherwise `target/release-source` inside the repository."
  [{:keys [dir source-dir]}]
  (io/file (or source-dir (io/file dir "target" "release-source"))))

(defn- worktree-add!
  "Exports `tag` into `target` as a detached worktree, throwing when git refuses."
  [dir tag target]
  (let [{:keys [exit err]} (git dir ["worktree" "add" "--detach" (str target) tag])]
    (when-not (zero? exit)
      (throw (ex-info (str "Could not export release tag " tag " into " target ": "
                           (str/trim err))
                      {:reason ::export-failed :dir (str dir) :tag tag
                       :source-dir (str target) :exit exit})))
    (str target)))

(defn verified-source!
  "Materializes the tree that `:version`'s release tag names, returning its path.

  The build must consume this immutable snapshot rather than live files, which
  can diverge from the verified commit the moment the guards have passed. Pair
  every call with [[release-source-cleanup!]]."
  ([] (verified-source! nil))
  ([opts]
   (let [{:keys [dir version] :as opts} (config opts)
         target (export-dir opts)]
     ;; A run that died between the export and its cleanup leaves the worktree
     ;; registered in .git/worktrees even after `clean` deleted target/, and
     ;; `worktree add` then refuses a path that no longer exists. Pruning first
     ;; is idempotent, and a prune that fails is not a release failure.
     (git dir ["worktree" "prune"])
     (worktree-add! dir (release-tag version) target))))

(defn release-source-cleanup!
  "Removes the worktree [[verified-source!]] created; safe when there is none.

  Returns the exported path. Cleanup is best-effort by design: a leftover export
  must never turn a successful, verified release into a failure."
  ([] (release-source-cleanup! nil))
  ([opts]
   (let [{:keys [dir] :as opts} (config opts)
         target (export-dir opts)]
     (git dir ["worktree" "remove" "--force" (str target)])
     (git dir ["worktree" "prune"])
     (str target))))

;;;; Artifact identity

(defn sha256-file
  "Lowercase hex SHA-256 of the file at `path`, streamed rather than slurped."
  [path]
  (let [digest (MessageDigest/getInstance "SHA-256")
        buffer (byte-array 65536)]
    (with-open [^java.io.InputStream in (io/input-stream (io/file path))]
      (loop [n (.read in buffer)]
        (when (pos? n)
          (.update digest buffer 0 n)
          (recur (.read in buffer)))))
    (str/join (map #(format "%02x" (bit-and % 0xff)) (.digest digest)))))

(def ^:private pom-version-pattern
  (re-pattern (str "<artifactId>" (name lib) "</artifactId>\\s*<version>([^<]+)</version>")))

(def ^:private scm-tag-pattern
  #"(?s)<scm>.*?<tag>([^<]+)</tag>")

(def ^:private properties-version-pattern
  #"(?m)^version=(.+)$")

(defn- maven-path
  "Path of the descriptor `entry` inside a jar's `META-INF/maven` directory."
  [entry]
  (str "META-INF/maven/" (namespace lib) "/" (name lib) "/" entry))

(defn- entry-bytes
  "Bytes of the jar entry `entry-name` in `file`, or nil when it is absent."
  [file entry-name]
  (with-open [zip (ZipFile. (io/file file))]
    (when-let [entry (.getEntry zip entry-name)]
      (with-open [in (.getInputStream zip entry)
                  out (ByteArrayOutputStream.)]
        (io/copy in out)
        (.toByteArray out)))))

(defn- entry-text
  "Text of the jar entry `entry-name` in `file`, or nil when it is absent."
  [file entry-name]
  (some-> (entry-bytes file entry-name) (String. "UTF-8")))

(defn- first-group
  "The first capture of `re` in `s`, trimmed, or `:absent`."
  [re s]
  (or (some->> s (re-find re) second str/trim) :absent))

(defn- embedded-identity
  "What the jar's own embedded descriptors say it is.

  The version each Maven descriptor records, plus the release tag the pom claims
  it was built from. Anything absent — a missing descriptor, a pom with no
  `<scm><tag>` — reads as `:absent` rather than nil, so nothing missing can be
  mistaken for a match."
  [file]
  (let [xml (entry-text file (maven-path "pom.xml"))]
    {:pom-xml (first-group pom-version-pattern xml)
     :scm-tag (first-group scm-tag-pattern xml)
     :pom-properties (first-group properties-version-pattern
                                  (entry-text file (maven-path "pom.properties")))}))

(defn- artifact-file!
  "The jar at `jar` as a `File`, failing when it is missing or misnamed."
  [jar version]
  (let [file (io/file jar)]
    (when-not (.isFile file)
      (throw (ex-info (str "Release artifact is missing: " file
                           "; the inspected bytes are the only publishable ones.")
                      {:reason ::missing-artifact :jar (str file)})))
    (when-not (str/includes? (.getName file) version)
      (throw (ex-info (str "Release artifact name does not carry version " version ": "
                           (.getName file))
                      {:reason ::artifact-name-mismatch :jar (str file) :version version})))
    file))

(defn verify-artifact-metadata!
  "Fails unless the jar at `jar` identifies itself as the release everywhere.

  Checks the file name, the version in the embedded `pom.xml` and
  `pom.properties`, and the `<scm><tag>` the pom claims it was built from, and
  returns what it found. A jar whose name, metadata, and provenance disagree is
  not the artifact its coordinate promises; a release that records no tag at all
  claims no provenance and is refused here."
  ([jar] (verify-artifact-metadata! jar nil))
  ([jar opts]
   (let [{:keys [version]} (config opts)
         file (artifact-file! jar version)
         expected {:pom-xml version :scm-tag (release-tag version) :pom-properties version}
         found (embedded-identity file)]
     (when-not (= expected found)
       (throw (ex-info (str "Embedded Maven metadata in " file " does not match the release: "
                            "expected " (pr-str expected) ", found " (pr-str found))
                       {:reason ::artifact-metadata-mismatch :jar (str file)
                        :version version :expected expected :found found})))
     found)))

;;;; The release receipt

(defn receipt-path
  "Path of the release receipt for the repository at `:dir`."
  ([] (receipt-path nil))
  ([opts] (io/file (:dir (config opts)) "target" "release.edn")))

(defn receipt
  "The release receipt for `:jar`: the facts a later upload must re-check.

  `:commit` is the verified `HEAD` and `:sha256` the digest of the exact bytes
  that were built, so [[verify-receipt!]] can tell an inspected artifact from one
  replaced after inspection. `:pom` is the descriptor that goes to the repository
  beside the jar, named here so an upload cannot pick up some other file — see
  [[verify-pom!]]."
  [opts]
  (let [{:keys [version tag commit jar pom]} (config opts)]
    {:version version
     :tag tag
     :commit commit
     :jar (str jar)
     :pom (str pom)
     :sha256 (sha256-file jar)}))

(defn write-receipt!
  "Writes `receipt` as EDN to [[receipt-path]] and returns that path."
  ([receipt] (write-receipt! receipt nil))
  ([receipt opts]
   (let [file (receipt-path opts)]
     (io/make-parents file)
     (spit file (str (pr-str receipt) "\n"))
     file)))

(defn read-receipt!
  "Reads the release receipt, failing when there is none to read."
  ([] (read-receipt! nil))
  ([opts]
   (let [file (receipt-path opts)]
     (when-not (.isFile file)
       (throw (ex-info (str "No release receipt at " file
                            "; run `clojure -T:build release` first.")
                       {:reason ::missing-receipt :receipt (str file)})))
     (edn/read-string (slurp file)))))

(defn- verified-digest!
  "Fails unless the receipted artifact is still byte-identical to the inspected
  one; returns its digest."
  [{:keys [jar sha256]} version]
  (let [file (artifact-file! jar version)
        found (sha256-file file)]
    (when-not (= sha256 found)
      (throw (ex-info (str "Release artifact changed after it was inspected: " file
                           " hashes to " found ", the receipt recorded " sha256)
                      {:reason ::digest-mismatch :jar (str file)
                       :expected sha256 :found found})))
    found))

(defn verify-receipt!
  "Fails unless `receipt` still describes this repository and the jar on disk.

  Re-checks `:version`, `:tag`, and `:commit` against the authoritative version
  and the repository's current state, then recomputes the artifact's SHA-256.
  Returns `receipt`."
  ([receipt] (verify-receipt! receipt nil))
  ([receipt opts]
   (let [{:keys [version] :as opts} (config opts)
         expected (assoc (exact-tag! opts) :version version)
         found (select-keys receipt [:version :tag :commit])]
     (when-not (= expected found)
       (throw (ex-info (str "Release receipt does not describe this repository: expected "
                            (pr-str expected) ", found " (pr-str found))
                       {:reason ::receipt-mismatch :expected expected :found found})))
     (verified-digest! receipt version)
     receipt)))

(defn- file-bytes
  "All bytes of `file`."
  [file]
  (with-open [in (io/input-stream (io/file file))
              out (ByteArrayOutputStream.)]
    (io/copy in out)
    (.toByteArray out)))

(defn- embedded-pom
  "Bytes of the pom inside the jar at `jar`, or nil when it carries none."
  [jar]
  (when-not (.isFile (io/file jar))
    (throw (ex-info (str "Release artifact is missing: " jar
                         "; the inspected bytes are the only publishable ones.")
                    {:reason ::missing-artifact :jar (str jar)})))
  (entry-bytes jar (maven-path "pom.xml")))

(defn verify-pom!
  "Fails unless `:pom` is byte-identical to the jar's own embedded descriptor.

  A repository serves the pom beside the jar, and it is the pom that defines the
  coordinate and the dependency list a consumer resolves, so the file an upload
  publishes must be the one inside the artifact that was inspected. Comparing it
  against the jar entry rather than against a second recorded digest means the
  artifact's own SHA-256 already covers both files. Returns the pom path."
  [{:keys [jar pom]}]
  (let [file (when pom (io/file pom))
        expected (when (some-> file .isFile) (file-bytes file))]
    (when-not expected
      (throw (ex-info (str "Receipted pom is missing: " (pr-str pom)
                           "; run `clojure -T:build release` first.")
                      {:reason ::missing-pom :pom (str pom)})))
    (let [embedded (embedded-pom jar)]
      (when-not (Arrays/equals ^bytes expected ^bytes embedded)
        (throw (ex-info (str "Receipted pom " file " is not the pom.xml embedded in " jar
                             (when-not embedded "; the artifact carries no embedded pom"))
                        {:reason ::pom-mismatch :pom (str file) :jar (str jar)
                         :embedded (if embedded :present :absent)}))))
    (str file)))

(defn verified-artifact!
  "The receipted release artifact, re-verified and safe to hand to a publisher.

  Reads the receipt, checks it against the repository and the bytes on disk, and
  re-checks the artifact's embedded metadata and the pom that will be uploaded
  with it; returns the receipt, whose `:jar` and `:pom` are the exact files that
  were inspected. Nothing here builds — an upload that cannot find a receipt
  fails instead of producing fresh, uninspected bytes."
  ([] (verified-artifact! nil))
  ([opts]
   (let [receipt (verify-receipt! (read-receipt! opts) opts)]
     (verify-artifact-metadata! (:jar receipt) opts)
     (verify-pom! receipt)
     receipt)))
