(ns com.kirahowe.secrets.init
  "Standalone, one-shot project bootstrapper for `bb secrets`."
  (:require [babashka.cli :as bbcli]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.java.shell :as sh]
            [clojure.pprint :as pprint]
            [clojure.string :as str]
            [com.kirahowe.secrets.cli :as cli]
            [com.kirahowe.secrets.safe-edn :as safe-edn]
            [rewrite-clj.node :as node]
            [rewrite-clj.zip :as z])
  (:import [java.nio ByteBuffer]
           [java.nio.charset StandardCharsets]
           [java.nio.file FileSystems Files LinkOption OpenOption Path
            StandardCopyOption StandardOpenOption]
           [java.nio.file.attribute FileAttribute PosixFilePermissions]))

;;;; Configuration

(def ^:private coordinate-resource
  "The library's coordinates, shipped beside this namespace and shared with the
  release guards, so what the initializer scaffolds is what a release checks."
  "com/kirahowe/secrets/coordinate.edn")

(defn- coordinate-url
  "Where [[coordinate-resource]] was loaded from, which also says where the
  running library is: a `file:` URL inside a source checkout, or a `jar:` URL
  inside a Maven artifact."
  []
  (or (io/resource coordinate-resource)
      (throw (ex-info (str "The initializer cannot find " coordinate-resource
                           " on the classpath; the library's source tree is incomplete.")
                      {:resource coordinate-resource}))))

(def ^:private coordinates (edn/read-string (slurp (coordinate-url))))

(def ^:private known-coordinates
  "Either name a project may already declare this library under."
  #{(:lib coordinates) (:git-lib coordinates)})

(defn- git
  "Runs `git` with the argv `args` in `dir`, returning `clojure.java.shell/sh`'s
  result map. A `git` that cannot be started answers like one that failed, so
  the caller sees one shape."
  [dir & args]
  (try
    (apply sh/sh "git" (concat args [:dir dir]))
    (catch java.io.IOException e
      {:exit 127 :out "" :err (ex-message e)})))

(defn- git!
  "Runs `git` through the runner `run` and returns its trimmed stdout, throwing
  when it fails."
  [run dir & args]
  (let [{:keys [exit out err]} (apply run dir args)]
    (when-not (zero? exit)
      (throw (ex-info (str "The initializer pins the commit of the checkout it runs from, but "
                           "`git " (str/join " " args) "` failed in " dir ": " (str/trim err)
                           ". Run it from a git clone of the library, or add the dependency "
                           "by hand.")
                      {:dir (str dir) :args (vec args) :exit exit})))
    (str/trim out)))

(defn library-dependency
  "The dependency that resolves to the library that is running, as the single
  `{lib coordinate}` entry a project's `:deps` needs, given the `url` its
  coordinate resource was loaded from.

  A `file:` URL is a source checkout, and the coordinate is that checkout's
  `HEAD`: `{:git/tag \"v<version>\" :git/sha <commit>}` when the release tag
  names it, and `{:git/sha <commit>}` otherwise. tools.deps wants the commit
  beside a tag, and no commit can record its own hash, so asking git is how the
  initializer writes the version that is running rather than the one before it.
  A checkout under `~/.gitlibs` is a git worktree and answers the same way. Any
  other URL is the jar of a Maven artifact, and the version the resource
  declares is the version that jar was built from.

  `run` executes a git argv in a directory and returns `clojure.java.shell/sh`'s
  map. It is a parameter so each shape can be tested without a repository."
  [^java.net.URL url {:keys [lib git-lib version]} run]
  (if (= "file" (.getProtocol url))
    (let [dir (.getParentFile (io/file url))
          commit (git! run dir "rev-parse" "HEAD")
          tags (set (str/split-lines (git! run dir "tag" "--points-at" "HEAD")))
          tag (str "v" version)]
      {git-lib (if (contains? tags tag)
                 {:git/tag tag :git/sha commit}
                 {:git/sha commit})})
    {lib {:mvn/version version}}))

(def ^:private default-dependency
  "What a project that declares neither name gets: the library that is running,
  located once per run and only when a plan needs it."
  (delay (library-dependency (coordinate-url) coordinates git)))

(def ^:private init-spec
  [[:app {:coerce :string :desc "Application name"}]
   [:env {:coerce :string :default "dev" :desc "Environment name"}]
   [:layout {:coerce keyword
             :default :tracked
             :validate #{:tracked :disposable}
             :desc "Artifact layout: tracked or disposable"}]
   [:team {:coerce :boolean :desc "Create a public recipients file"}]
   [:keygen {:coerce :boolean :desc "Generate an identity after applying"}]
   [:apply {:coerce :boolean :desc "Apply the previewed changes"}]
   [:show-contents {:coerce :boolean :desc "Print complete file contents"}]
   [:help {:alias :h :coerce :boolean :desc "Show this help"}]])

(def ^:private boolean-option-names
  {:team :team?
   :keygen :keygen?
   :apply :apply?
   :show-contents :show-contents?
   :help :help?})

(def ^:private plain-app-name #"[A-Za-z][A-Za-z0-9._-]*")

(defn- require-plain-app-name!
  "An app name is a plain identifier: it becomes a directory name under
  `~/.config`, the manifest's `:app` gate, and the bb.edn key that points
  Babashka at the project's deps.edn, so it has to read as a symbol as is."
  [app]
  (when-not (and (string? app) (re-matches plain-app-name app))
    (throw (ex-info (str "--app must be a plain name: letters, digits, dots, hyphens, or "
                         "underscores, starting with a letter (got " (pr-str app) ")")
                    {:app app}))))

(defn parse-args
  "Parse initializer options, including standalone `-h` and `--help`."
  [args]
  (let [parsed (bbcli/parse-opts args {:spec init-spec
                                       :restrict true
                                       :restrict-args true
                                       :no-keyword-opts true})
        opts (reduce-kv (fn [m option result]
                          (if (true? (get parsed option))
                            (assoc m result true)
                            m))
                        (apply dissoc parsed (keys boolean-option-names))
                        boolean-option-names)]
    (when-not (:help? opts)
      (when-not (and (string? (:app opts)) (not (str/blank? (:app opts))))
        (throw (ex-info "--app <name> is required" {})))
      (require-plain-app-name! (:app opts)))
    opts))

(defn proposed-config
  "Build a proposed secrets configuration from initializer options."
  [{:keys [app env layout team?]
    :or {env "dev" layout :tracked}}]
  (let [disposable? (= layout :disposable)
        dir (if disposable? ".local/secrets" "secrets")
        env-config (cond-> {:secrets-file (str dir "/secrets.edn.age")
                            :template "secrets/secrets.edn.example"
                            :manifest (str dir "/secrets.edn.manifest")}
                     disposable? (assoc :key-file (str dir "/key.txt"))
                     team? (assoc :recipients-file (str dir "/recipients.txt")))]
    {:app app
     :default-environment (keyword env)
     :environments {(keyword env) env-config}}))

(defn task-spec
  "Build the `bb.edn` task specification for a secrets configuration."
  [config]
  {:doc "Manage encrypted secrets"
   :requires '([com.kirahowe.secrets.cli :as cli])
   :task (list 'cli/run! config '*command-line-args*)})

;;;; bb.edn and deps.edn Integration

(defn- parse-edn-map
  "Zipper location and value of the top-level map in `source`. These files may
  hold a credential, so a parse failure names the file, a fixed reason and the
  parser's line and column when it gives them; the parser's own message is not
  kept."
  [source file]
  (let [parsed (try
                 (let [loc (z/of-string source)]
                   (when (z/map? loc) [loc (z/sexpr loc)]))
                 (catch Exception e
                   (let [{:keys [row col]} (ex-data e)]
                     (throw (ex-info (str "Could not read " file ": it is not valid EDN"
                                          (when (and row col)
                                            (str " at line " row ", column " col)))
                                     {:file file})))))]
    (or parsed
        (throw (ex-info (str file " must be a top-level map") {:file file})))))

(defn- append-entry [map-loc k v]
  ;; Node-level editing keeps every existing comment and reader form intact.
  (reduce z/append-child
          map-loc
          [(node/newline-node "\n")
           (node/whitespace-node "  ")
           (node/coerce k)
           (node/whitespace-node " ")
           (node/coerce v)]))

(defn- add-root-entry [source file k v]
  (let [[loc _] (parse-edn-map source file)]
    (z/root-string (append-entry loc k v))))

(defn- top-level-value
  "Zipper location of the value under top-level key `k` of `map-loc`, or nil.
  Walks the map's own entries only, so a `:deps` nested inside a deps.edn
  alias is never mistaken for the top-level one."
  [map-loc k]
  (loop [loc (z/down map-loc)]
    (when loc
      (if (= k (z/sexpr loc))
        (z/right loc)
        (recur (some-> loc z/right z/right))))))

(defn- add-nested-entry [source file parent k v]
  (let [[loc _] (parse-edn-map source file)
        map-loc (top-level-value loc parent)]
    (when-not (z/map? map-loc)
      (throw (ex-info (str parent " in " file " must be a map") {:file file :field parent})))
    (z/root-string (append-entry map-loc k v))))

(defn- deps-map [edn file]
  (let [deps (get edn :deps {})]
    (when-not (map? deps)
      (throw (ex-info (str ":deps in " file " must be a map") {:file file})))
    deps))

(defn- known-dependency [deps]
  (some #(when (contains? deps %) %) known-coordinates))

(defn- declares-library? [source file]
  (let [[_ edn] (parse-edn-map source file)]
    (some? (known-dependency (deps-map edn file)))))

(defn self-dependency
  "The bb.edn dependency that puts the project's own deps.edn on Babashka's
  classpath: `{myapp/myapp {:local/root \".\"}}`, keyed by the app name so
  the entry says what it is."
  [app]
  (require-plain-app-name! app)
  {(symbol app app) {:local/root "."}})

(defn- self-dependency? [[_ coordinate]]
  (and (map? coordinate) (= "." (:local/root coordinate))))

(defn merge-bb-edn
  "Merge the generated `secrets` task, and whatever bb.edn needs to load this
  library, without reformatting existing content. With `owner` `:bb.edn` (the
  default) a known coordinate is retained and a missing one is added. With
  `:deps.edn` no coordinate is added; bb.edn instead gets a `:local/root \".\"`
  dependency on the project, unless one is already there, so Babashka reads
  the coordinate from deps.edn. Task conflicts fail."
  ([source config] (merge-bb-edn source config :bb.edn))
  ([source config owner]
   (let [original (or source "{}\n")
         [_ bb] (parse-edn-map original "bb.edn")
         deps (deps-map bb "bb.edn")
         tasks (get bb :tasks {})
         _ (when-not (map? tasks)
             (throw (ex-info ":tasks in bb.edn must be a map" {:file "bb.edn"})))
         known (known-dependency deps)
         desired-task (task-spec config)
         _ (when (and (contains? tasks 'secrets)
                      (not= (get tasks 'secrets) desired-task))
             (throw (ex-info "bb.edn already has a conflicting secrets task"
                             {:task 'secrets})))
         add-dependency? (and (= owner :bb.edn) (nil? known))
         add-self? (and (= owner :deps.edn) (not (some self-dependency? deps)))
         entry (cond add-dependency? @default-dependency
                     add-self? (self-dependency (:app config)))
         source-with-dependency
         (if entry
           (if (contains? bb :deps)
             (add-nested-entry original "bb.edn" :deps (ffirst entry) (val (first entry)))
             (add-root-entry original "bb.edn" :deps entry))
           original)
         [_ parsed-source-with-dependency] (parse-edn-map source-with-dependency "bb.edn")
         add-task? (not (contains? tasks 'secrets))
         final-source
         (if add-task?
           (if (contains? parsed-source-with-dependency :tasks)
             (add-nested-entry source-with-dependency "bb.edn" :tasks 'secrets desired-task)
             (add-root-entry source-with-dependency "bb.edn" :tasks {'secrets desired-task}))
           source-with-dependency)]
     {:content final-source
      :changed? (not= original final-source)
      :owner owner
      :dependency (or known (ffirst @default-dependency))
      :added-dependency? add-dependency?
      :added-self-dependency? add-self?
      :added-task? add-task?})))

(defn merge-deps-edn
  "Make deps.edn declare this library without reformatting existing content.
  A known coordinate already there is kept as is."
  [source]
  (let [[_ edn] (parse-edn-map source "deps.edn")
        known (known-dependency (deps-map edn "deps.edn"))
        content (cond
                  known source
                  (contains? edn :deps)
                  (add-nested-entry source "deps.edn" :deps
                                    (ffirst @default-dependency)
                                    (val (first @default-dependency)))
                  :else (add-root-entry source "deps.edn" :deps @default-dependency))]
    {:content content
     :changed? (not= source content)
     :dependency (or known (ffirst @default-dependency))
     :added-dependency? (nil? known)}))

(defn integration-plan
  "Decide which file owns this library's coordinate, then merge each file.

  Without a deps.edn, bb.edn owns the coordinate. With one, deps.edn owns it
  and bb.edn reaches it through a `:local/root \".\"` dependency on the
  project, so the coordinate is declared once and the JVM application and
  the Babashka task load the same version. A bb.edn that already declares
  the coordinate keeps owning it, because a project may run the task without
  needing the library at runtime. Both files declaring it is refused."
  [bb-source deps-source config]
  (let [bb-declares? (declares-library? (or bb-source "{}\n") "bb.edn")
        deps-declares? (and (some? deps-source) (declares-library? deps-source "deps.edn"))]
    (cond
      (and bb-declares? deps-declares?)
      (throw (ex-info (str "bb.edn and deps.edn both declare this library. Keep the "
                           "coordinate in deps.edn and let bb.edn reach it through the "
                           "project itself: {:deps "
                           (binding [*print-namespace-maps* false]
                             (pr-str (self-dependency (:app config))))
                           "}")
                      {:files ["bb.edn" "deps.edn"]}))

      (or (nil? deps-source) bb-declares?)
      {:owner :bb.edn
       :bb-edn (merge-bb-edn bb-source config :bb.edn)}

      :else
      {:owner :deps.edn
       :deps-edn (merge-deps-edn deps-source)
       :bb-edn (merge-bb-edn bb-source config :deps.edn)})))

(defn- manual-integration
  "What to paste where, as `[file snippet]` pairs with the owner first."
  [{:keys [owner deps-edn]} config]
  (let [task {'secrets (task-spec config)}]
    (case owner
      :bb.edn [["bb.edn" {:deps @default-dependency :tasks task}]]
      :deps.edn (cond-> []
                  (:added-dependency? deps-edn) (conj ["deps.edn" {:deps @default-dependency}])
                  true (conj ["bb.edn" {:deps (self-dependency (:app config)) :tasks task}])))))

;;;; Trusted Ancestry
;;; Babashka cannot reach `SecureDirectoryStream`, so openat-style anchoring is
;;; unavailable on the initializer's own runtime. Instead of re-walking ancestors
;;; that an attacker could have swapped, this proves that no other principal is
;;; able to swap them at all, and refuses to write when it cannot.

(def ^:private no-follow
  (into-array LinkOption [LinkOption/NOFOLLOW_LINKS]))

(def ^:private new-directory-attributes
  ;; Create with an explicit 0755 rather than whatever the process umask yields.
  ;; A umask can only narrow this, never widen it, so group and other write can
  ;; never appear and the verification that follows creation cannot fail on the
  ;; caller's umask.
  (into-array FileAttribute
              [(PosixFilePermissions/asFileAttribute
                (PosixFilePermissions/fromString "rwxr-xr-x"))]))

(def ^:private required-attribute-views ["posix" "unix"])

(def ^:private sticky-bit 01000)
(def ^:private group-write 020)
(def ^:private other-write 002)

(defn filesystem-capability
  "Report the default filesystem's support for the attributes the ancestry proof
  needs. `:views` is everything it reports, `:missing` names any required view it
  cannot, and `:supported?` is false whenever one is missing. Tests redefine this
  var to exercise the fail-closed branch."
  []
  (let [views (set (.supportedFileAttributeViews (FileSystems/getDefault)))
        missing (vec (remove views required-attribute-views))]
    {:views views :missing missing :supported? (empty? missing)}))

(defn- capability! []
  (let [{:keys [missing views]} (filesystem-capability)]
    (when (seq missing)
      (throw (ex-info (str "This filesystem cannot report its "
                           (str/join " and " missing)
                           " file attributes, so the initializer cannot prove that no other"
                           " user is able to redirect its writes. It will not mutate a project"
                           " while implying a race safety it has not established. Initialize"
                           " the project on a POSIX filesystem.")
                      {:reason :unsupported-filesystem :missing missing :views views})))))

(defn- refuse-ancestor! [^Path path reason detail]
  (throw (ex-info (str "Refusing to initialize under " path ": " detail
                       " Move the project under a directory only you can write.")
                  {:path (str path) :reason reason})))

(defn- trusted-type! [^Path path]
  (when-not (Files/exists path no-follow)
    (refuse-ancestor! path :missing "it does not exist."))
  (when (Files/isSymbolicLink path)
    (refuse-ancestor! path :symlink "it is a symbolic link another user could repoint."))
  (when-not (Files/isDirectory path no-follow)
    (refuse-ancestor! path :not-a-directory "it is not a directory.")))

(defn- trusted-owner!
  "Refuse `path` unless the current user or `root` owns it, and return its owner."
  [^Path path detail]
  (let [owner (.getName (Files/getOwner path no-follow))]
    (when-not (#{(System/getProperty "user.name") "root"} owner)
      (refuse-ancestor! path :foreign-owner (str detail owner ", who could replace it.")))
    owner))

(defn- posix-group
  "The name of `path`'s POSIX group. Tests redefine this var to stand in for a
  user-private group, which no portable API can create."
  [^Path path]
  (.getName (get (Files/readAttributes path "posix:group" no-follow) "group")))

(defn- trusted-group-write! [^Path path owner]
  ;; A group whose name matches the owner's is a user-private group, as on
  ;; Fedora, RHEL, and Debian: it holds nobody but the owner, so group write
  ;; hands no other principal a rename and there is no attack to refuse.
  (let [group (posix-group path)]
    (when-not (= owner group)
      (refuse-ancestor! path :shared-group-writable
                        (str "it is writable by group " group
                             ", which holds more than its owner, and is not sticky.")))))

(defn- trusted-mode! [^Path path]
  (let [owner (trusted-owner! path "it belongs to ")
        mode (get (Files/readAttributes path "unix:mode" no-follow) "mode")
        ;; Sticky restores the rename guarantee a write bit takes away: only an
        ;; entry's own owner may rename or delete it.
        sticky? (pos? (bit-and mode sticky-bit))]
    (when (and (not sticky?) (pos? (bit-and mode other-write)))
      (refuse-ancestor! path :world-writable
                        "it is writable by others and is not sticky."))
    (when (and (not sticky?) (pos? (bit-and mode group-write)))
      (trusted-group-write! path owner))))

(defn- trusted-directory! [^Path path]
  (doto path trusted-type! trusted-mode!))

(defn- trusted-component! [^Path path]
  ;; A symlink's own mode bits are ignored by the kernel, so only its owner and
  ;; its parent decide whether anyone else can repoint it: repointing means
  ;; deleting and recreating that entry, which its parent's mode governs and
  ;; which the walk has already checked.
  (if (Files/isSymbolicLink path)
    (trusted-owner! path "this symbolic link belongs to ")
    (trusted-directory! path)))

(defn- path-segments
  "Each path from the child of `root` down to `path`, in order."
  [^Path root ^Path path]
  ;; A `path` equal to `root` relativizes to the empty path, whose one name
  ;; element is the empty string. Drop it so nothing resolves back to `root`.
  (rest (reductions (fn [^Path parent ^Path part] (.resolve parent part))
                    root
                    (remove #(str/blank? (str %)) (.relativize root path)))))

(defn- ancestry [^Path path]
  (let [anchor (.getRoot path)]
    (cons anchor (path-segments anchor path))))

(defn trusted-ancestry!
  "Prove that no principal other than you or `root` can rename or relink any
  directory on the way to project `root`, and return `root`'s real path.

  Every component of the real path that `Path.toRealPath` resolves — from the
  filesystem root down to and including the project root — must exist as a
  directory under `NOFOLLOW_LINKS`, be owned by the current user or by `root`,
  and not be writable by anyone else. Components are rechecked rather than
  assumed from the resolution, because it is the check that makes the claim true
  at operation time rather than at resolution time.

  \"Anyone else\" is exact rather than approximate. Other-write is a refusal
  unless the sticky bit is set. Group write is a refusal unless the sticky bit is
  set or the directory's group name equals its owner's, which is a user-private
  group as on Fedora, RHEL, and Debian: a group holding nobody but the owner is
  not another principal, and a `umask 002` checkout at mode 0775 is exactly as
  safe as one at 0755. Sticky, meanwhile, means only an entry's own owner may
  rename or delete that entry, so another user with write access to `/tmp` can
  create entries beside ours but cannot swap ours for a symlink — and that swap
  is the whole attack. Refusing either case would reject ordinary working
  configurations without taking one capability away from an attacker.

  The path as written is walked too, because a symlink on the way in can be
  repointed by whoever writes the *link's* own parent, and the resolved path does
  not reveal that parent. A link component is judged on its owner alone — the
  kernel ignores a symlink's mode bits — with its parent covered by the same
  walk. Link components are permitted rather than refused: on macOS both `/tmp`
  and `/var` are root-owned symlinks, and a checkout reached through a link the
  user owns is ordinary.

  Throws `ex-info` naming the offending directory under `:path`, with `:reason`
  one of `:unsupported-filesystem`, `:missing`, `:not-a-directory`, `:symlink`,
  `:foreign-owner`, `:world-writable`, or `:shared-group-writable`."
  ^Path [root]
  (capability!)
  (let [given (.normalize (.toAbsolutePath (.toPath (io/file (str root)))))
        real (.toRealPath given (make-array LinkOption 0))]
    (run! trusted-component! (ancestry given))
    (run! trusted-directory! (ancestry real))
    real))

;;;; Change Planning

(defn- safe-segments! [rel segments]
  (doseq [^Path segment segments]
    (when (Files/isSymbolicLink segment)
      (throw (ex-info "Refusing a path below a symbolic link"
                      {:path rel :link (str segment)}))))
  (doseq [^Path segment (butlast segments)]
    (when (and (Files/exists segment no-follow)
               (not (Files/isDirectory segment no-follow)))
      (throw (ex-info "Refusing a path below a non-directory"
                      {:path rel :entry (str segment)})))))

(defn- target-path!
  "Resolve `rel` under project `root`, which may be a string, `File`, or `Path`."
  ^Path [root rel]
  (let [root (.normalize (.toAbsolutePath (.toPath (io/file (str root)))))
        target (.normalize (.toAbsolutePath (.resolve root rel)))]
    (when-not (.startsWith target root)
      (throw (ex-info "Path escapes project" {:path rel})))
    ;; A safe leaf below a symlinked directory is not a safe project artifact:
    ;; writes would escape the consumer checkout. Every relative segment is
    ;; rechecked here, and every mutation re-enters this function, so the check
    ;; runs at write time and not only while planning.
    (safe-segments! rel (path-segments root target))
    target))

(defn- merge-gitignore [old line]
  (if (some #(= (str/trim %) (str/trim line))
            (str/split-lines (or old "")))
    old
    (str (or old "")
         (when (and (seq old) (not (str/ends-with? old "\n"))) "\n")
         line)))

(defn scaffold-files
  "Return the public scaffold files for initializer options."
  [{:keys [layout team?]}]
  (let [dir (if (= layout :disposable) ".local/secrets" "secrets")]
    (cond-> {"secrets/secrets.edn.example" "{:example/api-key \"replace-me\"}\n"}
      team? (assoc (str dir "/recipients.txt") "# One age recipient per line.\n")
      (= layout :disposable) (assoc ".gitignore" "/.local/secrets/\n"))))

(defn- existing-template! [file path]
  (let [{:keys [ok? value] :as parsed} (safe-edn/parse (slurp file))]
    (when-not ok?
      (throw (ex-info "Existing secrets template is not valid EDN"
                      (merge {:path path}
                             (select-keys parsed
                                          [:reason :line :column :depth :limit])))))
    (when-not (map? value)
      (throw (ex-info "Existing secrets template must contain an EDN map"
                      {:path path})))
    value))

(def ^:private write-actions #{:create :merge})

(defn proposed-changes
  "Plan all writes and run the CLI's canonical collision validation first.

  Returns `:changes`, the entries to write, and `:actions`, one `:path` and
  `:action` (`:create`, `:merge`, `:preserve`, or `:unchanged`) per proposed
  file so every one of them stays auditable. Neither retains the existing
  contents of a file it is about to replace. `:owner` names the file that
  declares this library's coordinate (see [[integration-plan]]), `:added-dependency`
  is the `{lib coordinate}` entry the plan declares there, or nil when the
  project already declares one, and `:manual` holds the snippets a manual
  integration would paste."
  [{:keys [root layout team?] :as opts}]
  (let [root (or root ".")
        config (proposed-config opts)
        normalized (cli/normalize-config config)
        source (fn [name]
                 (let [file (io/file root name)]
                   (when (.exists file) (slurp file))))
        plan (integration-plan (source "bb.edn") (source "deps.edn") config)
        raw (into
             (cond-> []
               (:deps-edn plan)
               (conj {:path "deps.edn"
                      :content (get-in plan [:deps-edn :content])
                      :replace? true})
               true
               (conj {:path "bb.edn"
                      :content (get-in plan [:bb-edn :content])
                      :replace? true}))
             (for [[path content] (scaffold-files {:layout layout :team? team?})
                   :let [file (io/file root path)
                         exists? (.exists file)]]
               (cond
                 (= path ".gitignore")
                 {:path path
                  :content (merge-gitignore (when exists? (slurp file)) content)
                  :replace? true}

                 (= path "secrets/secrets.edn.example")
                 (do
                   (when exists?
                     (existing-template! file path))
                   {:path path
                    :content (if exists? (slurp file) content)
                    :replace? false
                    :preserve? exists?})

                  ;; Recipients are public but hand-maintained; comments,
                  ;; ordering, and existing teammates' keys are preserved.
                 (str/ends-with? path "/recipients.txt")
                 {:path path
                  :content (if exists? (slurp file) content)
                  :replace? false
                  :preserve? exists?}

                 :else
                 {:path path :content content :replace? false})))]
    (doseq [{:keys [path replace? preserve?]} raw]
      (let [target (target-path! root path)]
        (when (and (Files/exists target no-follow)
                   (not replace?)
                   (not preserve?))
          (throw (ex-info "Refusing to overwrite existing initializer artifact"
                          {:path path})))))
    (let [planned (mapv (fn [{:keys [path content preserve?] :as entry}]
                          (let [file (io/file root path)
                                ;; The old body is read to detect a change and
                                ;; classify the action, then dropped. Nothing
                                ;; downstream needs it — `apply-changes!` reads
                                ;; the bytes it rolls back for itself — and a
                                ;; plan that carries it can only disclose it.
                                old (when (.exists file) (slurp file))]
                            (-> entry
                                (dissoc :replace? :preserve?)
                                (assoc :action
                                       (cond
                                         preserve? :preserve
                                         (= content old) :unchanged
                                         (some? old) :merge
                                         :else :create)))))
                        raw)]
      {:config config
       :normalized-config normalized
       :owner (:owner plan)
       :added-dependency (when (or (get-in plan [:bb-edn :added-dependency?])
                                   (get-in plan [:deps-edn :added-dependency?]))
                           @default-dependency)
       :manual (manual-integration plan config)
       :actions (mapv #(select-keys % [:path :action]) planned)
       :changes (filterv (comp write-actions :action) planned)})))

;;;; Safe Output
;;; A previewed file is untrusted input to the terminal, and the file most
;;; likely to be replaced is the consumer's own bb.edn, which may already hold
;;; a credential nobody asked to see. Every character taken from file content
;;; or from a path reaches stdout through `render-line` or `render-path`.

(def ^:private max-line-width 160)

(def ^:private named-escapes
  {\newline "\\n"
   \return "\\r"
   \tab "\\t"
   \formfeed "\\f"
   \backspace "\\b"})

(defn- control? [code]
  (or (< code 0x20) (= code 0x7f) (<= 0x80 code 0x9f)))

(defn- escape-control
  "Render control characters, `ESC` first among them, as printable escapes.

  A crafted file could otherwise repaint the terminal previewing it and hide
  what is about to be written; a literal `\\x1b` cannot."
  [s]
  (str/join
   (for [c s]
     (cond
       (named-escapes c) (named-escapes c)
       (control? (int c)) (format "\\x%02x" (int c))
       :else c))))

(def ^:private sensitive-value
  (let [name-part "[-\\w.:/*+!?<>$]*"
        secretish "(?:secret|token|password|key|credential)"
        ;; The separator is required, so the closing quote of one string cannot
        ;; open a quoted "value" that runs on into the next one.
        separator "(?:\"?\\s*[:=]\\s*|\"?\\s+)"
        value "(\"[^\"]*\"|[-\\w+/=.:@~$]{4,})"]
    ;; After the secret-like word the name ends at the first place a separator
    ;; fits. Greedy, it would take `:hunter2` from `password:hunter2 host=x` as
    ;; part of the name and hide the host instead of the password.
    (re-pattern (str "(?i)(" name-part secretish name-part "?" separator ")" value))))
(def ^:private age-secret-key #"AGE-SECRET-KEY-1[0-9A-Za-z]+")
(def ^:private opaque-token #"[A-Za-z0-9+/=_-]{32,}")

(defn- hidden-marker [s]
  (str "[redacted " (count s) " characters]"))

(defn- letters-and-digits? [s]
  (boolean (and (re-find #"[A-Za-z]" s) (re-find #"[0-9]" s))))

(defn- redact
  "Replace the values that most obviously carry a credential with a marker
  naming how many characters it hid.

  Three deliberately simple rules — a value under a key named like a secret, an
  `AGE-SECRET-KEY-1…` identity, and a long opaque token — and not a general
  secret scanner, which is an explicit non-goal. It over-redacts on purpose: a
  Git SHA and a `:secrets-file` path go the same way as a real credential, and
  `--show-contents` is the way to read what a preview hid."
  [s]
  (-> s
      (str/replace sensitive-value (fn [[_ k v]] (str k (hidden-marker v))))
      (str/replace age-secret-key hidden-marker)
      (str/replace opaque-token
                   #(if (letters-and-digits? %) (hidden-marker %) %))))

(defn- truncate [s]
  (if (<= (count s) max-line-width)
    s
    (str (subs s 0 max-line-width)
         " [truncated, " (- (count s) max-line-width) " more characters]")))

(defn- render-path
  "Make a path safe to print. Redaction is not applied: a path is a name, not a
  value, and the rules would mangle `secrets/key.txt`."
  [path]
  (truncate (escape-control (str path))))

(defn- render-line
  "Make one line of file content safe to print: redacted, escaped, bounded."
  [line]
  (truncate (escape-control (redact line))))

;;;; Preview and Application
;;; Every report is built first as a vector of strings, one per line, by a pure
;;; function, and reaches the terminal only through `emit!`.

(defn- emit!
  "Write `lines` to `*out*`, one per line."
  [lines]
  (run! println lines))

(def ^:private proposed-labels
  {:create "create"
   :merge "merge into the existing file"
   :preserve "leave as is, existing file preserved"
   :unchanged "leave as is, already current"})
(def ^:private applied-labels
  {:create "created" :merge "merged"})

(def ^:private contents-warning
  [" WARNING: --show-contents prints complete file contents to stdout,"
   " including whatever the files being replaced already hold. A credential"
   " already sitting in one of them (an existing bb.edn, most likely) is"
   " printed unredacted, so do not do this into a shared log."])

(defn- action-line [{:keys [path action]}]
  (str " " (render-path path) ": " (proposed-labels action)))

(defn- counts-line [actions]
  (let [writes (count (filter (comp write-actions :action) actions))]
    (str " " writes (if (= 1 writes) " file to write, " " files to write, ")
         (- (count actions) writes) " left as is.")))

(def ^:private hunk-context 3)

(defn- common-count [xs ys]
  (count (take-while true? (map = xs ys))))

(defn- changed-region
  "Bound the changed region between two vectors of lines, with context.

  Common leading and trailing lines are peeled off, which is exactly right for
  the merges the initializer proposes: they append to an existing file, so the
  region is small however long the file is."
  [olds news]
  (let [prefix (common-count olds news)
        tail (min (common-count (reverse olds) (reverse news))
                  (- (count olds) prefix)
                  (- (count news) prefix))
        old-end (- (count olds) tail)
        new-end (- (count news) tail)
        from (max 0 (- prefix hunk-context))
        until (min (count olds) (+ old-end hunk-context))]
    {:from from
     :before (subvec olds from prefix)
     :removed (subvec olds prefix old-end)
     :added (subvec news prefix new-end)
     :after (subvec olds old-end until)}))

(defn- lines [content]
  (if (nil? content) [] (vec (str/split-lines content))))

(defn- span [from n]
  (str (if (zero? n) 0 (inc from)) "," n))

(defn- hunk-lines
  "The changed region between `old` and `content` as a unified-diff hunk, every
  line of it rendered safe."
  [old content]
  (let [olds (lines old)
        news (lines content)
        {:keys [from before removed added after]} (changed-region olds news)
        context (+ (count before) (count after))]
    (-> [(str "  @@ -" (span from (+ context (count removed)))
              " +" (span from (+ context (count added))) " @@")]
        (into (map #(str "   " (render-line %))) before)
        (into (map #(str "  -" (render-line %))) removed)
        (into (map #(str "  +" (render-line %))) added)
        (into (map #(str "   " (render-line %))) after))))

(defn- content-lines
  "Both bodies in full, as `--show-contents` asked: unredacted by design."
  [path old content]
  (-> [(str "--- " (if (nil? old) "/dev/null" (str "a/" (render-path path))))
       (str "+++ b/" (render-path path))]
      (into (map #(str "-" %)) (when (some? old) (str/split-lines old)))
      (into (map #(str "+" %)) (str/split-lines content))))

(defn- body-lines [mode old {:keys [path content]}]
  (if (= :full mode)
    (content-lines path old content)
    (hunk-lines old content)))

(defn- dependency-lines
  "The coordinate a plan adds, named in full, since a bb.edn hunk redacts the
  commit as an opaque token. A commit that is not a release tag can be resolved
  only once it is pushed, and that is said here rather than found out at
  resolve time."
  [added-dependency]
  (when-let [[lib coordinate] (first added-dependency)]
    (cond-> [(str " Dependency: " lib " "
                  (binding [*print-namespace-maps* false] (pr-str coordinate)))]
      (and (:git/sha coordinate) (not (:git/tag coordinate)))
      (conj (str " That commit is the checkout's HEAD, not a release tag. Push it before"
                 " another machine resolves this project.")))))

(defn- preview-lines
  "The preview: each path with its action, the body of each change when `mode`
  shows bodies, the totals, and the dependency the plan adds. `current` maps a
  change's path to what is on disk there now, for the modes that render it."
  [{:keys [actions changes mode current added-dependency]}]
  (let [bodies (when (not= :summary mode)
                 (into {} (map (juxt :path identity)) changes))]
    (-> ["Secrets initializer preview:"]
        (into (when (= :full mode) contents-warning))
        (into (if (seq actions)
                (-> []
                    (into (mapcat (fn [{:keys [path] :as action}]
                                    (cons (action-line action)
                                          (when-let [change (get bodies path)]
                                            (body-lines mode (get current path) change)))))
                          actions)
                    (conj (counts-line actions)))
                [" no project changes are needed."]))
        (into (dependency-lines added-dependency))
        (conj " Private identities are never created unless --keygen is supplied."))))

(defn- current-content
  "Read what is on disk at `path` under `root`, to render it and let it go."
  [root path]
  (let [file (io/file (str root) path)]
    (when (.exists file)
      (slurp file))))

(defn print-preview!
  "Print the proposed initializer changes.

  `:mode` decides how much of a file reaches stdout. `:summary`, the default and
  what every noninteractive or `--apply` run gets, names each path and its
  action and prints no file body at all. `:hunks` adds the changed region of
  each file, redacted and escaped. `:full` prints whole bodies behind a warning,
  and only because `--show-contents` asked for them. The files a body needs are
  read here, rendered, and let go."
  [{:keys [root actions changes mode added-dependency]}]
  (let [mode (or mode :summary)
        current (when (not= :summary mode)
                  (into {}
                        (map (fn [{:keys [path]}] [path (current-content root path)]))
                        changes))]
    (emit! (preview-lines {:actions actions :changes changes :mode mode :current current
                           :added-dependency added-dependency}))))

(defn- applied-lines [changes]
  (when (seq changes)
    (into ["Applied:"]
          (map (fn [{:keys [path action]}]
                 (str " " (render-path path) ": " (applied-labels action))))
          changes)))

(def ^:private staging-options
  ;; O_CREAT|O_EXCL: the open fails outright on any existing entry, a symlink
  ;; included, so the staging leaf is no-follow by construction and needs no
  ;; separate link check of its own.
  (into-array OpenOption [StandardOpenOption/CREATE_NEW StandardOpenOption/WRITE]))

(defn- ensure-directories! [^Path root ^Path target]
  ;; `Files/createDirectories` re-walks the whole pathname; this walks one
  ;; segment at a time below the already-verified root. A directory created here
  ;; is verified too: the window between creating it and writing into it is the
  ;; same window as the window between finding it and writing into it.
  (doseq [^Path segment (path-segments root (.getParent target))]
    (when-not (Files/exists segment no-follow)
      (Files/createDirectory segment new-directory-attributes))
    (trusted-directory! segment)))

(defn- publish! [^Path staging ^Path target]
  ;; ATOMIC_MOVE is renameat(2): it replaces whatever entry sits at `target`
  ;; without following a link there, so the leaf was never the exposure — the
  ;; ancestors were. A leaf link check here would be redundant.
  (try
    (Files/move staging target
                (into-array StandardCopyOption
                            [StandardCopyOption/ATOMIC_MOVE
                             StandardCopyOption/REPLACE_EXISTING]))
    (catch Exception e
      ;; Babashka cannot resolve AtomicMoveNotSupportedException, so identify
      ;; that one exception by name. There is no copy-and-delete fallback,
      ;; which would follow a symlink planted at `target`.
      (if (= "java.nio.file.AtomicMoveNotSupportedException" (.getName (class e)))
        (throw (ex-info (str "This filesystem cannot atomically publish " target)
                        {:path (str target) :reason :atomic-move-unsupported}
                        e))
        (throw e)))))

(defn- staging-path
  "Name a staging file beside `target`, inside the already-verified parent."
  ^Path [^Path target]
  ;; A random name is unaimable, so nothing can be planted at it on purpose;
  ;; CREATE_NEW then refuses whatever happens to be there anyway.
  (.resolve (.getParent target) (str ".secrets-init-" (random-uuid) ".tmp")))

(defn- atomic-write! [^Path root ^Path target ^String content]
  (ensure-directories! root target)
  (let [staging (staging-path target)]
    (try
      (with-open [channel (Files/newByteChannel staging staging-options)]
        (.write channel (ByteBuffer/wrap (.getBytes content StandardCharsets/UTF_8))))
      (publish! staging target)
      (finally
        (Files/deleteIfExists staging)))))

(defn- rollback! [^Path root old]
  (reduce (fn [failed [path bytes]]
            ;; A path that no longer resolves safely under the verified root was
            ;; never written through, so there is nothing there to undo.
            (if-let [target (try (target-path! root path) (catch Exception _ nil))]
              (try
                (if bytes
                  (atomic-write! root target (String. ^bytes bytes StandardCharsets/UTF_8))
                  (Files/deleteIfExists target))
                failed
                (catch Exception _ (conj failed path)))
              failed))
          []
          old))

(defn- apply-changes! [root changes]
  (let [root (trusted-ancestry! root)
        old (into {}
                  (for [{:keys [path]} changes
                        :let [target (target-path! root path)]]
                    [path
                     (when (Files/exists target no-follow)
                       (Files/readAllBytes target))]))]
    (try
      (doseq [{:keys [path content]} changes]
        (atomic-write! root (target-path! root path) content))
      (catch Exception e
        (let [failed (rollback! root old)]
          (throw (ex-info (str "Initializer failed and "
                               (if (seq failed)
                                 "some previous project files could not be restored: "
                                 "previous project files were restored: ")
                               (or (ex-message e) (str e)))
                          {:unrestored failed}
                          e)))))))

(defn- choice! [{:keys [choice input]}]
  (or choice
      (do
        (emit! ["Choose: [a]pply, [m]anual, [c]ancel"])
        (let [read! (or input read-line)]
          (case (some-> (read!) str/trim str/lower-case)
            ("a" "apply") :apply
            ("m" "manual") :manual
            :cancel)))))

(defn root-trust
  "Report, without mutating anything, whether the initializer would be allowed to
  write into project `root`. Preview prints this so a refusal is visible before
  apply is chosen; the apply path re-establishes the guarantee itself rather than
  trusting this report."
  [root]
  (let [capability (filesystem-capability)]
    (try
      {:trusted? true :capability capability :root (str (trusted-ancestry! root))}
      (catch Exception e
        (merge {:trusted? false
                :capability capability
                :message (or (ex-message e) (str e))}
               (select-keys (ex-data e) [:reason :path]))))))

(defn- trust-line [{:keys [trusted? message]}]
  (if trusted?
    " Project path is trusted for safe writes."
    (str " Project path is not trusted; --apply will be refused. " message)))

(defn- manual-lines
  "The manual integration as copyable EDN: each file, then its snippet, pretty
  printed with namespace-map shorthand and the print limits off."
  [manual]
  (binding [*print-namespace-maps* false
            *print-length* nil
            *print-level* nil]
    (into ["Manual integration (no files changed):"]
          (mapcat (fn [[file snippet]]
                    [(str file ":")
                     (str/trim-newline (with-out-str (pprint/pprint snippet)))]))
          manual)))

(defn- preview-outcome-lines
  "What a preview-only run ends with when there was something to apply."
  [changes trust]
  (when (seq changes)
    [(if (:trusted? trust)
       "No files changed. Rerun with --apply to apply this plan."
       "No files changed. Fix the project-path trust problem above, then preview again.")]))

(defn- output-mode
  "Choose how much file content this run's preview may print.

  `--show-contents` is the only route to complete bodies. Otherwise a
  noninteractive or `--apply` run gets path-and-action summaries and an
  interactive preview gets redacted hunks, so wherever two modes could apply the
  safer one wins: an interactive `--apply` run prints no bodies either."
  [{:keys [show-contents? apply? tty?]}]
  (cond
    show-contents? :full
    (or apply? (not tty?)) :summary
    :else :hunks))

(defn init!
  "Preview and optionally apply. `:root`, `:tty?`, `:choice`, and `:input` are
  injectable for tests. A non-TTY caller must set :apply? to mutate files.
  The returned map carries `:trust`, the [[root-trust]] report the preview
  printed, so no caller has to infer whether race safety was established, and
  `:actions`, one path and action per proposed file. It deliberately carries no
  file contents: a caller that prints its status map would otherwise disclose
  whatever the files it touched already held."
  [opts]
  (let [opts (merge {:root "."
                     :tty? (some? (System/console))
                     :env "dev"
                     :layout :tracked}
                    opts)
        proposal (assoc (proposed-changes opts) :root (:root opts))
        trust (root-trust (:root opts))
        _ (print-preview! (assoc proposal :mode (output-mode opts)))
        _ (emit! [(trust-line trust)])
        selected (cond
                   (:apply? opts) :apply
                   (:tty? opts) (choice! opts)
                   :else :preview)
        result {:actions (:actions proposal) :trust trust}]
    (case selected
      :apply
      (do
        (apply-changes! (:root opts) (:changes proposal))
        (emit! (applied-lines (:changes proposal)))
        (when (:keygen? opts)
          (cli/keygen! (:normalized-config proposal) (:env opts)))
        (assoc result :status :applied))

      :manual
      (do
        (emit! (manual-lines (:manual proposal)))
        (assoc result :status :manual))

      :cancel
      (assoc result :status :cancelled)

      (do
        (emit! (preview-outcome-lines (:changes proposal) trust))
        (assoc result :status :preview)))))

;;;; Entry Point

(defn- help-lines []
  ["Secrets project initializer"
   ""
   "Usage: -m com.kirahowe.secrets.init --app NAME [options]"
   ""
   "Options:"
   (bbcli/format-opts {:spec init-spec})])

(defn- error-lines [e]
  [(str "secrets init: " (ex-message e))
   "Run with --help for usage and options."])

(defn- print-init-error! [e]
  (binding [*out* *err*]
    (emit! (error-lines e))))

(defn -main
  "Run the secrets initializer from command-line arguments."
  [& args]
  (try
    (let [opts (parse-args args)]
      (if (:help? opts)
        (emit! (help-lines))
        (init! opts)))
    (catch clojure.lang.ExceptionInfo e
      (print-init-error! e)
      (System/exit 1))))
