(ns com.kirahowe.secrets.init
  "One-shot project bootstrapper for `bb secrets`.

  It creates the files a new setup needs and never modifies a file that already
  exists. For an existing `bb.edn` or `deps.edn` it prints what to add and
  leaves the file alone."
  (:require [babashka.cli :as bbcli]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.java.shell :as sh]
            [clojure.pprint :as pprint]
            [clojure.string :as str]
            [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.safe-edn :as safe-edn])
  (:import [java.nio.charset StandardCharsets]
           [java.nio.file FileAlreadyExistsException Files LinkOption OpenOption Path
            StandardOpenOption]
           [java.nio.file.attribute FileAttribute]))

;;;; The library's own coordinate

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
                      {:reason :no-file :resource coordinate-resource}))))

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
                      {:reason :git-failed :dir (str dir) :args (vec args) :exit exit})))
    (str/trim out)))

(defn- library-dependency
  "The dependency that resolves to the library that is running, as the single
  `{lib coordinate}` entry a project's `:deps` needs, given the `url` its
  coordinate resource was loaded from.

  A `file:` URL is a source checkout, and the coordinate is that checkout's
  `HEAD`: `{:git/tag \"v<version>\" :git/sha <commit>}` when the release tag
  names it, and `{:git/sha <commit>}` otherwise. tools.deps wants the commit
  beside a tag, and no commit can record its own hash, so the initializer asks
  git for it. A checkout under `~/.gitlibs` is a git worktree and answers the
  same way. Any other URL is the jar of a Maven artifact, and the version the
  resource declares is the version that jar was built from.

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
  "The library that is running, located once per run and only when a plan
  is made."
  (delay (library-dependency (coordinate-url) coordinates git)))

;;;; Options

(def ^:private init-spec
  [[:app {:coerce :string :desc "Application name"}]
   [:env {:coerce :string :default "dev" :desc "Environment name"}]
   [:keygen {:coerce :boolean :desc "Also generate an age identity"}]
   [:apply {:coerce :boolean :desc "Create the files instead of previewing"}]
   [:help {:alias :h :coerce :boolean :desc "Show this help"}]])

(def ^:private boolean-option-names
  {:keygen :keygen?
   :apply :apply?
   :help :help?})

(def ^:private plain-name #"[A-Za-z][A-Za-z0-9._-]*")

(defn- require-plain-name!
  "The app and environment names are plain identifiers. The app name becomes a
  directory under `~/.config` and a symbol in bb.edn, and the environment name
  becomes a keyword there, so both have to read back as written. The rejected
  value is not echoed, so nothing the names carry reaches the terminal."
  [option value]
  (when-not (and (string? value) (re-matches plain-name value))
    (throw (ex-info (str option " must be a plain name: letters, digits, dots, hyphens, or "
                         "underscores, starting with a letter")
                    {:reason :usage :option option}))))

(defn- parse-args
  "Parse initializer options, including standalone `-h` and `--help`. The names
  are checked when [[proposed-config]] uses them."
  [args]
  (let [parsed (bbcli/parse-opts args {:spec init-spec
                                       :restrict true
                                       :restrict-args true
                                       :no-keyword-opts true
                                       :error-fn (fn [{:keys [msg]}]
                                                   (throw (ex-info msg {:reason :usage})))})
        opts (reduce-kv (fn [m option result]
                          (if (true? (get parsed option))
                            (assoc m result true)
                            m))
                        (apply dissoc parsed (keys boolean-option-names))
                        boolean-option-names)]
    (when-not (:help? opts)
      (when-not (and (string? (:app opts)) (not (str/blank? (:app opts))))
        (throw (ex-info "--app <name> is required" {:reason :usage}))))
    opts))

;;;; What a project needs

(defn- proposed-config
  "The secrets configuration a new project starts with: one environment whose
  ciphertext is `secrets/secrets.edn.age`. The CLI derives the template and
  manifest paths beside it and the identity path from the app name. Throws when
  `app` or `env` is not a plain name."
  [{:keys [app env] :or {env "dev"}}]
  (require-plain-name! "--app" app)
  (require-plain-name! "--env" env)
  {:app app
   :default-environment (keyword env)
   :environments {(keyword env) {:secrets-file "secrets/secrets.edn.age"}}})

(defn- task-spec
  "Build the `bb.edn` task specification for a secrets configuration."
  [config]
  {:doc "Manage encrypted secrets"
   :requires '([com.kirahowe.secrets.cli :as cli])
   :task (list 'cli/run! config '*command-line-args*)})

(defn- self-dependency
  "The bb.edn dependency that puts the project's own deps.edn on Babashka's
  classpath: `{myapp/myapp {:local/root \".\"}}`, keyed by the app name so
  the entry says what it is."
  [app]
  {(symbol app app) {:local/root "."}})

(def ^:private template-path
  "Where the CLI looks for the template of `secrets/secrets.edn.age`."
  "secrets/secrets.edn.example")

(def ^:private template-content "{:example/api-key \"replace-me\"}\n")

(defn- edn-text
  "`x` as copyable EDN: pretty printed, with namespace-map shorthand and the
  print limits off. The pretty printer's commas are dropped, which is safe
  because no string the initializer generates contains one."
  [x]
  (binding [*print-namespace-maps* false
            *print-length* nil
            *print-level* nil]
    (-> (with-out-str (pprint/pprint x))
        str/trim-newline
        (str/replace "," ""))))

(defn- entry-text
  "A map entry as it is typed into a file, with a long value on its own lines."
  [k v]
  (let [text (edn-text v)]
    (str k (if (str/includes? text "\n") "\n" " ") text)))

;;;; Planning

(def ^:private no-follow (into-array LinkOption [LinkOption/NOFOLLOW_LINKS]))

(defn- target
  "`path` under project `root`. An absolute `path` stands for itself."
  ^Path [root path]
  (.resolve (.toPath (io/file (str root))) (str path)))

(defn- exists?
  "True when anything is at `path` under `root`, a dangling link included."
  [root path]
  (Files/exists (target root path) no-follow))

(defn- existing-map
  "The top-level map of the existing EDN file `path`, or nil when it is not a
  readable file holding one EDN map. Such an entry counts as having nothing,
  so every wanted entry is printed for it."
  [root path]
  (let [file (.toFile (target root path))
        {:keys [ok? value]} (when (.isFile file) (safe-edn/parse (slurp file)))]
    (when (and ok? (map? value)) value)))

(defn- present?
  "Whether the file map `current` already has the wanted `[section k v]` entry.
  The library counts under either of its names, and any `:local/root \".\"`
  dependency counts as the self dependency."
  [current [section k v]]
  (let [entries (get current section)
        entries (if (map? entries) entries {})]
    (boolean
     (cond
       (= "." (:local/root v)) (some #(and (map? %) (= "." (:local/root %))) (vals entries))
       (known-coordinates k) (some #(contains? entries %) known-coordinates)
       :else (contains? entries k)))))

(defn- file-map
  "The whole EDN map a new file holds for the wanted `[section k v]` entries."
  [wanted]
  (reduce (fn [m [section k v]] (assoc-in m [section k] v)) (array-map) wanted))

(defn- edn-file
  "Plan one EDN project file. A missing file is created with every wanted
  entry. An existing file is left alone, and the entries it lacks become
  additions to print. `:entries` holds the wanted entries the plan creates or prints."
  [root path wanted]
  (if-not (exists? root path)
    {:path path :action :create :entries wanted
     :content (str (edn-text (file-map wanted)) "\n")}
    (let [current (existing-map root path)
          missing (vec (remove #(present? current %) wanted))]
      (if (empty? missing)
        {:path path :action :exists}
        {:path path
         :action :add
         :entries missing
         :additions (mapv (fn [[section k v]]
                            {:under section :text (entry-text k v)})
                          missing)}))))

(defn- plain-file
  "Plan a file the initializer only ever creates."
  [root path content]
  (if (exists? root path)
    {:path path :action :exists}
    {:path path :action :create :content content}))

(defn- plan
  "Decide, without writing anything, what initializing a project would do.

  Returns `:root`, the proposed `:config`, and `:files`, one map per file with
  its `:path`, relative to `:root` unless absolute, and an `:action`:

  - `:create` for a file that does not exist, with its `:content`. The identity
    `--keygen` asks for is a `:create` entry marked `:private?` and has no
    content, because `age-keygen` writes it.
  - `:exists` for a file that is already there and needs nothing.
  - `:add` for an existing file that lacks something, with `:additions`, each
    the top-level key to put it `:under` and the `:text` to put there.

  Without a deps.edn, bb.edn declares the library. With one, deps.edn declares
  it and bb.edn reaches it through a `:local/root \".\"` dependency on the
  project, so the JVM application and the Babashka task load the same version.
  A bb.edn that already declares the library keeps doing so. `:dependency` is
  the library's `{lib coordinate}` entry when the plan creates or prints it."
  [opts]
  (let [{:keys [root app keygen?] :as opts} (merge {:root "."} opts)
        config (proposed-config opts)
        library (vec (cons :deps (first @default-dependency)))
        task [:tasks 'secrets (task-spec config)]
        deps-owns? (and (exists? root "deps.edn")
                        (not (and (exists? root "bb.edn")
                                  (present? (existing-map root "bb.edn") library))))
        bb-edn (edn-file root "bb.edn"
                         [(if deps-owns?
                            (vec (cons :deps (first (self-dependency app))))
                            library)
                          task])
        deps-edn (when deps-owns? (edn-file root "deps.edn" [library]))
        key-file (secrets/default-key-file app)
        files (cond-> (filterv some? [deps-edn
                                      bb-edn
                                      (plain-file root template-path template-content)])
                keygen? (conj (if (exists? root key-file)
                                {:path key-file :action :exists}
                                {:path key-file :action :create :private? true})))]
    (cond-> {:root root :config config :key-file key-file :files files}
      (some #{library} (mapcat :entries files)) (assoc :dependency @default-dependency))))

;;;; Applying

(def ^:private create-new
  ;; O_CREAT|O_EXCL: the open fails on any existing entry, a symbolic link
  ;; included, so a file that appeared after the plan was made is not replaced.
  (into-array OpenOption [StandardOpenOption/CREATE_NEW StandardOpenOption/WRITE]))

(defn- refuse-existing! [path created]
  (throw (ex-info (str path " already exists, so the initializer did not write it."
                       (when (seq created)
                         (str " Created before stopping: " (str/join ", " created) ".")))
                  {:reason :file-exists :path (str path) :created created})))

(defn- apply-plan!
  "Create every `:create` file of `plan`, in order, and return `:created`, the
  paths written, and `:public-key` when an identity was generated.

  A file is only ever created. If something already sits at a path, which means
  it appeared after the plan was made, the run stops with an `ex-info` naming
  that `:path` and the files `:created` before it, and what is there is left
  untouched. Public files get the process's default permissions. The identity
  is generated by `age/keygen!`, which makes it readable by its owner only."
  [{:keys [root files]}]
  (reduce
   (fn [{:keys [created] :as result} {:keys [path content private?]}]
     (let [file (target root path)]
       (if private?
         (do (when (Files/exists file no-follow)
               (refuse-existing! path created))
             (-> result
                 (assoc :public-key (age/keygen! (str file)))
                 (update :created conj path)))
         (do (when-let [parent (.getParent file)]
               (Files/createDirectories parent (make-array FileAttribute 0)))
             (try
               (Files/write file (.getBytes ^String content StandardCharsets/UTF_8) create-new)
               (catch FileAlreadyExistsException _
                 (refuse-existing! path created)))
             (update result :created conj path)))))
   {:created []}
   (filter #(= :create (:action %)) files)))

;;;; Reporting

(defn- indented [n text]
  (map #(str (str/join (repeat n " ")) %) (str/split-lines text)))

(defn- section
  "`heading` over `lines` with a blank line before, or nothing without lines."
  [heading lines]
  (when (seq lines)
    (concat ["" heading] lines)))

(defn- report-lines
  "Everything a run prints, one string per line. `result` is what
  [[apply-plan!]] returned, or nil for a preview."
  [{:keys [files dependency key-file]} keygen? result]
  (let [by-action (group-by :action files)
        [lib coordinate] (first dependency)]
    (concat
     [(if result
        "Secrets initializer"
        "Secrets initializer preview. Nothing is written without --apply.")]
     (section (if result "Created:" "Would create:")
              (mapcat (fn [{:keys [path content private?]}]
                        (cons (str "  " path)
                              (cond
                                private? ["      a new age identity, readable only by you"]
                                result nil
                                :else (indented 6 content))))
                      (:create by-action)))
     (section "Already there, left as they are:"
              (map #(str "  " (:path %)) (:exists by-action)))
     (section "Add these yourself. The initializer does not edit existing files."
              (for [{:keys [path additions]} (:add by-action)
                    {:keys [under text]} additions
                    line (cons (str "  " path ", under " under ":") (indented 6 text))]
                line))
     (when (and (:git/sha coordinate) (not (:git/tag coordinate)))
       ["" (str lib " is pinned to this checkout's HEAD commit, which is not a release tag.")
        "Push that commit before another machine resolves the project."])
     (when-let [public-key (:public-key result)]
       ["" (str "Public key: " public-key)
        "Back the identity up, for example in a password manager. It is not in git"
        "and cannot be recovered."])
     (when-not keygen?
       ["" (str "No age identity is generated. Pass --keygen to generate one at " key-file ".")])
     (when-not (or (:create by-action) (:add by-action))
       ["" "There is nothing to create and nothing to add."])
     (when (and (not result) (:create by-action))
       ["" "Rerun with --apply to create the files listed under \"Would create\"."]))))

(defn init!
  "Print what initializing the project does and, with `:apply?`, do it.

  Takes `:app`, the application name, and optionally `:env` (default \"dev\"),
  `:keygen?`, `:apply?`, and `:root`, the project directory, which defaults to
  the current one. Without `:apply?` nothing is written.
  Returns `:status`, `:preview` or `:applied`, and after applying the `:created`
  paths."
  [{:keys [apply? keygen?] :as opts}]
  (let [proposal (plan opts)
        result (when apply?
                 (when keygen? (age/ensure-installed!))
                 (apply-plan! proposal))]
    (run! println (report-lines proposal keygen? result))
    (if result
      {:status :applied :created (:created result)}
      {:status :preview})))

;;;; Entry Point

(defn- help-lines []
  ["Secrets project initializer"
   ""
   "Usage: -m com.kirahowe.secrets.init --app NAME [options]"
   ""
   "Prints what it would create and what to add to existing files. With --apply"
   "it creates the missing files. It never modifies a file that already exists."
   ""
   "Options:"
   (bbcli/format-opts {:spec init-spec})])

(defn- print-init-error!
  "One line for failure `e`: an `ex-info`'s message, or any other exception's
  class."
  [e]
  (binding [*out* *err*]
    (println (str "secrets init: "
                  (if (instance? clojure.lang.ExceptionInfo e)
                    (ex-message e)
                    (str "Unexpected failure: " (.getName (class e))))))
    (println "Run with --help for usage and options.")))

(defn- exit!
  "Leave the process boundary with exit `code`, returning only when it is 0.
  On the JVM the agent threads `clojure.java.shell` starts keep a finished
  process alive for a minute, so they are shut down here."
  [code]
  (when-not (System/getProperty "babashka.version")
    (shutdown-agents))
  (when (pos? code)
    (System/exit code)))

(defn -main
  "Run the secrets initializer from command-line arguments, as the whole of a
  process. A failure prints one line and exits 1."
  [& args]
  (exit! (try
           (let [opts (parse-args args)]
             (if (:help? opts)
               (run! println (help-lines))
               (init! opts))
             0)
           (catch Exception e
             (print-init-error! e)
             1))))
