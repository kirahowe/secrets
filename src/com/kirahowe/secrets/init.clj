(ns com.kirahowe.secrets.init
  "One-shot project bootstrapper for `bb secrets`. It creates the files a new
  setup needs and never modifies an existing one; for an existing `bb.edn` or
  `deps.edn` it prints what to add."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.pprint :as pprint]
            [clojure.string :as str]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.fs :as fs]
            [com.kirahowe.secrets.keychain :as keychain]
            [com.kirahowe.secrets.manifest :as manifest]
            [com.kirahowe.secrets.safe-edn :as safe-edn]
            [com.kirahowe.secrets.store :as store])
  (:import [java.nio.charset StandardCharsets]
           [java.nio.file FileAlreadyExistsException Files LinkOption OpenOption Path
            StandardOpenOption]
           [java.nio.file.attribute FileAttribute]))

;;;; The library's own coordinate

(def ^:private coordinate-resource
  "The library's coordinates, shared with the release guards, so what the
  initializer scaffolds is what a release checks."
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
  "Runs `git` with the argv `args` in `dir`, returning its `:exit`, `:out`, and
  `:err`. A `git` that cannot be started answers like one that failed, so the
  caller sees one shape."
  [dir & args]
  (try
    (fs/sh (cons "git" args) {:dir dir})
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
  "The `{lib coordinate}` entry a project's `:deps` needs to resolve the
  running library, given the `url` its coordinate resource was loaded from.

  A `file:` URL is a source checkout, and the coordinate is its `HEAD`:
  `{:git/tag \"v<version>\" :git/sha <commit>}` when the release tag names it,
  `{:git/sha <commit>}` otherwise. tools.deps wants the commit beside a tag and
  no commit can record its own hash, so git supplies it. A checkout under
  `~/.gitlibs` is a worktree and answers the same way. Any other URL is a Maven
  jar, built from the version the resource declares.

  `run` executes a git argv in a directory and returns what [[git]] does. It is
  a parameter so tests need no repository."
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

(def ^:private options
  "Every option: its flags, the key it sets, the name of the value it takes
  (nil for a switch), and its help line."
  [[#{"--app"} :app "NAME" "Application name (required)"]
   [#{"--env"} :env "NAME" "Environment name (default: dev)"]
   [#{"--keygen"} :keygen? nil "Also generate an age identity in the macOS Keychain"]
   [#{"--apply"} :apply? nil "Create the files instead of previewing"]
   [#{"-h" "--help"} :help? nil "Show this help"]])

(def ^:private plain-name #"[A-Za-z][A-Za-z0-9._-]*")

(defn- require-plain-name!
  "Reject an app or environment name that is not a plain identifier. The app
  name becomes a Keychain account and a bb.edn symbol, and the environment name
  a keyword, so both must read back as written. The value is not echoed."
  [option value]
  (when-not (and (string? value) (re-matches plain-name value))
    (throw (ex-info (str option " must be a plain name: letters, digits, dots, hyphens, or "
                         "underscores, starting with a letter")
                    {:reason :usage :option option}))))

(defn- parse-args
  "Parse initializer options, including standalone `-h` and `--help`. The names
  are checked when [[proposed-config]] uses them. An argument that is not an
  option is refused without being repeated."
  [args]
  (let [usage! #(throw (ex-info % {:reason :usage}))
        opts (loop [opts {:env "dev"}
                    [arg & more] args]
               (if (nil? arg)
                 opts
                 (let [[_ k value-name] (some #(when (contains? (first %) arg) %) options)]
                   (cond
                     (nil? k)
                     (usage! "Unknown option or argument.")

                     (nil? value-name)
                     (recur (assoc opts k true) more)

                     (or (empty? more) (str/starts-with? (first more) "-"))
                     (usage! (str "Missing value: " arg " " value-name))

                     :else
                     (recur (assoc opts k (first more)) (rest more))))))]
    (when-not (or (:help? opts) (:app opts))
      (usage! "--app <name> is required"))
    opts))

;;;; What a project needs

(defn- proposed-config
  "The secrets config a new project starts with: one environment whose
  ciphertext is `secrets/secrets.edn.age`. Throws when `app` or `env` is not a
  plain name."
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
  classpath: `{myapp/myapp {:local/root \".\"}}`, keyed by the app name."
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
  (-> (manifest/print-whole #(with-out-str (pprint/pprint x)))
      str/trim-newline
      (str/replace "," "")))

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
  entry. An existing file is left alone and the entries it lacks become
  additions to print. `:entries` holds the entries the plan creates or prints."
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

  Returns `:root`, the proposed `:config`, and `:files`, one map per entry with
  an `:action`. A file entry has a `:path`, relative to `:root` unless absolute;
  a Keychain entry has a `:keychain-app` instead. The actions:

  - `:create` for a file that does not exist, with its `:content`. The identity
    `--keygen` asks for is an entry with `:keychain-app`, the app whose macOS
    Keychain item it becomes, and no `:path` or `:content`.
  - `:exists` for a file that is already there and needs nothing.
  - `:add` for an existing file that lacks something, with `:additions`, each
    the top-level key to put it `:under` and the `:text` to put there.

  Without a deps.edn, bb.edn declares the library. With one, deps.edn declares
  it and bb.edn reaches it through a `:local/root \".\"` dependency, so the JVM
  application and the Babashka task load the same version. A bb.edn that
  already declares the library keeps doing so. `:dependency` is the library's
  `{lib coordinate}` entry when the plan creates or prints it."
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
        files (cond-> (filterv some? [deps-edn
                                      bb-edn
                                      (plain-file root template-path template-content)])
                keygen? (conj (if (keychain/has-key? app)
                                {:keychain-app app :action :exists}
                                {:keychain-app app :action :create})))]
    (cond-> {:root root :config config :files files}
      (some #{library} (mapcat :entries files)) (assoc :dependency @default-dependency))))

;;;; Applying

(def ^:private create-new
  ;; O_CREAT|O_EXCL: the open fails on any existing entry, a symbolic link
  ;; included, so a file that appeared after the plan was made is not replaced.
  (into-array OpenOption [StandardOpenOption/CREATE_NEW StandardOpenOption/WRITE]))

(defn- entry-label
  "The text that names a plan entry, a file or a Keychain item, in output and
  errors."
  [{:keys [path keychain-app]}]
  (if keychain-app
    (str "macOS Keychain item " keychain/service ", account " keychain-app)
    path))

(defn- stop!
  "Throw because creating `path` failed, with `message` and then the files
  `created` before it, so a run that stops part-way says what it left. The
  data is that of `cause` with `:path`, `:created`, and `reason` when given."
  [message reason path created cause]
  (throw (ex-info (str message
                       (when (seq created)
                         (str "\nCreated before stopping: " (str/join ", " created) ".")))
                  (cond-> (assoc (ex-data cause) :path (str path) :created created)
                    reason (assoc :reason reason))
                  cause)))

(defn- apply-plan!
  "Create every `:create` entry of `plan`, in order, and return `:created`
  (the paths written, and the Keychain item's label) and `:public-key` when
  an identity was generated.

  Files are only created. Something already at a path appeared after the plan
  was made, so the run stops and leaves it. Every failure is an `ex-info` naming
  the `:path` and, in its data and message, the files `:created` before it. The
  identity is generated in memory and goes straight into the Keychain, never to
  disk."
  [{:keys [root files]}]
  (reduce
   (fn [{:keys [created] :as result} {:keys [path content keychain-app] :as entry}]
     (let [label (entry-label entry)
           exists (str label " already exists, so the initializer did not write it.")]
       (try
         (if keychain-app
           (do (when (keychain/has-key? keychain-app)
                 (stop! exists :file-exists label created nil))
               (let [{:keys [identity-contents public-key]} (age/generate)]
                 (keychain/store-key! keychain-app identity-contents)
                 (-> result
                     (assoc :public-key public-key)
                     (update :created conj label))))
           (let [file (target root path)]
             (when-let [parent (.getParent file)]
               (Files/createDirectories parent (make-array FileAttribute 0)))
             (Files/write file (.getBytes ^String content StandardCharsets/UTF_8) create-new)
             (update result :created conj label)))
         (catch FileAlreadyExistsException e
           (stop! exists :file-exists label created e))
         (catch Exception e
           (if (:created (ex-data e))
             (throw e)
             (stop! (store/failure-message e) nil label created e))))))
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
  [{:keys [files dependency config]} keygen? result]
  (let [by-action (group-by :action files)
        [lib coordinate] (first dependency)]
    (concat
     [(if result
        "Secrets initializer"
        "Secrets initializer preview. Nothing is written without --apply.")]
     (section (if result "Created:" "Would create:")
              (mapcat (fn [{:keys [content keychain-app] :as entry}]
                        (cons (str "  " (entry-label entry))
                              (cond
                                keychain-app ["      a new age identity, never written to disk"]
                                result nil
                                :else (indented 6 content))))
                      (:create by-action)))
     (section "Already there, left as they are:"
              (map #(str "  " (entry-label %)) (:exists by-action)))
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
        "and cannot be recovered. This prints it:"
        (str "  security find-generic-password -s " keychain/service " -a "
             (store/shell-quote (:app config)) " -w")])
     (when-not keygen?
       ["" (if (keychain/available?)
             "No age identity is generated. Pass --keygen to store one in the macOS Keychain."
             (str "No age identity is generated. Without the macOS Keychain, add :key-command"
                  " (a password manager command that prints the key) or :key-file to the"
                  " environment."))])
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
  paths and Keychain item label."
  [{:keys [apply? keygen?] :as opts}]
  (when (and keygen? (not (keychain/available?)))
    (throw (ex-info (str "--keygen stores the key in the macOS Keychain, which is not available"
                         " here. Store a key with your password manager and add :key-command"
                         " to the environment.")
                    {:reason :usage})))
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
   (str/join "\n" (for [[flags _ value-name text] options]
                    (format "  %-13s %s"
                            (str (str/join ", " (sort-by count flags))
                                 (when value-name (str " " value-name)))
                            text)))])

(defn- print-init-error!
  "Print failure `e` as the CLI prints one: `store/failure-message`."
  [e]
  (binding [*out* *err*]
    (println (str "secrets init: " (store/failure-message e)))
    (println "Run with --help for usage and options.")))

(defn -main
  "Run the secrets initializer from command-line arguments, as the whole of a
  process. A failure prints one line and exits 1."
  [& args]
  (store/exit! (try
                 (let [opts (parse-args args)]
                   (if (:help? opts)
                     (run! println (help-lines))
                     (init! opts))
                   0)
                 (catch Exception e
                   (print-init-error! e)
                   1))))
