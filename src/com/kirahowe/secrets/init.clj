(ns com.kirahowe.secrets.init
  "Standalone, one-shot project bootstrapper for `bb secrets`."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.pprint :as pprint]
            [clojure.string :as str]
            [com.kirahowe.secrets.cli :as cli]
            [rewrite-clj.node :as node]
            [rewrite-clj.zip :as z])
  (:import [java.nio.charset StandardCharsets]
           [java.nio.file Files LinkOption OpenOption Path StandardCopyOption]
           [java.nio.file.attribute FileAttribute]))

;;;; Configuration

(def ^:private known-coordinates #{'com.kirahowe/secrets 'io.github.kirahowe/secrets})
(def ^:private default-dependency
  {'io.github.kirahowe/secrets
   {:git/tag "v0.1.0"
    :git/sha "89ded34ce8bd146754cc3ec9971d1ea1fd25da28"}})

(defn parse-args
  "Parse initializer options, including standalone `--help`."
  [args]
  (loop [xs args
         opts {:env "dev" :layout :tracked}]
    (if-let [x (first xs)]
      (case x
        "--app"
        (if-let [v (and (second xs)
                        (not (str/starts-with? (second xs) "--"))
                        (second xs))]
          (recur (nnext xs) (assoc opts :app v))
          (throw (ex-info "--app needs a name" {})))

        "--env"
        (if-let [v (and (second xs)
                        (not (str/starts-with? (second xs) "--"))
                        (second xs))]
          (recur (nnext xs) (assoc opts :env v))
          (throw (ex-info "--env needs a name" {})))

        "--layout"
        (if-let [v (and (second xs)
                        (not (str/starts-with? (second xs) "--"))
                        (second xs))]
          (let [layout (keyword v)]
            (when-not (#{:tracked :disposable} layout)
              (throw (ex-info "--layout must be tracked or disposable" {:layout v})))
            (recur (nnext xs) (assoc opts :layout layout)))
          (throw (ex-info "--layout needs a value" {})))

        "--team" (recur (next xs) (assoc opts :team? true))
        "--keygen" (recur (next xs) (assoc opts :keygen? true))
        "--apply" (recur (next xs) (assoc opts :apply? true))
        "--help" (assoc opts :help? true)
        (throw (ex-info (str "Unknown option: " x) {:argument x})))
      (do
        (when-not (and (string? (:app opts)) (not (str/blank? (:app opts))))
          (throw (ex-info "--app <name> is required" {})))
        opts))))

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

;;;; bb.edn Integration

(defn- parse-bb [source]
  (try
    (let [loc (z/of-string source)]
      (when-not (z/map? loc)
        (throw (ex-info "bb.edn must be a top-level map" {})))
      [loc (z/sexpr loc)])
    (catch clojure.lang.ExceptionInfo e
      (throw e))
    (catch Exception e
      (throw (ex-info "Could not read bb.edn" {:cause (.getMessage e)} e)))))

(defn- append-entry [map-loc k v]
  ;; Node-level editing keeps every existing comment and reader form intact.
  (reduce z/append-child
          map-loc
          [(node/newline-node "\n")
           (node/whitespace-node "  ")
           (node/coerce k)
           (node/whitespace-node " ")
           (node/coerce v)]))

(defn- add-root-entry [source k v]
  (let [[loc _] (parse-bb source)]
    (z/root-string (append-entry loc k v))))

(defn- add-nested-entry [source parent k v]
  (let [[loc _] (parse-bb source)
        key-loc (z/find-value loc z/next parent)
        map-loc (some-> key-loc z/right)]
    (when-not (z/map? map-loc)
      (throw (ex-info (str parent " must be a map") {:field parent})))
    (z/root-string (append-entry map-loc k v))))

(defn merge-bb-edn
  "Merge this library and generated `secrets` task without reformatting existing
  bb.edn content. Known library coordinates are retained; task conflicts fail."
  [source config]
  (let [original (or source "{}\n")
        [_ bb] (parse-bb original)
        deps (get bb :deps {})
        tasks (get bb :tasks {})
        _ (when-not (map? deps)
            (throw (ex-info ":deps must be a map" {})))
        _ (when-not (map? tasks)
            (throw (ex-info ":tasks must be a map" {})))
        known-dependency (some #(when (contains? deps %) %) known-coordinates)
        desired-task (task-spec config)
        _ (when (and (contains? tasks 'secrets)
                     (not= (get tasks 'secrets) desired-task))
            (throw (ex-info "bb.edn already has a conflicting secrets task"
                            {:task 'secrets})))
        add-dependency? (nil? known-dependency)
        source-with-dependency
        (if add-dependency?
          (if (contains? bb :deps)
            (add-nested-entry original
                              :deps
                              (ffirst default-dependency)
                              (val (first default-dependency)))
            (add-root-entry original :deps default-dependency))
          original)
        [_ parsed-source-with-dependency] (parse-bb source-with-dependency)
        add-task? (not (contains? tasks 'secrets))
        final-source
        (if add-task?
          (if (contains? parsed-source-with-dependency :tasks)
            (add-nested-entry source-with-dependency :tasks 'secrets desired-task)
            (add-root-entry source-with-dependency :tasks {'secrets desired-task}))
          source-with-dependency)]
    {:content final-source
     :changed? (not= original final-source)
     :dependency (or known-dependency (ffirst default-dependency))
     :added-dependency? add-dependency?
     :added-task? add-task?}))

;;;; Change Planning

(defn- target-path! [root rel]
  (let [root (.normalize (.toAbsolutePath (.toPath (io/file root))))
        target (.normalize (.toAbsolutePath (.resolve root rel)))]
    (when-not (.startsWith target root)
      (throw (ex-info "Path escapes project" {:path rel})))
    ;; A safe leaf below a symlinked directory is not a safe project artifact:
    ;; writes would escape the consumer checkout. Check every relative segment.
    (loop [parent root
           parts (seq (iterator-seq (.iterator (.relativize root target))))]
      (when-let [part (first parts)]
        (let [child (.resolve parent ^Path part)]
          (when (Files/isSymbolicLink child)
            (throw (ex-info "Refusing a path below a symbolic link"
                            {:path rel :link (str child)})))
          (recur child (next parts)))))
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
  (try
    (let [value (edn/read-string (slurp file))]
      (when-not (map? value)
        (throw (ex-info "Existing secrets template must contain an EDN map"
                        {:path path})))
      value)
    (catch clojure.lang.ExceptionInfo e
      (throw e))
    (catch Exception e
      (throw (ex-info "Existing secrets template is not valid EDN"
                      {:path path :cause (.getMessage e)}
                      e)))))

(defn proposed-changes
  "Plan all writes and run the CLI's canonical collision validation first."
  [{:keys [root layout team?] :as opts}]
  (let [root (or root ".")
        config (proposed-config opts)
        normalized (cli/normalize-config config)
        bb-file (io/file root "bb.edn")
        merged (merge-bb-edn (when (.exists bb-file) (slurp bb-file)) config)
        raw (into
             [{:path "bb.edn"
               :content (:content merged)
               :replace? true}]
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
        (when (and (Files/exists target (make-array LinkOption 0))
                   (not replace?)
                   (not preserve?))
          (throw (ex-info "Refusing to overwrite existing initializer artifact"
                          {:path path})))))
    {:config config
     :normalized-config normalized
     :changes (->> raw
                   (map (fn [{:keys [path] :as entry}]
                          (assoc entry
                                 :old
                                 (when (.exists (io/file root path))
                                   (slurp (io/file root path))))))
                   (filter (fn [{:keys [content old replace? preserve?]}]
                             (and (not preserve?)
                                  (or (not replace?) (not= content old)))))
                   vec)}))

;;;; Preview and Application

(defn- print-content-diff! [{:keys [path old content]}]
  (println (str "--- " (if (nil? old) "/dev/null" (str "a/" path))))
  (println (str "+++ b/" path))
  ;; A complete line-oriented replacement is deliberately simple, predictable,
  ;; and dependency-free. It still makes every proposed byte visible before
  ;; mutation, unlike a filename-only preview.
  (when (some? old)
    (doseq [line (str/split-lines old)]
      (println (str "-" line))))
  (doseq [line (str/split-lines content)]
    (println (str "+" line))))

(defn print-preview!
  "Print the proposed initializer changes."
  [{:keys [changes]}]
  (println "Secrets initializer preview:")
  (if (seq changes)
    (doseq [change changes]
      (print-content-diff! change))
    (println " no project changes are needed."))
  (println " Private identities are never created unless --keygen is supplied."))

(defn- atomic-write! [^Path target content]
  (let [parent (.getParent target)
        _ (Files/createDirectories parent (make-array FileAttribute 0))
        tmp (Files/createTempFile
             parent
             ".secrets-init-"
             ".tmp"
             (make-array FileAttribute 0))]
    (try
      (Files/write tmp
                   (.getBytes content StandardCharsets/UTF_8)
                   (make-array OpenOption 0))
      (try
        (Files/move
         tmp
         target
         (into-array
          StandardCopyOption
          [StandardCopyOption/ATOMIC_MOVE StandardCopyOption/REPLACE_EXISTING]))
        (catch Exception _
          (Files/move
           tmp
           target
           (into-array StandardCopyOption [StandardCopyOption/REPLACE_EXISTING]))))
      (finally
        (Files/deleteIfExists tmp)))))

(defn- apply-changes! [root changes]
  (let [old (into {}
                  (for [{:keys [path]} changes
                        :let [target (target-path! root path)]]
                    [path
                     (when (Files/exists target (make-array LinkOption 0))
                       (Files/readAllBytes target))]))]
    (try
      (doseq [{:keys [path content]} changes]
        (atomic-write! (target-path! root path) content))
      (catch Exception e
        (doseq [[path bytes] old]
          (let [target (target-path! root path)]
            (if bytes
              (atomic-write! target (String. ^bytes bytes StandardCharsets/UTF_8))
              (Files/deleteIfExists target))))
        (throw (ex-info "Initializer failed; previous project files were restored." {} e))))))

(defn- choice! [{:keys [choice input]}]
  (or choice
      (do
        (println "Choose: [a]pply, [m]anual, [c]ancel")
        (let [read! (or input read-line)]
          (case (some-> (read!) str/trim str/lower-case)
            ("a" "apply") :apply
            ("m" "manual") :manual
            :cancel)))))

(defn init!
  "Preview and optionally apply. `:root`, `:tty?`, `:choice`, and `:input` are
  injectable for tests. A non-TTY caller must set :apply? to mutate files."
  [opts]
  (let [opts (merge {:root "."
                     :tty? (some? (System/console))
                     :env "dev"
                     :layout :tracked}
                    opts)
        proposal (assoc (proposed-changes opts) :root (:root opts))
        _ (print-preview! proposal)
        selected (cond
                   (:apply? opts) :apply
                   (:tty? opts) (choice! opts)
                   :else :preview)]
    (case selected
      :apply
      (do
        (apply-changes! (:root opts) (:changes proposal))
        (when (:keygen? opts)
          (cli/keygen! (:normalized-config proposal) (:env opts)))
        {:status :applied :changes (:changes proposal)})

      :manual
      (do
        (println "Manual integration (no files changed):")
        (binding [*print-namespace-maps* false
                  *print-length* nil
                  *print-level* nil]
          (pprint/pprint {:deps default-dependency
                          :tasks {'secrets (task-spec (:config proposal))}}))
        {:status :manual :changes (:changes proposal)})

      :cancel
      {:status :cancelled :changes (:changes proposal)}

      {:status :preview :changes (:changes proposal)})))

;;;; Entry Point

(defn -main
  "Run the secrets initializer from command-line arguments."
  [& args]
  (try
    (let [opts (parse-args args)]
      (if (:help? opts)
        (println
         (str "Usage: bb -Sdeps '<coordinate>' -m com.kirahowe.secrets.init --app NAME "
              "[--env dev] [--layout tracked|disposable] [--team] [--keygen] [--apply]"))
        (init! opts)))
    (catch clojure.lang.ExceptionInfo e
      (binding [*out* *err*]
        (println "secrets init:" (ex-message e)))
      (System/exit 1))))
