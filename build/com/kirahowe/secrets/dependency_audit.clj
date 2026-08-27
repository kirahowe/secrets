(ns com.kirahowe.secrets.dependency-audit
  "Reproducibly audits every resolved dependency graph with OSV-Scanner.

  The audit resolves each configured alias through the repository's pinned
  Clojure CLI, writes exact Maven coordinates and every dependency path reported
  by tools.deps, and submits that exact set to a checksum-verified OSV-Scanner.
  There is deliberately no ignore list: any package match makes the run fail.

  This namespace lives under `build/` and runs from `:audit`'s replaced
  classpath, so the audit implementation and scanner never enter the library,
  build, book, or credential-bearing deploy graph."
  (:require [clojure.data.json :as json]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.java.shell :as sh]
            [clojure.string :as str])
  (:import (java.nio.file Files StandardCopyOption)
           (java.security MessageDigest)))

(def ^:private config-file ".github/dependency-audit.edn")
(def ^:private output-root "target/dependency-audit")

(defn- read-config
  "Returns the dependency audit configuration."
  []
  (edn/read-string (slurp config-file)))

(defn- platform-key
  "Returns the scanner asset key for the current JVM platform."
  []
  (let [os-name (str/lower-case (System/getProperty "os.name"))
        os (cond
             (str/starts-with? os-name "mac") "darwin"
             (str/starts-with? os-name "linux") "linux"
             (str/starts-with? os-name "windows") "windows"
             :else (throw (ex-info "Unsupported OS for dependency audit"
                                   {:os os-name})))
        arch-name (str/lower-case (System/getProperty "os.arch"))
        arch (case arch-name
               ("aarch64" "arm64") "arm64"
               ("amd64" "x86_64") "amd64"
               (throw (ex-info "Unsupported architecture for dependency audit"
                               {:architecture arch-name})))]
    (str os "-" arch)))

(defn- sha256
  "Returns the lowercase SHA-256 digest of `file`."
  [file]
  (let [digest (MessageDigest/getInstance "SHA-256")]
    (with-open [input (io/input-stream file)]
      (let [buffer (byte-array 65536)]
        (loop []
          (let [n (.read input buffer)]
            (when-not (neg? n)
              (.update digest buffer 0 n)
              (recur))))))
    (apply str (map #(format "%02x" (bit-and 0xff %)) (.digest digest)))))

(defn- download!
  "Downloads `url` to `file` through a temporary file."
  [url file]
  (let [temporary (io/file (str file ".download"))]
    (.mkdirs (.getParentFile file))
    (try
      (with-open [input (io/input-stream url)
                  output (io/output-stream temporary)]
        (io/copy input output))
      (Files/move (.toPath temporary) (.toPath file)
                  (into-array StandardCopyOption
                              [StandardCopyOption/REPLACE_EXISTING]))
      (finally
        (Files/deleteIfExists (.toPath temporary))))))

(defn- ensure-scanner!
  "Returns the checksum-verified pinned scanner executable, downloading as needed."
  [{:keys [version base-url assets]}]
  (let [platform (platform-key)
        asset (get assets platform)
        file (:file asset)
        expected-sha (:sha256 asset)]
    (when-not asset
      (throw (ex-info "No pinned scanner asset for this platform"
                      {:platform platform})))
    (let [scanner (io/file output-root "bin" file)]
      (when-not (and (.isFile scanner) (= expected-sha (sha256 scanner)))
        (println "Downloading OSV-Scanner" version "for" platform)
        (download! (str base-url file) scanner))
      (when-not (= expected-sha (sha256 scanner))
        (throw (ex-info "OSV-Scanner checksum mismatch"
                        {:platform platform :version version})))
      (when-not (.setExecutable scanner true)
        (throw (ex-info "Could not make OSV-Scanner executable"
                        {:path (str scanner)})))
      (str scanner))))

(defn- run-command!
  "Runs `command` and returns stdout, throwing a concise error on failure."
  [description command]
  (let [{:keys [exit out err]} (apply sh/sh command)]
    (when (seq err)
      (binding [*out* *err*]
        (print err)))
    (when-not (zero? exit)
      (throw (ex-info (str description " failed")
                      {:command (first command) :exit exit})))
    out))

(defn- deps-command
  "Returns a Clojure CLI dependency command for `operation` and `aliases`."
  [operation aliases]
  (cond-> ["clojure" "-X:deps" operation ":format" ":edn"]
    (seq aliases) (into [":aliases" (pr-str aliases)])))

(defn graph-record
  "Returns deterministic exact coordinates and dependency paths from `libs`.

  `libs` is the EDN map printed by `clojure -X:deps list :format :edn`. Every
  library must be a Maven coordinate with an exact `:mvn/version`; an unknown
  coordinate kind fails instead of disappearing from the advisory scan."
  [libs]
  (let [unsupported (keep (fn [[lib coordinate]]
                            (when-not (:mvn/version coordinate) lib))
                          libs)]
    (when (seq unsupported)
      (throw (ex-info "Dependency graph contains coordinates OSV cannot scan"
                      {:libraries (vec (sort-by str unsupported))})))
    {:packages
     (mapv (fn [[lib {:keys [mvn/version parents]}]]
             {:coordinate [(str lib) version]
              :dependency-paths
              (->> parents
                   (map #(mapv str (conj % lib)))
                   (sort-by pr-str)
                   vec)})
           (sort-by (comp str key) libs))}))

(defn scanner-input
  "Returns OSV-Scanner custom-lockfile data for exact packages in `record`."
  [record]
  {:results
   [{:packages
     (mapv (fn [{[name version] :coordinate}]
             {:package {:name (str/replace name "/" ":")
                        :version version
                        :ecosystem "Maven"}})
           (:packages record))}]})

(defn- write-edn!
  "Writes deterministic `value` as EDN to `file`."
  [file value]
  (spit file (str (pr-str value) "\n")))

(defn- audit-graph!
  "Resolves and scans one configured dependency `graph`."
  [scanner {:keys [name aliases]}]
  (let [directory (io/file output-root name)
        list-output (run-command! (str "Resolving " name " coordinates")
                                  (deps-command "list" aliases))
        record (graph-record (edn/read-string list-output))
        tree-output (run-command! (str "Resolving " name " dependency tree")
                                  (deps-command "tree" aliases))
        coordinates (io/file directory "coordinates.edn")
        tree (io/file directory "tree.edn")
        lockfile (io/file directory "osv-scanner.json")
        result (io/file directory "osv-result.json")]
    (.mkdirs directory)
    (write-edn! coordinates record)
    (spit tree tree-output)
    (spit lockfile (json/write-str (scanner-input record)))
    (run-command!
     (str "OSV scan for " name)
     [scanner "scan" "source"
      (str "--lockfile=osv-scanner:" (.getCanonicalPath lockfile))
      "--format=json" "--all-packages"
      (str "--output-file=" (.getCanonicalPath result))])
    (println "Audited" name "graph:" (count (:packages record))
             "exact Maven coordinates; paths in" (str coordinates))))

(defn- selected-graphs
  "Returns configured graphs named by `requested`, or every graph when empty."
  [graphs requested]
  (if (seq requested)
    (let [by-name (into {} (map (juxt :name identity) graphs))
          missing (remove by-name requested)]
      (when (seq missing)
        (throw (ex-info "Unknown dependency graph"
                        {:graphs (vec missing)})))
      (mapv by-name requested))
    graphs))

(defn -main
  "Audits every configured graph, or only graph names in `requested`.

  All selected graphs are attempted so one advisory does not hide matches in a
  later alias. The process exits unsuccessfully after the last graph if any
  resolution or scan failed."
  [& requested]
  (let [{:keys [scanner graphs]} (read-config)
        executable (ensure-scanner! scanner)
        version-output (run-command! "Checking OSV-Scanner version"
                                     [executable "--version"])]
    (when-not (str/includes? version-output (:version scanner))
      (throw (ex-info "OSV-Scanner reported an unexpected version"
                      {:expected (:version scanner)})))
    (let [failures (reduce (fn [found graph]
                             (try
                               (audit-graph! executable graph)
                               found
                               (catch Exception exception
                                 (binding [*out* *err*]
                                   (println "Dependency audit failed for"
                                            (:name graph) "-"
                                            (ex-message exception)))
                                 (conj found (:name graph)))))
                           []
                           (selected-graphs graphs requested))]
      (when (seq failures)
        (throw (ex-info "Dependency advisory audit failed"
                        {:graphs failures}))))))
