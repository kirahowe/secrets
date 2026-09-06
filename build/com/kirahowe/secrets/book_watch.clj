(ns com.kirahowe.secrets.book-watch
  "Re-render one chapter per save and reload it in place.

  `bb book:watch` runs [[-main]]. Two processes share the work. Clay evaluates a
  chapter and writes its `.qmd` into the render directory, and `quarto preview`
  turns that `.qmd` into HTML and reloads the browser. Quarto already re-renders
  only the chapter whose source changed and reloads the page the reader is on,
  so the watcher here does the one thing Quarto cannot do on its own: turn a
  saved `.clj` back into its `.qmd`.

  This does not use Clay's own live reload, because it registers the whole-book
  spec for every chapter file. A save then re-evaluates every chapter, re-runs
  Quarto over the whole book, and sends the browser to `index.html`.

  The per-chapter render goes through Clay's `extract-specs` and
  `handle-single-source-spec!` rather than `make!`. `make!` with a `:book`
  config always rewrites `_quarto.yml` from the chapters it was given, so a
  one-chapter call would leave the book with a one-chapter table of contents.
  Computing the spec from the full chapter list also keeps every target path
  identical to a full build, including the preface landing at `index.qmd`. Both
  functions are public in Clay but not part of its documented API; deps.edn pins
  the Clay version, and a bump there should re-check this namespace."
  (:require [babashka.fs :as fs]
            [clojure.string :as str]
            [nextjournal.beholder :as beholder]
            [scicloj.clay.v2.config :as config]
            [scicloj.clay.v2.make :as make]
            [scicloj.kindly.v4.api :as kindly])
  (:import (java.util ArrayList List)
           (java.util.concurrent LinkedBlockingQueue)))

(def ^:private clay-spec
  "Options for every Clay call here. Clay's server stays off, and Clay never runs
  Quarto itself: quarto preview owns the HTML."
  {:show false
   :run-quarto false})

(defn- chapter-specs
  "One Clay spec per chapter in clay.edn, computed as a full build computes them."
  []
  (:single-ns-specs (make/extract-specs (config/config clay-spec) clay-spec)))

(defn- chapter-spec
  "The spec whose source file is `path`, or nil when `path` is not a chapter."
  [path]
  (when (fs/regular-file? path)
    (let [wanted (fs/canonicalize path)]
      (->> (chapter-specs)
           (filter #(= wanted (fs/canonicalize (:full-source-path %))))
           first))))

(defn- render-chapter!
  "Evaluate one chapter and rewrite its `.qmd`, as the full build would."
  [spec]
  (println "book:watch: rendering" (:full-source-path spec))
  (binding [make/*making* true
            kindly/*prefer-kinds* true]
    (make/handle-single-source-spec! spec)))

(def ^:private settle-ms
  "Editors often write a file in two steps. Waiting this long after the first
  event turns the burst of events for one save into one render."
  200)

(defn- next-batch!
  "Block until a path arrives, then return it with whatever else arrived during
  the settle window, without duplicates and in arrival order."
  [^LinkedBlockingQueue queue]
  (let [head (.take queue)
        tail (ArrayList.)]
    (Thread/sleep settle-ms)
    (.drainTo queue tail)
    (distinct (cons head tail))))

(defn- render-loop!
  "Render every path the watcher enqueues, forever. A failing chapter is
  reported and the loop keeps going, so the next save gets another chance."
  [queue]
  (loop []
    (doseq [path (next-batch! queue)]
      (try
        (if-let [spec (chapter-spec path)]
          (render-chapter! spec)
          (println "book:watch: ignoring" path "(not a chapter)"))
        (catch Throwable e
          (println "book:watch: rendering" path "failed")
          (println e))))
    (recur)))

(defn- chapter-source?
  "Whether a changed file is worth rendering: a `.clj` that is not an editor's
  lock or backup file."
  [path]
  (let [file-name (fs/file-name path)]
    (and (= "clj" (fs/extension path))
         (not (str/starts-with? file-name "."))
         (not (str/starts-with? file-name "#")))))

(defn- watch!
  "Watch `dir` recursively and enqueue every created or modified chapter source."
  [dir ^LinkedBlockingQueue queue]
  (beholder/watch (fn [{:keys [type path]}]
                    (when (and (#{:create :modify} type)
                               (chapter-source? path))
                      (.offer queue (str path))))
                  dir))

(defn- quarto-preview!
  "Start `quarto preview` on the render directory, sharing this terminal, and
  stop it when this JVM exits. Extra `args` go to Quarto, so `--no-browser` or
  `--port 4444` work from `bb book:watch`."
  [dir args]
  (let [command (into ["quarto" "preview" dir] args)
        process (-> (ProcessBuilder. ^List command)
                    (.inheritIO)
                    (.start))]
    (.addShutdownHook (Runtime/getRuntime)
                      (Thread. (fn [] (.destroy process))))
    process))

(defn -main
  "Render every chapter once, then keep the `.qmd` files current as chapters are
  saved while quarto preview serves and reloads the result. Exits with Quarto's
  exit code once the preview stops."
  [& args]
  (let [{:keys [base-source-path base-target-path]} (config/config clay-spec)
        queue (LinkedBlockingQueue.)]
    (make/make! clay-spec)
    (watch! base-source-path queue)
    (doto (Thread. #(render-loop! queue) "book-watch-render")
      (.setDaemon true)
      (.start))
    (println "book:watch: watching" base-source-path)
    (System/exit (.waitFor (quarto-preview! base-target-path args)))))
