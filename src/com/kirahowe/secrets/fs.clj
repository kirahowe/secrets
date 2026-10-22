(ns com.kirahowe.secrets.fs
  "Implementation namespace; not part of the public API and may change without notice.

  Filesystem and subprocess primitives: home-relative paths, private temporary
  files, atomic replacement, and running a program."
  (:require [clojure.string :as str]))

(defn- user-home [] (System/getProperty "user.home"))

(defn expand-home
  "Return `path` as a string, with the user's home directory in place of the
  `~` when it is exactly `~` or begins with `~/`. Every other string, such as
  `~bob/x`, is returned unchanged."
  [path]
  (let [s (str path)]
    (if (or (= s "~") (str/starts-with? s "~/"))
      (str (user-home) (subs s 1))
      s)))

(defn sh
  "Run the program `argv` and return `{:exit code :out stdout :err stderr}`.
  It runs in directory `:dir` when one is given, and reads the string `:in` as
  its standard input, or no input at all. Standard error is read on a daemon
  thread, so no thread outlives the call and keeps a JVM from exiting. A
  program that cannot be started throws `java.io.IOException`."
  [argv & [{:keys [dir in]}]]
  (let [process (-> (ProcessBuilder. ^java.util.List (mapv str argv))
                    (cond-> dir (.directory (java.io.File. (str dir))))
                    .start)
        err (promise)]
    (doto (Thread. (fn [] (deliver err (slurp (.getErrorStream process) :encoding "UTF-8"))))
      (.setDaemon true)
      .start)
    (with-open [stdin (.getOutputStream process)]
      (when in
        (.write stdin (.getBytes ^String in "UTF-8"))))
    (let [out (slurp (.getInputStream process) :encoding "UTF-8")]
      {:exit (.waitFor process) :out out :err @err})))

(defn- ->path
  ^java.nio.file.Path [x]
  (if (instance? java.nio.file.Path x)
    x
    (.toPath (java.io.File. (str x)))))

(def ^:private owner-only
  (into-array java.nio.file.attribute.FileAttribute
              [(java.nio.file.attribute.PosixFilePermissions/asFileAttribute
                #{java.nio.file.attribute.PosixFilePermission/OWNER_READ
                  java.nio.file.attribute.PosixFilePermission/OWNER_WRITE})]))

(defn- create-owner-only
  [create]
  (try
    (.toFile ^java.nio.file.Path (create))
    (catch UnsupportedOperationException e
      (throw (ex-info "Cannot create a private temporary file on this filesystem."
                      {:reason :owner-only-temp-file-unavailable}
                      e)))))

(defn owner-only-temp-file!
  "Create a new, empty private file and return it as a `java.io.File`.

  The file is created exclusively, under a generated name that uses `prefix`
  and `suffix`, with mode 0600 as a creation attribute, so its bytes are never
  readable by another user. It lives in `dir` when one is given and in the
  system temporary directory otherwise. A filesystem that cannot create an
  owner-only file throws `ex-info` with
  `:reason :owner-only-temp-file-unavailable`. The caller deletes the file."
  ([prefix suffix]
   (create-owner-only #(java.nio.file.Files/createTempFile prefix suffix owner-only)))
  ([dir prefix suffix]
   (create-owner-only
    #(java.nio.file.Files/createTempFile (->path dir) prefix suffix owner-only))))

(defonce ^:private live-temp-files
  ;; The private temp files in use now. Ctrl-C or a closed terminal ends the
  ;; process inside `with-private-temp-file`, and this hook deletes them then.
  (let [live (atom #{})]
    (.addShutdownHook (Runtime/getRuntime)
                      (Thread. (fn [] (run! #(.delete ^java.io.File %) @live))))
    live))

(defn- try-delete!
  "Delete `file` and return true when it is gone."
  [^java.io.File file]
  (try (.delete file) (catch Exception _ nil))
  (swap! live-temp-files disj file)
  (not (.exists file)))

(defn with-private-temp-file
  "Create a private temporary file as [[owner-only-temp-file!]] does, call `f`
  with it, delete it, and return what `f` returned.

  The file is deleted whether `f` returns or throws, and by a shutdown hook
  when a signal ends the process first. When the delete fails and
  the file still exists, the operator has to remove it, so the path is
  reported under `:remaining-file` in an `ex-info` with `:reason
  :private-file-remains`. After a failed `f` that `ex-info` carries the
  failure's message (its class name, unless it is an `ex-info`) with the path
  added, the failure's other data, and the failure as its cause."
  [prefix suffix f]
  (let [file (owner-only-temp-file! prefix suffix)
        path (.getAbsolutePath ^java.io.File file)
        remains (str "A private temporary file could not be deleted. Remove it: " path)
        result (try
                 (swap! live-temp-files conj file)
                 (f file)
                 (catch Throwable t
                   (throw (if (try-delete! file)
                            t
                            (ex-info (str (if (instance? clojure.lang.ExceptionInfo t)
                                            (ex-message t)
                                            (.getName (class t)))
                                          "\n" remains)
                                     (assoc (ex-data t)
                                            :reason :private-file-remains
                                            :remaining-file path)
                                     t)))))]
    (when-not (try-delete! file)
      (throw (ex-info remains {:reason :private-file-remains :remaining-file path})))
    result))

(defn staging-file
  "Return a `java.io.File` beside `target` under an unpredictable name, for
  staging a public artifact before [[atomic-move!]] puts it in place. Parent
  directories are created. The file itself is not: whoever writes it creates
  it with the ordinary default permissions, so the artifact that replaces
  `target` is as readable as any other new file. The caller deletes it if the
  move does not happen."
  ^java.io.File [target]
  (let [target (.getAbsoluteFile (java.io.File. (str target)))
        parent (.getParentFile target)]
    (.mkdirs parent)
    (java.io.File. parent (str "." (.getName target) "." (java.util.UUID/randomUUID) ".tmp"))))

(defn- atomic-move-unsupported?
  "True when `e` is NIO's AtomicMoveNotSupportedException. The class is
  recognized by name because babashka cannot resolve it."
  [e]
  (= "java.nio.file.AtomicMoveNotSupportedException" (.getName (class e))))

(defn atomic-move!
  "Atomically move the file `source` to `target` and return `target`.

  Each argument is a `Path`, a `File`, or a path string, and both must be on
  one filesystem. The move replaces whatever entry sits at `target`. A symbolic
  link there is replaced as a link and never written through, and `target`
  keeps its previous contents until the move succeeds. There is no copy
  fallback: a filesystem that cannot move atomically throws `ex-info` with
  `:reason :atomic-move-unsupported`, the `:source` and `:target` paths, and
  the NIO exception as its cause. Every other failure propagates unchanged."
  [source target]
  (try
    (java.nio.file.Files/move
     (->path source) (->path target)
     (into-array java.nio.file.CopyOption
                 [java.nio.file.StandardCopyOption/ATOMIC_MOVE
                  java.nio.file.StandardCopyOption/REPLACE_EXISTING]))
    target
    (catch Exception e
      (throw (if (atomic-move-unsupported? e)
               (ex-info (str "This filesystem cannot atomically move a file to " target)
                        {:reason :atomic-move-unsupported
                         :source (str source)
                         :target (str target)}
                        e)
               e)))))
