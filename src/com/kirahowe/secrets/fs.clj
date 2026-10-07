(ns com.kirahowe.secrets.fs
  "Filesystem primitives: private temporary files and atomic replacement.")

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

(defn- try-delete!
  "Delete `file` and return true when it no longer exists."
  [^java.io.File file]
  (try (.delete file) (catch Exception _ nil))
  (not (.exists file)))

(defn with-private-temp-file
  "Create a private temporary file as [[owner-only-temp-file!]] does, call `f`
  with it, delete it, and return what `f` returned.

  The file is deleted whether `f` returns or throws. When the delete fails and
  the file still exists, the operator has to remove it, so the path is
  reported under `:remaining-file`. After a successful `f` that is an
  `ex-info` with `:reason :private-file-remains`. After a failed `f` the
  failure is rethrown as an `ex-info` whose message adds the path, whose data
  is the failure's own data plus `:remaining-file` (and that `:reason` when
  the failure had none), and whose cause is the failure."
  [prefix suffix f]
  (let [file (owner-only-temp-file! prefix suffix)
        path (.getAbsolutePath ^java.io.File file)
        remains (str "A private temporary file could not be deleted. Remove it: " path)
        result (try
                 (f file)
                 (catch Throwable t
                   (throw (if (try-delete! file)
                            t
                            (ex-info (str (ex-message t) "\n" remains)
                                     (merge {:reason :private-file-remains}
                                            (ex-data t)
                                            {:remaining-file path})
                                     t)))))]
    (when-not (try-delete! file)
      (throw (ex-info remains {:reason :private-file-remains :remaining-file path})))
    result))

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
