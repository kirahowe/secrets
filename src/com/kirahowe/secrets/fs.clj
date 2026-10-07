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
