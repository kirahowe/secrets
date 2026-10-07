(ns com.kirahowe.secrets.fs
  "Owner-only filesystem primitives for materialized secret data.")

(defn owner-only-temp-file!
  "Create an owner-only delete-on-exit temporary file.

  The file is created with mode 0600 atomically via NIO POSIX attributes, so
  sensitive bytes are never exposed through a default-umask permission window.
  A filesystem which cannot make that guarantee is refused. The generated name
  uses `prefix` and `suffix`. Returns a `java.io.File`; `.deleteOnExit` is a
  backstop, not a substitute for the caller's prompt cleanup."
  [prefix suffix]
  (doto (try
          (.toFile
           (java.nio.file.Files/createTempFile
            prefix suffix
            (into-array java.nio.file.attribute.FileAttribute
                        [(java.nio.file.attribute.PosixFilePermissions/asFileAttribute
                          #{java.nio.file.attribute.PosixFilePermission/OWNER_READ
                            java.nio.file.attribute.PosixFilePermission/OWNER_WRITE})])))
          (catch UnsupportedOperationException e
            (throw (ex-info "Cannot create a private temporary file on this filesystem."
                            {:reason :owner-only-temp-file-unavailable}
                            e))))
    (.deleteOnExit)))

(defn- ->path
  ^java.nio.file.Path [x]
  (if (instance? java.nio.file.Path x)
    x
    (.toPath (java.io.File. (str x)))))

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
      ;; Babashka cannot resolve AtomicMoveNotSupportedException as a class, so
      ;; the exception is recognized by name.
      (if (= "java.nio.file.AtomicMoveNotSupportedException" (.getName (class e)))
        (throw (ex-info (str "This filesystem cannot atomically move a file to " target)
                        {:reason :atomic-move-unsupported
                         :source (str source)
                         :target (str target)}
                        e))
        (throw e)))))
