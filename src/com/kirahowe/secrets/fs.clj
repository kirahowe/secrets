(ns com.kirahowe.secrets.fs
  "Owner-only filesystem primitives for materialized secret data.")

(defn owner-only-temp-file!
  "Create an owner-only delete-on-exit temporary file.

  The file is created with mode 0600 atomically via NIO POSIX attributes, so
  sensitive bytes are never exposed through a default-umask permission window.
  Filesystems without POSIX permissions fall back to create-then-chmod. The
  generated name uses `prefix` and `suffix`. Returns a `java.io.File`;
  `.deleteOnExit` is a backstop, not a substitute for the caller's prompt
  cleanup."
  [prefix suffix]
  (doto (try
          (.toFile
           (java.nio.file.Files/createTempFile
            prefix suffix
            (into-array java.nio.file.attribute.FileAttribute
                        [(java.nio.file.attribute.PosixFilePermissions/asFileAttribute
                          #{java.nio.file.attribute.PosixFilePermission/OWNER_READ
                            java.nio.file.attribute.PosixFilePermission/OWNER_WRITE})])))
          (catch UnsupportedOperationException _
            (doto (java.io.File/createTempFile prefix suffix)
              (.setReadable false false) (.setReadable true true)
              (.setWritable false false) (.setWritable true true))))
    (.deleteOnExit)))
