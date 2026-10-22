(ns com.kirahowe.secrets.test-env
  "The one seam through which tests replace the environment the runtime reads,
  and the helpers the property suites share."
  (:require [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.keychain :as keychain]))

(declare keychain-redefs)

(defn getenv-redefs
  "Return a `with-redefs-fn` binding map that makes `environment`, a map of
  variable name to value, the whole environment the runtime sees. A variable
  absent from the map is unset. Only the raw read is replaced, so the blank
  check and everything else in identity resolution still runs. The macOS
  Keychain is part of that environment, and it is empty."
  [environment]
  (merge {#'secrets/getenv #(get environment %)}
         (keychain-redefs (atom {}))))

(defn thrown
  "The `Exception` that calling `f` throws, or nil when it returns."
  [f]
  (try (f) nil (catch Exception e e)))

(defn rendered
  "Everything a reader of logs could see of `e`: the message and data of the
  throwable, of each cause, and of each suppressed throwable."
  [e]
  (let [walk (fn walk [t]
               (when t
                 (cons (str (ex-message t) " " (pr-str (ex-data t)))
                       (concat (walk (ex-cause t))
                               (mapcat walk (.getSuppressed ^Throwable t))))))]
    (apply str (interpose "\n" (walk e)))))

(defn permission-names
  "The POSIX permissions of `path` itself, as names such as \"OWNER_READ\"."
  [path]
  (set (map str (java.nio.file.Files/getPosixFilePermissions
                 (.toPath (java.io.File. (str path)))
                 (into-array java.nio.file.LinkOption [])))))

(def owner-only-names #{"OWNER_READ" "OWNER_WRITE"})

(defn keychain-redefs
  "Return a `with-redefs-fn` binding map that replaces the macOS Keychain with
  `items`, an atom of app name to stored key, available on every platform.
  Tests never reach the real login Keychain."
  [items]
  {#'keychain/available? (constantly true)
   #'keychain/read-key #(get @items %)
   #'keychain/has-key? #(contains? @items %)
   #'keychain/store-key! (fn [app contents] (swap! items assoc app contents) contents)})

(defn with-fake-keychain
  "A fixture that runs each test against an empty fake Keychain."
  [f]
  (with-redefs-fn (keychain-redefs (atom {})) f))
