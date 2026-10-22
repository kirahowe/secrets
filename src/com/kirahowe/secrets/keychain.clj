(ns com.kirahowe.secrets.keychain
  "Implementation namespace; not part of the public API and may change without notice.

  The macOS login Keychain, the default home of an app's age identity on a
  Mac. Each app's key is one generic password item whose service is
  `com.kirahowe.secrets` and whose account is the app name. The key is read
  and written through `/usr/bin/security`, which creates the item and so can
  read it back without a prompt. The key goes to `security` on its standard
  input and never appears in a process's arguments or on disk."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [com.kirahowe.secrets.fs :as fs]))

(def service
  "The service name of every item this library stores."
  "com.kirahowe.secrets")

(def ^:private security "/usr/bin/security")

(def ^:private item-not-found
  "The exit status `security` gives when no item matches."
  44)

(defn available?
  "True on macOS, where `/usr/bin/security` can reach the login Keychain."
  []
  (and (str/starts-with? (str (System/getProperty "os.name")) "Mac")
       (.canExecute (io/file security))))

(defn- failure
  [message app {:keys [exit err]}]
  (ex-info (str message " (security exited " exit
                (when-not (str/blank? err) (str ": " (str/trim err))) ")")
           {:reason :keychain-failed :service service :account app :exit exit}))

(defn read-key
  "Return the age identity stored for `app`, or nil when there is none."
  [app]
  (let [{:keys [exit out] :as result}
        (fs/sh [security "find-generic-password" "-s" service "-a" app "-w"])]
    (cond
      (zero? exit) (not-empty (str/trim out))
      (= item-not-found exit) nil
      :else (throw (failure (str "Could not read the age identity for " app
                                 " from the macOS Keychain")
                            app result)))))

(defn has-key?
  "True when the Keychain holds an item for `app`, false when it holds none.
  Reads no secret. Any other failure, such as a locked Keychain, throws rather
  than reading as absence."
  [app]
  (let [{:keys [exit] :as result}
        (fs/sh [security "find-generic-password" "-s" service "-a" app])]
    (cond
      (zero? exit) true
      (= item-not-found exit) false
      :else (throw (failure (str "Could not look up the age identity for " app
                                 " in the macOS Keychain")
                            app result)))))

(defn- quoted
  "`s` as one argument of a `security -i` command line."
  [s]
  (when (re-find #"[\"\\\n\r]" s)
    (throw (ex-info (str "The app name " (pr-str s) " cannot name a Keychain item:"
                         " it holds a quote, a backslash, or a line break.")
                    {:reason :invalid-config :account s})))
  (str "\"" s "\""))

(defn store-key!
  "Store `contents`, an age secret key, as the Keychain item for `app`,
  replacing any item already there, and read it back to check it arrived.

  `security add-generic-password` takes the password only as an argument, so
  the command goes to `security -i` on its standard input instead."
  [app contents]
  (let [line (str/join " " ["add-generic-password" "-U"
                            "-s" (quoted service) "-a" (quoted app)
                            "-l" (quoted (str app " age identity (" service ")"))
                            "-w" (quoted contents)])
        result (fs/sh [security "-i"] {:in (str line "\n")})]
    (when-not (and (zero? (:exit result)) (= contents (read-key app)))
      (throw (failure (str "Could not store the age identity for " app
                           " in the macOS Keychain")
                      app result)))
    contents))
