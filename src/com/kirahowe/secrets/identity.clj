(ns com.kirahowe.secrets.identity
  "Implementation namespace; not part of the public API and may change without notice.

  The age identity a project keeps for itself: the output of a `:key-command`,
  a `:key-file`, or the macOS Keychain item for the app."
  (:require [clojure.string :as str]
            [com.kirahowe.secrets.fs :as fs]
            [com.kirahowe.secrets.keychain :as keychain]))

(defn valid-key-command?
  "True when `argv` is a non-empty vector of non-blank strings."
  [argv]
  (boolean (and (vector? argv) (seq argv)
                (every? #(and (string? %) (not (str/blank? %))) argv))))

(defn- run-key-command!
  "Run `argv`, a `:key-command`, and return its output as the age identity.
  It gets no standard input, so it cannot consume a value piped to the CLI.
  Throws, naming the program and never its output, when `argv` is invalid
  (`:invalid-identity`), the command cannot start or exits nonzero
  (`:key-command-failed`), or it prints nothing (`:invalid-identity`)."
  [argv]
  (when-not (valid-key-command? argv)
    (throw (ex-info (str ":key-command must be a vector of non-blank strings, a program and"
                         " its arguments, such as [\"op\" \"read\" \"op://vault/myapp/key\"].")
                    {:reason :invalid-identity :identity-source :key-command})))
  (let [program (first argv)
        fail (fn [why] (ex-info (str "The :key-command " program " " why)
                                {:reason :key-command-failed
                                 :identity-source :key-command
                                 :program program}))
        {:keys [exit out err]} (try
                                 (fs/sh argv)
                                 (catch java.io.IOException _
                                   (throw (fail "could not be started. Is it installed?"))))]
    (cond
      (not (zero? exit))
      (throw (fail (str "exited " exit (when-not (str/blank? err) (str ": " (str/trim err))))))

      (str/blank? out)
      (throw (ex-info (str "The :key-command " program " printed no age identity.")
                      {:reason :invalid-identity
                       :identity-source :key-command
                       :program program}))

      :else out)))

(defn key-identity
  "Return the identity a project keeps for itself, ignoring the
  SECRETS_AGE_IDENTITY* variables: `:key-command`, else `:key-file`, else on
  macOS the Keychain item for `:app`. A command or the Keychain is read now
  and held as `:identity-contents`. A key file is named by `:identity-file`
  whether or not it exists. With no Keychain item or nothing configured, the
  result has only `:identity-source`."
  [{:keys [key-command key-file app]}]
  (cond
    key-command
    {:identity-contents (run-key-command! key-command) :identity-source :key-command}

    key-file
    {:identity-file (fs/expand-home key-file) :identity-source :configured-key-file}

    (and app (keychain/available?))
    (if-let [contents (keychain/read-key app)]
      {:identity-contents contents :identity-source :keychain}
      {:identity-source :keychain})

    :else
    {:identity-source nil}))
