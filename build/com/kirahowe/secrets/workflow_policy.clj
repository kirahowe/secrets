(ns com.kirahowe.secrets.workflow-policy
  "The rule that every executable dependency a workflow names is immutable.

  A GitHub Actions workflow runs third-party code chosen by its `uses:` and
  `image:` references. A reference to a tag or a branch resolves to whatever that
  name points at when the job starts, so upstream movement can change what a
  privileged job executes with no reviewed change here (CWE-829, CWE-494). These
  functions decide whether a workflow's references are pinned instead: an action
  to a full commit SHA carrying a version comment, a container image to a digest.

  The checks read workflow *text* rather than parsed YAML, deliberately. What
  makes a pinned reference reviewable is the version comment beside it, and a
  comment is exactly what a YAML parser throws away — so the shape this policy
  judges is not in the parse tree. These references are line-oriented anyway:
  one scalar per line, its version context in that line's trailing comment. Text
  also has no dependency cost (babashka bundles `clj-yaml`, the JVM `:test`
  classpath has no parser at all) and lets the same rules check a documentation
  example that is a YAML fragment rather than a whole workflow file.

  This namespace lives under `build/` rather than `src/`, so it never ships in
  the library jar. It uses only `clojure.core` and `clojure.string`, so it loads
  and runs identically under JVM Clojure and babashka."
  (:require [clojure.string :as str]))

;;;; Reading references

(def ^:private quoted-scalar-pattern
  #"(['\"])(.*?)\1\s*(?:#\s*(.*?))?\s*")

(def ^:private plain-scalar-pattern
  #"([^#]*?)\s*(?:#\s*(.*?))?\s*")

(defn- scalar
  "Returns `[value comment]` for the YAML scalar text `s`.
  A workflow may quote a reference or leave it bare, and may follow it with a
  `#` comment; the comment is `nil` when absent or empty."
  [s]
  (if-let [[_ _ quoted comment] (re-matches quoted-scalar-pattern s)]
    [quoted (not-empty comment)]
    (let [[_ plain comment] (re-matches plain-scalar-pattern s)]
      [plain (not-empty comment)])))

(defn- references
  "Returns the `key-name:` scalars in workflow `text`, in file order.
  Matches both the `- key:` and `key:` forms; a `#` comment line is not a
  reference, because the key has to start the line's content."
  [key-name text]
  (let [pattern (re-pattern (str "\\s*(?:-\\s+)?" key-name ":\\s*(\\S.*)"))]
    (vec (keep-indexed (fn [i line]
                         (when-let [[_ value] (re-matches pattern line)]
                           (let [[reference comment] (scalar value)]
                             {:line (inc i) :reference reference :comment comment})))
                       (str/split-lines text)))))

(defn action-references
  "Returns the `uses:` references in workflow `text`, in file order.
  Each entry is `{:line <1-based> :reference <value> :comment <trailing comment
  or nil>}`."
  [text]
  (references "uses" text))

(defn image-references
  "Returns the `image:` references in workflow `text`, in file order.
  Entries have the shape [[action-references]] returns."
  [text]
  (references "image" text))

;;;; The pinning rules

;; The only action form this policy knows how to pin: `owner/repo[/path]@ref`.
;; A `docker://` or `./local` reference does not match, and is reported as
;; unsupported rather than quietly exempted.
(def ^:private action-reference-pattern
  #"[A-Za-z0-9][\w.-]*/[\w.-]+(?:/[\w.-]+)*@(\S+)")

(def ^:private commit-sha-pattern
  #"[0-9a-f]{40}")

(def ^:private digested-image-pattern
  #"\S+@sha256:[0-9a-f]{64}")

(defn- action-reason
  "Returns why the action `reference` fails the policy, or `nil` when it passes.
  A bare SHA is unreviewable, so a pinned reference still needs the trailing
  `comment` naming the version that commit is."
  [{:keys [reference comment]}]
  (if-let [[_ git-ref] (re-matches action-reference-pattern reference)]
    (cond
      (not (re-matches commit-sha-pattern git-ref)) ::mutable-action-reference
      (nil? comment) ::unlabelled-action-reference)
    ::unsupported-action-reference))

(defn- image-reason
  "Returns why the image `reference` fails the policy, or `nil` when it passes."
  [{:keys [reference]}]
  (when-not (re-matches digested-image-pattern reference)
    ::mutable-image-reference))

;;;; Findings

(defn- findings
  "Returns a finding for each of `entries` that `reason-fn` rejects."
  [source kind reason-fn entries]
  (keep (fn [entry]
          (when-let [reason (reason-fn entry)]
            (assoc (select-keys entry [:line :reference]) :source source :kind kind
                   :reason reason)))
        entries))

(defn violations
  "Returns the policy findings for workflow `text`, labelled `source`.
  `source` is any label a diagnostic can name — a path, or the documentation
  section an example came from. Each finding is `{:source <label> :kind :action
  or :image :line <1-based> :reference <value> :reason <keyword>}`. An empty
  result means `text` pins every executable reference it declares."
  [source text]
  (vec (concat (findings source :action action-reason (action-references text))
               (findings source :image image-reason (image-references text)))))

(def ^:private reason-descriptions
  {::mutable-action-reference "is not pinned to a full 40-character commit SHA"
   ::unsupported-action-reference "is not an `owner/repo[/path]@sha` action reference"
   ::unlabelled-action-reference "is pinned but carries no trailing version comment"
   ::mutable-image-reference "is not pinned by an `@sha256:` digest"})

(defn finding-message
  "Renders a `finding` from [[violations]] as a one-line diagnostic.
  Names the source, the line, the reference, and what is wrong with it."
  [{:keys [source line reference reason]}]
  (str source ":" line ": " reference " "
       (get reason-descriptions reason (str "violates " reason))))
