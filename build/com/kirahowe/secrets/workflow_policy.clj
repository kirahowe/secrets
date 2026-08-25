(ns com.kirahowe.secrets.workflow-policy
  "The rules that a workflow's dependencies are immutable and its keys are narrow.

  Two properties, checked the same way. Every executable dependency a workflow
  names has to be pinned, and a private age identity has to be granted to the
  one step that consumes it rather than to everything running beside it.

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

  What a text rule cannot do is bound what it claims: it reads placement and
  reference shape, not behaviour. It catches the credential granted too widely
  and the reference that upstream can retarget. It does not know what a pinned
  action does with the environment it is handed, and no rule here makes a
  reviewed action trustworthy.

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

;;;; The identity-placement rule

;; The three spellings of one credential, from `identity-env-sources` in
;; `com.kirahowe.secrets.cli`. `_FILE` names a path rather than key material and
;; is checked anyway: what a declaration outside a step hands the steps beside it
;; is the ability to decrypt, and that capability is the same whichever spelling
;; carries it. Exempting one spelling would only teach a reader which one to use
;; to keep the check quiet.
(def ^:private identity-key-pattern
  #"(?:^|[\s{,])(SECRETS_AGE_IDENTITY(?:_FILE|_B64)?)\s*:")

(def ^:private env-block-pattern
  #"(\s*)(-\s+)?env:\s*(\S.*)?")

(def ^:private sequence-item-pattern
  #"(\s*)-(\s+)\S.*")

(def ^:private blank-or-comment-pattern
  #"\s*(?:#.*)?")

(defn- indentation
  "Returns the column the content of `line` starts at."
  [line]
  (count (take-while #{\space} line)))

(defn- item-content-column
  "Returns the column a sequence item's own keys sit at, `nil` for other lines."
  [line]
  (when-let [[_ indent gap] (re-matches sequence-item-pattern line)]
    (+ (count indent) 1 (count gap))))

(defn- structural-lines
  "Returns `[<0-based index> line]` for the lines of `text` that YAML nests by.
  A blank line and a whole-line comment carry no indentation to nest from, so
  they are dropped; the retained index keeps every line number reportable."
  [text]
  (vec (keep-indexed (fn [i line]
                       (when-not (re-matches blank-or-comment-pattern line)
                         [i line]))
                     (str/split-lines text))))

(defn- env-scope
  "Returns `:step` when an `env:` key at `column` belongs to a sequence item.
  `preceding` is the structural lines before it. The key's parent is the last
  line indented less than the key itself: a step's `env:` is a sibling of that
  step's `- ` marker, and a wider block's parent is a plain mapping key."
  [column preceding]
  (let [parent (last (filter #(< (indentation (second %)) column) preceding))]
    (if (= column (some-> parent second item-content-column)) :step :wider)))

(defn- env-block-references
  "Returns the identity declarations of the `env:` block opening at `[i line]`.
  `preceding` and `following` are the structural lines around it. The block's
  body is everything indented past the `env:` key, plus whatever a flow mapping
  put on the key's own line."
  [[i line] preceding following]
  (let [[_ indent marker inline] (re-matches env-block-pattern line)
        column (+ (count indent) (count marker))
        scope (if marker :step (env-scope column preceding))
        body (take-while #(< column (indentation (second %))) following)]
    (for [[j text] (cons [i (str inline)] body)
          [_ variable] (re-seq identity-key-pattern text)]
      {:line (inc j) :reference variable :scope scope})))

(defn identity-env-references
  "Returns the private age identities workflow `text` declares in an `env:` block.
  Each entry is `{:line <1-based> :reference <variable name> :scope :step or
  :wider}`, in file order. `:step` is a step's own environment; `:wider` is a
  job's or the workflow's, which every step underneath it inherits.

  Indentation is the whole signal, so this reads the block form every workflow
  and example here is written in — a `KEY:` under an `env:` key, or a flow
  mapping on that key's own line. A step collapsed into a single flow mapping is
  not read, and neither is a credential a step passes on in some other way. The
  rule finds the placement mistake, not every route out."
  [text]
  (let [lines (structural-lines text)]
    (vec (mapcat (fn [n]
                   (let [entry (nth lines n)]
                     (when (re-matches env-block-pattern (second entry))
                       (env-block-references entry (subvec lines 0 n)
                                             (subvec lines (inc n))))))
                 (range (count lines))))))

(defn- identity-reason
  "Returns why an identity declaration fails the policy, `nil` when it passes."
  [{:keys [scope]}]
  (when-not (= :step scope) ::widely-scoped-identity))

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
  section an example came from. Each finding is `{:source <label> :kind :action,
  :image or :env :line <1-based> :reference <value> :reason <keyword>}`. An empty
  result means `text` pins every executable reference it declares and grants no
  private identity wider than the step that uses it."
  [source text]
  (vec (concat (findings source :action action-reason (action-references text))
               (findings source :image image-reason (image-references text))
               (findings source :env identity-reason (identity-env-references text)))))

(def ^:private reason-descriptions
  {::mutable-action-reference "is not pinned to a full 40-character commit SHA"
   ::unsupported-action-reference "is not an `owner/repo[/path]@sha` action reference"
   ::unlabelled-action-reference "is pinned but carries no trailing version comment"
   ::mutable-image-reference "is not pinned by an `@sha256:` digest"
   ::widely-scoped-identity (str "is a private age identity granted to more than "
                                 "the step that consumes it")})

(defn finding-message
  "Renders a `finding` from [[violations]] as a one-line diagnostic.
  Names the source, the line, the reference, and what is wrong with it."
  [{:keys [source line reference reason]}]
  (str source ":" line ": " reference " "
       (get reason-descriptions reason (str "violates " reason))))

;;;; Examples inside documentation

;; Only whitespace that precedes a comment prefix comes off. A Markdown fence
;; carries no prefix, and its block's indentation is exactly what the placement
;; rule reads, so an unprefixed line has to survive untouched.
(def ^:private comment-prose-pattern
  #"(?:\s*;+ ?)?(.*)")

(def ^:private fence-pattern
  #"\s*```\s*(\S*)\s*")

(defn- prose
  "Returns the documentation text of `line`, less any `;;` comment prefix.
  Indentation inside the comment is kept: it is the block's own YAML structure."
  [line]
  (second (re-matches comment-prose-pattern line)))

(defn- fence-language
  "Returns the language a fenced block opens, `\"\"` for the fence that closes it,
  and `nil` when `line` opens no fence."
  [line]
  (second (re-matches fence-pattern line)))

(defn documentation-yaml-blocks
  "Returns the fenced YAML examples in documentation `text`, in file order.
  A book chapter keeps its prose in `;;` comments and its examples in fenced
  blocks inside them, so the prefix comes off before the fences are read; a
  Markdown document has the same fences without a prefix. Each block is returned
  as workflow text padded with blank lines to the position it holds in `text`, so
  a finding's line number is a line number in the source file. A fence in another
  language, and a fence nothing closes, yield no block."
  [text]
  (let [lines (mapv prose (str/split-lines text))
        fences (keep-indexed (fn [i line] (when (fence-language line) i)) lines)]
    (vec (for [[open close] (partition 2 fences)
               :when (= "yaml" (fence-language (nth lines open)))]
           (str/join "\n" (concat (repeat (inc open) "")
                                  (subvec lines (inc open) close)))))))
