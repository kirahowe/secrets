(ns com.kirahowe.secrets.site-policy
  "The rule that the published book runs only the assets it ships.

  The rendered book is a static Pages artifact, so everything a reader's browser
  executes arrives either from this repository's own build or from a third party
  the page names. A `<script src>` on a CDN, or an `@import` inside a stylesheet,
  hands that third party the ability to rewrite an installation command, a link,
  or what the copy button puts on the clipboard (CWE-829, CWE-494), and nothing
  reviewed here covers what that origin serves tomorrow. These functions rewrite
  the artifact so it names no such asset, and then decide whether the rewrite
  held.

  Two operations, one property. [[compliant-page]] removes every script that
  names another origin and states what is left as a Content Security Policy:
  `'self'`, plus a `'sha256-'` source for each inline script the page carries,
  computed from that script's own bytes. Quarto generates those scripts, so a
  hardcoded hash would rot into a blank page on the next Quarto release; a hash
  taken at build time cannot. [[violations]] reads the artifact back and reports
  what a published site must not contain.

  The artifact holds more than pages. [[rewrite!]] and [[violations]] cover the
  `.qmd` sources Clay leaves beside them, the stylesheets, and Quarto's `.quarto`
  build cache, because a reference removed from the HTML and left in a source or
  a cached copy is still a reference this repository publishes.

  Removal rather than self-hosting is the choice here because the external
  scripts Clay injects are unused: it adds jQuery and jQuery UI to every page as
  part of its default resource list, and this book uses no widget that needs
  them. A dependency nothing calls is not worth vendoring, reviewing, and
  updating.

  What a text rule cannot do is bound what it claims. It reads the assets a page
  *names*, not what they do: it catches the third-party dependency and the
  inline script no policy covers, and says nothing about whether the scripts this
  repository does ship are safe. It reads HTML with regular expressions, so an
  attribute value containing `>` would defeat it — nothing Quarto emits does.
  And a policy delivered as a `<meta>` element is weaker than a response header:
  it governs only what the parser reaches after it, and browsers ignore
  `frame-ancestors` in meta form entirely. GitHub Pages sets no headers we
  control, so meta is the delivery available.

  This namespace lives under `build/` rather than `src/`, so it never ships in
  the library jar. It uses only `clojure.core`, `clojure.java.io`,
  `clojure.string`, and the JDK, so it loads and runs identically under JVM
  Clojure and babashka."
  (:require [clojure.java.io :as io]
            [clojure.string :as str])
  (:import (java.security MessageDigest)
           (java.util Base64)))

;;;; Hashing inline content

(defn hash-source
  "Returns the CSP source expression that admits inline `content`.
  Base64 of the raw SHA-256 digest of the exact bytes between an element's tags,
  which is what a browser hashes when it decides whether to run them."
  [content]
  (->> (.getBytes ^String content "UTF-8")
       (.digest (MessageDigest/getInstance "SHA-256"))
       (.encodeToString (Base64/getEncoder))
       (format "'sha256-%s'")))

;;;; Reading a page

(def ^:private script-pattern #"(?is)<script\b([^>]*)>(.*?)</script\s*>")

(def ^:private link-pattern #"(?is)<link\b([^>]*)>")

(def ^:private attribute-pattern
  #"(?is)([a-z][\w:.-]*)(?:\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s\"'>]+)))?")

(defn- attributes
  "Returns the attributes in an element's tag text `s`, keyed by lower-case name.
  An attribute written without a value maps to the empty string."
  [s]
  (into {} (map (fn [[_ k double-quoted single-quoted bare]]
                  [(str/lower-case k) (or double-quoted single-quoted bare "")]))
        (re-seq attribute-pattern s)))

(defn- elements
  "Returns `[attrs body]` for each element in `html` that `pattern` matches."
  [pattern html]
  (map (fn [[_ tag body]] [(attributes tag) body]) (re-seq pattern html)))

;; A scheme-relative `//host/path` names another origin as surely as an absolute
;; one, and `/path` names this one. Matching the shape rather than a host list is
;; the point: a Clay or Quarto release that adds a third URL is caught too.
(def ^:private absolute-url-pattern #"(?i)\A(?:[a-z][a-z0-9+.-]*:)?//")

(defn- absolute?
  "True when `url` names an origin of its own rather than a path in this site."
  [url]
  (some? (re-find absolute-url-pattern (str url))))

(def ^:private executable-type-pattern
  #"(?i)\s*(?:module|(?:text|application)/(?:x-)?(?:java|ecma)script)\s*(?:;.*)?")

(defn- executable?
  "True when a browser runs the body of a `<script>` element carrying `attrs`.
  An absent or JavaScript `type` executes. `application/json` does not: Quarto's
  search options are a data block, so they take no hash and must survive intact."
  [attrs]
  (let [declared (get attrs "type")]
    (or (str/blank? declared) (some? (re-matches executable-type-pattern declared)))))

(defn external-scripts
  "Returns the `src` URLs of the `<script>` elements in page `html` that name
  another origin, in page order."
  [html]
  (vec (for [[attrs] (elements script-pattern html)
             :let [src (get attrs "src")]
             :when (absolute? src)]
         src)))

(defn external-stylesheets
  "Returns the `href` URLs of the stylesheet `<link>` elements in page `html`
  that name another origin, in page order."
  [html]
  (vec (for [[attrs] (elements link-pattern html)
             :let [{:strs [rel href]} attrs]
             :when (and (str/includes? (str/lower-case (str rel)) "stylesheet")
                        (absolute? href))]
         href)))

(defn inline-scripts
  "Returns the bodies of the executable inline `<script>` elements in `html`.
  In page order. An element with a `src` is not inline, and one with a
  non-JavaScript `type` is data."
  [html]
  (vec (for [[attrs body] (elements script-pattern html)
             :when (and (not (contains? attrs "src")) (executable? attrs))]
         body)))

;; Matched against the whole page rather than element by element, because the
;; handlers Quarto writes sit on ordinary elements this namespace has no reason
;; to parse. A `data-on…="…"` attribute or a string inside a script that happens
;; to take this shape would add a hash for content no browser runs: harmless,
;; since the rewrite and the check read the same shape.
(def ^:private event-handler-pattern
  #"(?is)\son[a-z]+\s*=\s*(?:\"([^\"]*)\"|'([^']*)')")

(defn inline-event-handlers
  "Returns the `on…` attribute bodies in page `html`, in page order.
  A handler attribute is inline script that runs on an event, and a policy has to
  admit each one by hash or the control it belongs to stops working."
  [html]
  (vec (for [[_ double-quoted single-quoted] (re-seq event-handler-pattern html)]
         (or double-quoted single-quoted))))

;;;; Reading a stylesheet

(def ^:private import-pattern
  #"(?is)@import\s*(?:url\(\s*)?(?:\"([^\"]*)\"|'([^']*)'|([^\"'\s;)]+))\s*\)?[^;]*;")

(def ^:private css-url-pattern
  #"(?is)url\(\s*(?:\"([^\"]*)\"|'([^']*)'|([^)\s]*))")

(defn external-css-references
  "Returns the URLs stylesheet `text` fetches from another origin when a page
  loads it, deduplicated and in file order.
  Both the `@import` rules and the `url()` references: either reaches a third
  party at render time as surely as a `<script src>` does, and an `@import` is
  invisible in the HTML that pulls the stylesheet in."
  [text]
  (vec (distinct (for [pattern [import-pattern css-url-pattern]
                       [_ double-quoted single-quoted bare] (re-seq pattern text)
                       :let [url (or double-quoted single-quoted bare)]
                       :when (absolute? url)]
                   url))))

;;;; The policy a page declares

;; `style-src` is the one allowance here, and it is measured rather than
;; assumed. The four `<style>` blocks Quarto emits hash cleanly, but
;; `quarto-nav.js` writes `style` attributes onto `body`, `#quarto-content`,
;; `#quarto-sidebar`, and `#quarto-margin-sidebar` after layout, with values
;; computed from the header height it just measured (`top: 0px`, `max-height:
;; calc(0px + 100vh)`). No build-time hash can exist for a value the browser
;; computes, and under a hash-only `style-src` Chrome blocks all four and the
;; sidebar loses its positioning. A stylesheet cannot execute, exfiltrate, or
;; rewrite a command, so this is a materially smaller allowance than an inline
;; script would be — and it stays out of `script-src`, where the check refuses
;; it.
(def ^:private style-sources "'self' 'unsafe-inline'")

(defn- script-sources
  "Returns the `script-src` source list for page `html`.
  Each inline script is admitted by its own hash rather than by `'unsafe-inline'`,
  which would admit any script an injection managed to place. `'unsafe-hashes'`
  extends those hashes to the `on…` handlers behind Quarto's sidebar toggle and
  search button: it admits those exact handler bodies and nothing else, and
  without it the narrow-viewport navigation and search stop responding."
  [html]
  (let [scripts (distinct (map hash-source (inline-scripts html)))
        handlers (distinct (map hash-source (inline-event-handlers html)))]
    (str/join " " (concat ["'self'"] scripts
                          (when (seq handlers) (cons "'unsafe-hashes'" handlers))))))

(defn content-security-policy
  "Returns the Content Security Policy for page `html`.
  Everything comes from this origin, except the inline content the page itself
  carries, which is admitted by hash. `data:` is allowed for images and fonts
  because Bootstrap's icon font and its inline SVG backgrounds are embedded that
  way; browsers ignore `frame-ancestors` from a `<meta>` element but it costs
  nothing and holds if this artifact is ever served with headers."
  [html]
  (str/join "; " ["default-src 'self'"
                  (str "script-src " (script-sources html))
                  (str "style-src " style-sources)
                  "img-src 'self' data:"
                  "font-src 'self' data:"
                  "connect-src 'self'"
                  "object-src 'none'"
                  "base-uri 'self'"
                  "frame-ancestors 'none'"]))

(def ^:private policy-element-pattern
  #"(?is)\s*<meta\s+http-equiv=\"Content-Security-Policy\"[^>]*>")

(def ^:private policy-content-pattern
  #"(?is)<meta\s+http-equiv=\"Content-Security-Policy\"[^>]*\scontent=\"([^\"]*)\"")

(defn page-policy
  "Returns the Content Security Policy page `html` declares, or `nil` for none."
  [html]
  (second (re-find policy-content-pattern html)))

(defn- policy-directives
  "Returns `policy` as a map from directive name to its set of source expressions."
  [policy]
  (into {} (for [clause (str/split (str policy) #";")
                 :let [[directive & sources] (str/split (str/trim clause) #"\s+")]
                 :when (seq directive)]
             [(str/lower-case directive) (set sources)])))

;;;; Rewriting the artifact

(def ^:private head-pattern
  #"(?is)<head\b[^>]*>(?:\s*<meta\s+charset=[^>]*>)?")

(defn- policy-element
  "Returns the `<meta>` element that delivers `policy`."
  [policy]
  (str "<meta http-equiv=\"Content-Security-Policy\" content=\"" policy "\">"))

(defn without-external-scripts
  "Returns page text `html` with every `<script>` element naming another origin
  removed.
  An external stylesheet is reported rather than removed: a script this book does
  not call can go, but a stylesheet is layout, and dropping one silently would
  trade a security finding for a broken page. Nothing Quarto emits links one."
  [html]
  (str/replace html script-pattern
               (fn [[element tag _]]
                 (if (absolute? (get (attributes tag) "src")) "" element))))

(defn compliant-page
  "Returns page `html` with no third-party script and a policy that says so.
  The policy element goes after the character set declaration, which has to stay
  in the document's first bytes, and before anything a browser could run.
  Idempotent: an existing policy element is replaced rather than stacked, so a
  second pass over an already rewritten page changes nothing."
  [html]
  (let [page (-> html
                 (str/replace policy-element-pattern "")
                 without-external-scripts)]
    (str/replace-first page head-pattern
                       #(str % "\n" (policy-element (content-security-policy page))))))

(defn compliant-stylesheet
  "Returns stylesheet `text` with every `@import` of another origin removed.
  Quarto's Bootstrap theme imports a Google Fonts stylesheet, which fetches from
  two more origins at render time and is the only thing on the page that does.
  The theme's own font stack names system faces after it, so removing the import
  costs a typeface and no layout."
  [text]
  (str/replace text import-pattern
               (fn [[rule double-quoted single-quoted bare]]
                 (if (absolute? (or double-quoted single-quoted bare)) "" rule))))

(defn- files-with-extension
  "Returns the files under `dir` whose names end in `extension`, in path order."
  [dir extension]
  (->> (file-seq (io/file dir))
       (filter #(and (.isFile ^java.io.File %) (str/ends-with? (str %) extension)))
       (sort-by str)
       vec))

(defn pages
  "Returns the HTML pages of the rendered book under `dir`, in path order."
  [dir]
  (files-with-extension dir ".html"))

(defn stylesheets
  "Returns the stylesheets of the rendered book under `dir`, in path order."
  [dir]
  (files-with-extension dir ".css"))

(defn page-sources
  "Returns the Quarto sources of the rendered book under `dir`, in path order.
  Clay leaves the `.qmd` it generated each page from inside the artifact, with
  the same third-party scripts injected into it. No browser runs one, but a
  published file naming a CDN script is what this policy exists to remove, and
  re-rendering a source that still names it would put it back."
  [dir]
  (files-with-extension dir ".qmd"))

(defn build-cache
  "Returns the Quarto build cache inside artifact `dir`, or `nil` when absent.
  Quarto writes `.quarto/` beside its output: a private scratch directory no page
  loads, holding a JSON copy of each source as it was before the rewrite. It is
  not site content, and publishing it would leave the removed references in the
  artifact for anyone scanning it."
  [dir]
  (let [cache (io/file dir ".quarto")]
    (when (.isDirectory cache) cache)))

(defn- rewrite-files!
  "Rewrites each of `files` through `f`, returning the paths that changed."
  [files f]
  (reduce (fn [changed file]
            (let [text (slurp file)
                  rewritten (f text)]
              (if (= text rewritten)
                changed
                (do (spit file rewritten)
                    (conj changed (str file))))))
          []
          files))

(defn- deleted-tree!
  "Deletes `file` and everything under it, returning the paths removed."
  [file]
  (let [removed (mapv str (file-seq file))]
    (run! io/delete-file (reverse (file-seq file)))
    removed))

(defn rewrite!
  "Rewrites the rendered book under `dir` into the artifact this policy allows.
  Removes every third-party script from each page and each Quarto source, every
  third-party `@import` from each stylesheet, and Quarto's build cache; gives
  each page the policy that states what is left. Returns the paths that changed.
  Idempotent, so a second run over an already rewritten artifact returns
  nothing."
  [dir]
  (-> (rewrite-files! (pages dir) compliant-page)
      (into (rewrite-files! (page-sources dir) without-external-scripts))
      (into (rewrite-files! (stylesheets dir) compliant-stylesheet))
      (into (some-> (build-cache dir) deleted-tree!))))

;;;; Findings

(defn- finding
  "Returns a finding naming what in `source` violates the policy, and why."
  [source reason reference]
  {:source source :reason reason :reference reference})

(defn- excerpt
  "Returns inline `content` as a single short line, for a diagnostic to name it."
  [content]
  (let [text (str/trim (str/replace content #"\s+" " "))]
    (if (> (count text) 60)
      (str (subs text 0 60) "…")
      text)))

(defn page-violations
  "Returns the policy findings for page `html`, labelled `source`.
  Each finding is `{:source <label> :reason <keyword> :reference <url or
  excerpt>}`. An empty result means the page fetches nothing executable from
  another origin, declares a policy, covers each of its own inline scripts and
  handlers by hash, and grants neither inline nor eval script."
  [source html]
  (let [policy (page-policy html)
        sources (get (policy-directives policy) "script-src" #{})
        covered? (comp sources hash-source)]
    (vec (concat (map #(finding source ::external-script %) (external-scripts html))
                 (map #(finding source ::external-stylesheet %) (external-stylesheets html))
                 (when-not policy
                   [(finding source ::missing-policy "no Content-Security-Policy element")])
                 (map #(finding source ::unhashed-inline-script (excerpt %))
                      (remove covered? (inline-scripts html)))
                 (map #(finding source ::unhashed-event-handler (excerpt %))
                      (remove covered? (inline-event-handlers html)))
                 (when (contains? sources "'unsafe-inline'")
                   [(finding source ::inline-script-allowance
                             (str "script-src " (str/join " " sources)))])
                 (when (str/includes? (str/lower-case (str policy)) "'unsafe-eval'")
                   [(finding source ::eval-allowance (excerpt (str policy)))])))))

(defn source-violations
  "Returns the policy findings for Quarto source `text`, labelled `source`.
  A source carries no policy of its own — the page rendered from it does — so
  only the assets it names are judged."
  [source text]
  (into (mapv #(finding source ::external-script %) (external-scripts text))
        (mapv #(finding source ::external-stylesheet %) (external-stylesheets text))))

(defn stylesheet-violations
  "Returns the policy findings for stylesheet `text`, labelled `source`."
  [source text]
  (mapv #(finding source ::external-stylesheet %) (external-css-references text)))

(defn violations
  "Returns the policy findings for the rendered book under `dir`.
  Every page, Quarto source, and stylesheet in the artifact, plus the build cache
  if it survived, so an asset named only in a stylesheet or left behind in
  scratch is judged by the same rule as one the HTML names."
  [dir]
  (-> (vec (mapcat #(page-violations (str %) (slurp %)) (pages dir)))
      (into (mapcat #(source-violations (str %) (slurp %)) (page-sources dir)))
      (into (mapcat #(stylesheet-violations (str %) (slurp %)) (stylesheets dir)))
      (into (when-let [cache (build-cache dir)]
              [(finding (str cache) ::published-build-cache "the Quarto build cache")]))))

(def ^:private reason-descriptions
  {::external-script "is a script this artifact does not ship"
   ::external-stylesheet "is a stylesheet this artifact does not ship"
   ::missing-policy "declares no Content Security Policy"
   ::unhashed-inline-script "is an inline script no `script-src` hash admits"
   ::unhashed-event-handler "is an inline event handler no `script-src` hash admits"
   ::inline-script-allowance "admits any inline script, not only the page's own"
   ::eval-allowance "admits `eval`"
   ::published-build-cache (str "is scratch no page loads, holding copies of the "
                                "references the rewrite removed")})

(defn finding-message
  "Renders a `finding` from [[violations]] as a one-line diagnostic.
  Names the file, what was found in it, and what is wrong with it."
  [{:keys [source reason reference]}]
  (str source ": " reference " "
       (get reason-descriptions reason (str "violates " reason))))
