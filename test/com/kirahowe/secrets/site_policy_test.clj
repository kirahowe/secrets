(ns com.kirahowe.secrets.site-policy-test
  "Checks on the site policy, and on the rendered book when one has been built.

  The fixtures are inline HTML rather than rendered pages, so the suite runs
  without `quarto`, without a JDK-only dependency, and without a build having
  happened first. One test reaches for the real artifact and states its reason
  for skipping when there is none, because the artifact is what actually ships
  and `bb book:build` enforces the same rules on it."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [are deftest is testing]]
            [com.kirahowe.secrets.site-policy :as policy]))

;;;; Fixtures

(defn- page
  "Returns a minimal page carrying `body-parts` in its head."
  [& head-parts]
  (str "<!DOCTYPE html>\n<html lang=\"en\"><head>\n<meta charset=\"utf-8\">\n"
       (str/join "\n" head-parts)
       "\n</head>\n<body><p>See <a href=\"https://age-encryption.org\">age</a>.</p></body></html>\n"))

;; Digests of the two inline scripts below, computed with `openssl dgst -sha256
;; -binary | openssl base64` rather than by the code under test, so a change in
;; how this namespace hashes fails the test instead of moving with it.
(def ^:private ready-script-digest "asm8aAmFS8uQhg2Eqy2o33b0pmZM8bVE6479NcKZ0mk=")

(def ^:private second-script-digest "8QJ2SmskTw0nGavvP8lhC99qQR0kOI+14lpNKs7L/qc=")

(def ^:private ready-script "<script>window.ready = true;</script>")

(def ^:private second-script "<script type=\"text/javascript\">window.second = 2;</script>")

(def ^:private search-options
  (str "<script id=\"quarto-search-options\" type=\"application/json\">"
       "{\"location\":\"sidebar\"}</script>"))

(def ^:private local-script "<script src=\"site_libs/quarto-nav/quarto-nav.js\"></script>")

(defn- policy-of
  "Returns the Content Security Policy the rewrite gives page `html`."
  [html]
  (policy/page-policy (policy/compliant-page html)))

(defn- reasons
  "Returns the set of reasons the policy finds in page `html`."
  [html]
  (set (map :reason (policy/page-violations "fixture.html" html))))

;;;; Removing what the artifact does not ship

(deftest external-scripts-are-removed-test
  (let [rewritten (policy/compliant-page
                   (page "<script src=\"https://code.jquery.com/jquery-3.6.0.min.js\" type=\"text/javascript\"></script>"
                         "<script src=\"https://code.jquery.com/ui/1.13.1/jquery-ui.min.js\" type=\"text/javascript\"></script>"
                         "<script src=\"https://cdn.example.test/analytics.js\"></script>"
                         local-script))]
    (testing "every script naming another origin is gone, matched by shape not by name"
      (is (empty? (policy/external-scripts rewritten)))
      (is (not (str/includes? rewritten "jquery")))
      (is (not (str/includes? rewritten "cdn.example.test"))))
    (testing "the scripts this artifact does ship survive"
      (is (str/includes? rewritten local-script)))
    (testing "prose links are not scripts"
      (is (str/includes? rewritten "<a href=\"https://age-encryption.org\">age</a>")))))

(deftest external-stylesheet-imports-are-removed-test
  (let [css (str "@import\"https://fonts.googleapis.com/css2?family=Source+Sans+Pro:wght@300;400;700\";"
                 "@import url(\"local-reset.css\");"
                 ".anchor{background:url(data:image/svg+xml,%3csvg%3e)}")
        rewritten (policy/compliant-stylesheet css)]
    (testing "the third-party import goes, and the local one and its rules stay"
      (is (empty? (policy/external-css-references rewritten)))
      (is (str/includes? rewritten "@import url(\"local-reset.css\");"))
      (is (str/includes? rewritten ".anchor{background:url(data:image/svg+xml,%3csvg%3e)}")))
    (testing "a semicolon inside the imported URL does not truncate the removal"
      (is (not (str/includes? rewritten "400;700"))))))

(defn- delete-tree!
  "Removes `file` and everything under it."
  [file]
  (run! io/delete-file (reverse (file-seq file))))

(defn- artifact!
  "Writes a miniature rendered book, of the shapes Clay and Quarto leave behind."
  []
  (let [dir (io/file (System/getProperty "java.io.tmpdir")
                     (str "site-policy-" (System/nanoTime)))
        cache (io/file dir ".quarto" "idx")]
    (.mkdirs cache)
    (spit (io/file dir "index.html")
          (page "<script src=\"https://code.jquery.com/jquery-3.6.0.min.js\"></script>"
                ready-script local-script))
    (spit (io/file dir "index.qmd")
          "---\ntitle: x\n---\n<script src=\"https://code.jquery.com/jquery-3.6.0.min.js\"></script>\n")
    (spit (io/file dir "theme.css") "@import\"https://fonts.googleapis.com/css2?family=X\";body{}")
    (spit (io/file cache "index.qmd.json") "{\"src\":\"https://code.jquery.com/jquery-3.6.0.min.js\"}")
    dir))

(deftest whole-artifact-is-rewritten-test
  (let [dir (artifact!)]
    (try
      (testing "the artifact starts non-compliant, so the check is not vacuous"
        (is (seq (policy/violations dir))))
      (let [changed (policy/rewrite! dir)]
        (testing "every kind of file in the artifact is covered"
          (is (empty? (policy/violations dir))
              (str/join "\n" (map policy/finding-message (policy/violations dir))))
          (is (not (str/includes? (slurp (io/file dir "index.qmd")) "jquery")))
          (is (str/includes? (slurp (io/file dir "index.html")) "Content-Security-Policy"))
          (is (nil? (policy/build-cache dir)))
          (is (some #(str/ends-with? % "index.qmd.json") changed))))
      (testing "a second pass changes nothing"
        (is (empty? (policy/rewrite! dir))))
      (finally (delete-tree! dir)))))

;;;; What the policy says

(deftest csp-hashes-cover-inline-scripts-test
  (testing "one inline script is admitted by the digest of its own bytes"
    (let [found (policy-of (page ready-script))]
      (is (str/includes? found (str "'sha256-" ready-script-digest "'")))
      (is (str/includes? found "script-src 'self' 'sha256-"))))
  (testing "two inline scripts are admitted by two hashes"
    (let [found (policy-of (page ready-script second-script))]
      (is (str/includes? found (str "'sha256-" ready-script-digest "'")))
      (is (str/includes? found (str "'sha256-" second-script-digest "'")))))
  (testing "a json data block is not script: it takes no hash and survives intact"
    (let [rewritten (policy/compliant-page (page ready-script search-options))]
      (is (str/includes? rewritten search-options))
      (is (= 1 (count (re-seq #"'sha256-" (policy/page-policy rewritten)))))))
  (testing "an inline event handler is admitted by hash, and only by hash"
    (let [found (policy-of (str/replace (page ready-script) "<p>" "<p onclick=\"go();\">"))]
      (is (str/includes? found "'unsafe-hashes'"))
      (is (= 2 (count (re-seq #"'sha256-" found))))))
  (testing "the policy grants no origin but this one, and no eval"
    (let [found (policy-of (page ready-script))]
      (are [directive] (str/includes? found directive)
        "default-src 'self'" "img-src 'self' data:" "font-src 'self' data:"
        "connect-src 'self'" "object-src 'none'" "base-uri 'self'"
        "frame-ancestors 'none'")
      (is (not (str/includes? found "unsafe-eval")))
      (is (not (str/includes? (re-find #"script-src[^;]*" found) "unsafe-inline"))))))

(deftest rewriting-is-idempotent-test
  (let [once (policy/compliant-page (page ready-script local-script))]
    (is (= once (policy/compliant-page once)))
    (is (= 1 (count (re-seq #"http-equiv=\"Content-Security-Policy\"" once))))))

;;;; What the policy refuses

(deftest policy-rejects-violations-test
  (let [compliant (policy/compliant-page (page ready-script))
        with-policy (fn [directives]
                      (str/replace compliant
                                   #"content=\"[^\"]*\""
                                   (str "content=\"" directives "\"")))]
    (are [reason html] (contains? (reasons html) reason)
      ::policy/external-script
      (str/replace compliant "</head>" "<script src=\"https://cdn.example.test/x.js\"></script></head>")

      ::policy/external-stylesheet
      (str/replace compliant "</head>"
                   "<link rel=\"stylesheet\" href=\"https://cdn.example.test/x.css\"></head>")

      ::policy/unhashed-inline-script
      (str/replace compliant "</head>" "<script>window.injected = true;</script></head>")

      ::policy/unhashed-event-handler
      (str/replace compliant "<p>" "<p onclick=\"go();\">")

      ::policy/inline-script-allowance
      (with-policy "default-src 'self'; script-src 'self' 'unsafe-inline'")

      ::policy/eval-allowance
      (with-policy (str "default-src 'self'; script-src 'self' 'unsafe-eval' 'sha256-"
                        ready-script-digest "'"))

      ::policy/missing-policy
      (page ready-script))
    (testing "a stylesheet reaching another origin is a finding too"
      (is (= #{::policy/external-stylesheet}
             (set (map :reason (policy/stylesheet-violations
                                "theme.css" "@import \"https://fonts.example.test/f.css\";"))))))
    (testing "a finding names the file and what was found in it"
      (is (= (str "fixture.html: https://cdn.example.test/x.js is a script this "
                  "artifact does not ship")
             (policy/finding-message
              (first (policy/page-violations
                      "fixture.html"
                      (str/replace compliant "</head>"
                                   "<script src=\"https://cdn.example.test/x.js\"></script></head>")))))))))

;;;; What the policy accepts

(deftest policy-accepts-a-compliant-page-test
  (let [found (policy/page-violations
               "fixture.html"
               (policy/compliant-page
                (page ready-script second-script search-options local-script
                      "<link rel=\"stylesheet\" href=\"site_libs/bootstrap/bootstrap.min.css\">")))]
    (is (empty? found) (str/join "\n" (map policy/finding-message found)))))

;;;; The artifact that ships

(deftest rendered-book-is-compliant-test
  (let [dir (io/file "book" "rendered")
        built (seq (policy/pages dir))]
    (if built
      (let [found (policy/violations dir)]
        (testing "every rendered page and stylesheet passes the same rules"
          (is (empty? found) (str/join "\n" (map policy/finding-message found)))))
      (println (str "rendered-book-is-compliant-test: skipped, " dir
                    " holds no pages. Run `bb book:build` to check the real artifact.")))))
