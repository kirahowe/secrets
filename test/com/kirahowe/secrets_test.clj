(ns com.kirahowe.secrets-test
  "End-to-end tests exercising the real `age` binary. They require `age` and
  `age-keygen` on the PATH (brew install age). Each test runs in a throwaway
  temp directory with a freshly generated key."
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.manifest :as manifest]))

(def ^:dynamic *dir* nil)
(def ^:dynamic *key* nil)

(defn with-tmp-key [f]
  (let [dir (str (java.nio.file.Files/createTempDirectory
                  "kira-secrets-test"
                  (into-array java.nio.file.attribute.FileAttribute [])))
        key (str dir "/key.txt")]
    (age/keygen! key)
    (binding [*dir* dir *key* key]
      (try
        (f)
        (finally
          (doseq [p (reverse (file-seq (io/file dir)))] (.delete p)))))))

(use-fixtures :each with-tmp-key)

(defn- encrypt-edn!
  "Write `m` as EDN, encrypt it to <dir>/secrets.edn.age, drop the plaintext,
  and return the ciphertext path."
  [m]
  (let [plain (str *dir* "/plain.edn")
        enc   (str *dir* "/secrets.edn.age")]
    (spit plain (pr-str m))
    (age/encrypt-file! *key* plain enc)
    (.delete (io/file plain))
    enc))

(deftest expand-home-test
  (is (= (str (System/getProperty "user.home") "/.config/x")
         (secrets/expand-home "~/.config/x")))
  (is (= "/abs/path" (secrets/expand-home "/abs/path"))))

(deftest age-roundtrip
  (testing "encrypt then decrypt returns the original bytes"
    (let [enc (encrypt-edn! {:database/url "jdbc:postgresql://h/db"
                             :auth/admins  #{"a@b.com" "c@d.com"}})]
      (is (.exists (io/file enc)))
      (is (not (re-find #"jdbc" (slurp enc))) "ciphertext does not leak plaintext")
      (let [m (secrets/load-secrets enc *key*)]
        (is (= "jdbc:postgresql://h/db" (secrets/get-secret m :database/url)))
        (is (= #{"a@b.com" "c@d.com"} (secrets/get-secret m :auth/admins))
            "native EDN sets survive the round trip")))))

(deftest get-secret-paths
  (let [m (secrets/load-secrets (encrypt-edn! {:r2 {:account-id "acc"}}) *key*)]
    (is (= "acc" (secrets/get-secret m [:r2 :account-id])))
    (is (nil?   (secrets/get-secret m [:r2 :missing])))
    (is (= :dflt (secrets/get-secret m [:r2 :missing] :dflt)))
    (is (= :dflt (secrets/get-secret m :nope :dflt)))))

(deftest public-key-test
  (is (re-find #"^age1" (age/public-key *key*)))
  (is (nil? (age/public-key (str *dir* "/does-not-exist")))))

(deftest reader-literals-present
  (let [enc     (encrypt-edn! {:database/url "jdbc:x" :llm/api-key "sk-123"})
        readers (secrets/reader-literals {:file enc :identity-file *key*})
        cfg     (edn/read-string
                 {:readers readers}
                 "{:url #secret/req :database/url
                   :key #secret/opt :llm/api-key
                   :absent #secret/opt :not-there}")]
    (is (= "jdbc:x" (:url cfg)))
    (is (= "sk-123" (:key cfg)))
    (is (nil? (:absent cfg)) "#secret/opt on a missing key is nil")))

(deftest reader-required-missing-throws
  (let [enc     (encrypt-edn! {:present 1})
        readers (secrets/reader-literals {:file enc :identity-file *key*})]
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"missing from the secrets file"
         (edn/read-string {:readers readers} "#secret/req :totally-absent")))))

(deftest reader-absent-file
  (testing "no secrets file on disk: #secret/opt → nil, #secret/req → throws"
    (let [readers (secrets/reader-literals {:file (str *dir* "/nope.age")
                                            :identity-file *key*})]
      (is (nil? (edn/read-string {:readers readers} "#secret/opt :anything")))
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo #"no secrets file found"
           (edn/read-string {:readers readers} "#secret/req :anything"))))))

(deftest reader-absent-identity
  (testing "secrets file present but identity file missing: opt → nil, req → throws"
    (let [enc     (encrypt-edn! {:k "v"})
          readers (secrets/reader-literals {:file enc
                                            :identity-file (str *dir* "/no-such-key.txt")})]
      (is (nil? (edn/read-string {:readers readers} "#secret/opt :k")))
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo #"identity"
           (edn/read-string {:readers readers} "#secret/req :k"))))))

(deftest reader-decrypts-once
  (testing "many secret tags share a single decryption"
    (let [enc   (encrypt-edn! {:a 1 :b 2 :c 3})
          calls (atom 0)
          real  age/decrypt]
      (with-redefs [age/decrypt (fn [& args] (swap! calls inc) (apply real args))]
        (let [readers (secrets/reader-literals {:file enc :identity-file *key*})
              cfg     (edn/read-string
                       {:readers readers}
                       "[#secret/req :a #secret/req :b #secret/opt :c #secret/opt :missing]")]
          (is (= [1 2 3 nil] cfg))
          (is (= 1 @calls) "decryption is memoized for the process"))))))

(deftest identity-from-env-contents
  (testing "SECRETS_AGE_IDENTITY-style contents are materialized to a usable keyfile"
    (let [enc      (encrypt-edn! {:k "v"})
          ;; env vars can't be set in-process, so drive the materialization
          ;; step directly — identity-from-env feeds it the same contents.
          path     (#'secrets/materialize-identity! (slurp *key*))]
      (is (.exists (io/file path)))
      (is (= {:k "v"} (secrets/load-secrets enc path))))))

(deftest identity-resolution-nil-without-app
  (testing "no env vars + no app ⇒ resolution returns nil (no silent default)"
    ;; Guarded: in an environment that has SECRETS_AGE_IDENTITY* set (e.g. CI), the
    ;; env legitimately wins, so only assert on a clean environment.
    (if (some #(System/getenv %) ["SECRETS_AGE_IDENTITY_FILE" "SECRETS_AGE_IDENTITY" "SECRETS_AGE_IDENTITY_B64"])
      (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
      (do (is (nil? (secrets/identity-from-env)))
          (is (nil? (secrets/resolve-identity-file)))
          (is (nil? (secrets/resolve-identity-file {})))))))

(def ^:private age-env-set?
  "SECRETS_AGE_IDENTITY* overrides both :app and :identity-file resolution, so tests
  that pin a specific (non-)existent key skip themselves when it is set — matching
  the guard in test/com/kirahowe/secrets/cli_test.clj."
  (boolean (some #(System/getenv %) ["SECRETS_AGE_IDENTITY_FILE" "SECRETS_AGE_IDENTITY" "SECRETS_AGE_IDENTITY_B64"])))

(deftest identity-available?-test
  (testing ":identity-file — true when the file exists, false when it doesn't"
    (is (true?  (secrets/identity-available? {:identity-file *key*})))
    (is (false? (secrets/identity-available? {:identity-file (str *dir* "/no-such-key.txt")}))))
  (testing "app-name resolution — true for an existing app key, false for a missing one"
    (if age-env-set?
      (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
      (let [home (System/getProperty "user.home")]
        (try
          (System/setProperty "user.home" *dir*)
          (io/make-parents (io/file *dir* ".config" "testapp" "key.txt"))
          (io/copy (io/file *key*) (io/file *dir* ".config" "testapp" "key.txt"))
          (is (true?  (secrets/identity-available? "testapp"))
              "string arg is an app name, as resolve-identity-file treats it")
          (is (true?  (secrets/identity-available? {:app "testapp"})))
          (is (false? (secrets/identity-available? "definitely-not-a-real-app-xyz")))
          (is (false? (secrets/identity-available? {:app "definitely-not-a-real-app-xyz"})))
          (finally
            (System/setProperty "user.home" home))))))
  (testing "0-arity mirrors resolve-identity-file with no app"
    (if age-env-set?
      (is true "skipped: an SECRETS_AGE_IDENTITY* env var is set")
      (is (false? (secrets/identity-available?))))))

(deftest b64-identity-decode
  (let [decode #'secrets/decode-b64-identity
        raw    "AGE-SECRET-KEY-1EXAMPLE\n"
        b64    (.encodeToString (java.util.Base64/getMimeEncoder) (.getBytes raw "UTF-8"))]
    (is (= raw (decode b64)) "valid base64 round-trips")
    (is (= raw (decode (str "  " b64 "\n"))) "surrounding whitespace is tolerated")
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"base64"
         (decode "!!! not base64 !!!"))
        "invalid base64 throws instead of silently falling back")))

(deftest load-secrets-opts-map
  (let [enc (encrypt-edn! {:k "v"})]
    (is (= {:k "v"} (secrets/load-secrets enc {:identity-file *key*})))
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"(?i)no age identity.*SECRETS_AGE_IDENTITY_FILE"
         (secrets/load-secrets enc {:identity-file (str *dir* "/nope")}))
        "a nonexistent identity file throws with the remediation options")))

;; ---------- load-secrets error quality (mirrors reader-literals' :reason vocabulary) ----------

(deftest load-secrets-nil-source-throws
  (testing "source is nil: names the classpath-resource cause, not a bare IllegalArgumentException"
    (let [e (is (thrown-with-msg?
                 clojure.lang.ExceptionInfo #"(?i)source is nil"
                 (secrets/load-secrets nil *key*)))]
      (is (= :no-file (:reason (ex-data e))))
      (is (nil? (:source (ex-data e))))
      (is (re-find #"(?i)classpath" (ex-message e)))
      (is (re-find #"bb secrets new" (ex-message e))))))

(deftest load-secrets-missing-file-throws
  (testing "source names a path that does not exist: names the path, not a bare FileNotFoundException"
    (let [missing (str *dir* "/nope.edn.age")
          e (is (thrown-with-msg?
                 clojure.lang.ExceptionInfo #"(?i)secrets file not found"
                 (secrets/load-secrets missing *key*)))]
      (is (= :no-file (:reason (ex-data e))))
      (is (= missing (:source (ex-data e))))
      (is (re-find (re-pattern (java.util.regex.Pattern/quote missing)) (ex-message e))
          "the error names the offending path")
      (is (re-find #"bb secrets new" (ex-message e))))))

(deftest load-secrets-missing-identity-throws
  (testing "missing identity file: :reason :no-identity, wording unchanged"
    (let [enc (encrypt-edn! {:k "v"})
          e (is (thrown-with-msg?
                 clojure.lang.ExceptionInfo #"(?i)no age identity.*SECRETS_AGE_IDENTITY_FILE"
                 (secrets/load-secrets enc (str *dir* "/no-such-key.txt"))))]
      (is (= :no-identity (:reason (ex-data e)))))))

(deftest load-secrets-success-unaffected
  (testing "a successful load is unaffected by the new error paths"
    (let [enc (encrypt-edn! {:k "v"})]
      (is (= {:k "v"} (secrets/load-secrets enc *key*))))))

(deftest jar-resource-loading
  (testing "load-secrets reads an encrypted entry through a jar: URL"
    (let [enc (encrypt-edn! {:from :jar})
          jar (str *dir* "/app.jar")]
      (with-open [zos (java.util.zip.ZipOutputStream. (io/output-stream jar))]
        (.putNextEntry zos (java.util.zip.ZipEntry. "secrets.edn.age"))
        (io/copy (io/file enc) zos)
        (.closeEntry zos))
      (let [url (str "jar:file:" jar "!/secrets.edn.age")]
        (is (= {:from :jar} (secrets/load-secrets (java.net.URL. url) *key*)))
        (is (= {:from :jar} (secrets/load-secrets url *key*))
            "a String source may be a URL, not only a path — io/input-stream tries the URL first")))))

;; ---------- Multi-recipient ----------

(deftest valid-recipient?-test
  (is (age/valid-recipient? (age/public-key *key*)))
  (is (age/valid-recipient? "  age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p  "))
  (is (not (age/valid-recipient? "not-a-key")))
  (is (not (age/valid-recipient? nil))))

(deftest multi-recipient-roundtrip
  (testing "a file encrypted to two recipients decrypts with either key"
    (let [key2  (str *dir* "/key2.txt")
          _     (age/keygen! key2)
          pub1  (age/public-key *key*)
          pub2  (age/public-key key2)
          plain (str *dir* "/p.edn")
          enc   (str *dir* "/multi.edn.age")]
      (spit plain (pr-str {:x 1}))
      (testing "via an explicit :recipients list"
        (age/encrypt-file! {:recipients [pub1 pub2]} plain enc)
        (is (= {:x 1} (secrets/load-secrets enc *key*)))
        (is (= {:x 1} (secrets/load-secrets enc key2))))
      (testing "via a :recipients-file"
        (let [rf (str *dir* "/recipients.txt")]
          (spit rf (str "# team\n" pub1 "\n" pub2 "\n"))
          (age/encrypt-file! {:recipients-file rf} plain enc)
          (is (= {:x 1} (secrets/load-secrets enc *key*)))
          (is (= {:x 1} (secrets/load-secrets enc key2))))))))

(deftest single-key-still-works
  (testing "passing a bare identity path encrypts to that identity (back-compat)"
    (let [plain (str *dir* "/p.edn")
          enc   (str *dir* "/single.edn.age")]
      (spit plain (pr-str {:y 2}))
      (age/encrypt-file! *key* plain enc)
      (is (= {:y 2} (secrets/load-secrets enc *key*))))))

(deftest bare-public-key-guard
  (testing "a bare age1… public key is rejected — it is not an identity-file path"
    (let [plain (str *dir* "/p.edn")]
      (spit plain (pr-str {:z 3}))
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo #":recipients"
           (age/encrypt-file! (age/public-key *key*) plain (str *dir* "/x.age")))))))

(deftest binary-roundtrip
  (testing "decrypt-bytes / decrypt-to-file! preserve binary plaintext exactly"
    (let [payload (byte-array (map unchecked-byte [0 1 2 255 254 10 13]))
          plain   (io/file *dir* "bin.dat")
          enc     (str *dir* "/bin.dat.age")
          out     (io/file *dir* "bin.out")]
      (io/copy payload plain)
      (age/encrypt-file! *key* plain enc)
      (is (java.util.Arrays/equals payload (age/decrypt-bytes *key* enc)))
      (age/decrypt-to-file! *key* enc out)
      (is (java.util.Arrays/equals payload
                                   (java.nio.file.Files/readAllBytes (.toPath out)))))))

;; ---------- Manifest ----------

(deftest manifest-structure
  (let [m {:database/url "jdbc:x"
           :auth        {:admins #{"a@b.com" "c@d.com"}}
           :retries     3
           :flag        true}
        e (manifest/entries m nil)]
    (is (= :string  (:type (e [:database/url]))))
    (is (= :set     (:type (e [:auth :admins]))))
    (is (= 2        (:count (e [:auth :admins]))))
    (is (= :integer (:type (e [:retries]))))
    (is (= :boolean (:type (e [:flag]))))
    (is (not (contains? (e [:database/url]) :vhash)) "no hmac key ⇒ no vhash")
    (is (not (contains? (e [:database/url]) :count)) "scalars have no :count")))

(deftest manifest-vhash-detects-value-change
  (let [hk (manifest/hmac-key (slurp *key*))]
    (is (contains? (get (manifest/entries {:k "v1"} hk) [:k]) :vhash))
    (is (= (manifest/entries {:k "v1"} hk)
           (manifest/entries {:k "v1"} hk))
        "stable for identical value + key")
    (is (not= (:vhash (get (manifest/entries {:k "v1"} hk) [:k]))
              (:vhash (get (manifest/entries {:k "v2"} hk) [:k])))
        "vhash changes when the value changes")
    (is (= (:vhash (get (manifest/entries {:s #{"a" "b"}} hk) [:s]))
           (:vhash (get (manifest/entries {:s #{"b" "a"}} hk) [:s])))
        "set element order does not affect vhash")))

(deftest manifest-render-round-trips
  (let [e (manifest/entries {:a 1 :b {:c "x"} :d #{:e}} nil)
        sha "a3f1c2d4e5b6978012345678901234567890123456789012345678901234abcd"]
    (testing "with a :ciphertext-sha it round-trips through the EDN"
      (let [parsed (edn/read-string (manifest/render {:app "myapp" :ciphertext-sha sha} e))]
        (is (= 1 (:version parsed)))
        (is (= "myapp" (:app parsed)))
        (is (= sha (:ciphertext-sha parsed)))
        (is (= e (:keys parsed)) "renders to EDN that reads back to the same entries")))
    (testing "omitted/nil :ciphertext-sha leaves the key out entirely"
      (doseq [hdr [{:app "myapp"} {:app "myapp" :ciphertext-sha nil}]]
        (let [parsed (edn/read-string (manifest/render hdr e))]
          (is (not (contains? parsed :ciphertext-sha)))
          (is (= e (:keys parsed))))))))

(deftest manifest-hmac-key-comment-insensitive
  (let [secret "AGE-SECRET-KEY-1QQPXZ6EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE"
        a (str "# created: 2026-01-01\n# public key: age1aaa\n" secret "\n")
        b (str "\n# created: 2026-07-14\n# public key: age1bbb\n  " secret "  \n\n")
        c (str "# created: 2026-01-01\n" secret "DIFFERENT\n")]
    (is (java.util.Arrays/equals (manifest/hmac-key a) (manifest/hmac-key b))
        "same secret line ⇒ same key, regardless of comments and whitespace")
    (is (not (java.util.Arrays/equals (manifest/hmac-key a) (manifest/hmac-key c)))
        "a different secret line ⇒ a different key")
    (testing "no AGE-SECRET-KEY line at all (e.g. an SSH identity) still works"
      (let [ssh "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"]
        (is (java.util.Arrays/equals (manifest/hmac-key ssh)
                                     (manifest/hmac-key (str "\n" ssh "\n")))
            "fallback path is stable (and whitespace-insensitive)")
        (is (not (java.util.Arrays/equals (manifest/hmac-key ssh) (manifest/hmac-key a))))))))

(deftest manifest-diff-test
  (testing "structure-only diff (nil key): sees add/remove/retype, not value edits"
    (let [a (manifest/entries {:x 1 :y "str"} nil)
          b (manifest/entries {:y 5 :z 3} nil)      ; :y string → integer
          d (manifest/diff a b)]
      (is (= [[:z]] (:added d)))
      (is (= [[:x]] (:removed d)))
      (is (= [[:y]] (:changed d)) "y retyped string → integer")))
  (testing "with a key, a same-type value edit shows up as :changed"
    (let [hk (manifest/hmac-key (slurp *key*))
          a  (manifest/entries {:token "old"} hk)
          b  (manifest/entries {:token "new"} hk)]
      (is (= [[:token]] (:changed (manifest/diff a b)))))))

(deftest blank-identity-env-var-throws
  (let [check #'secrets/identity-env-value]
    (testing "an unset variable is nil, and falls through to the next source"
      (is (nil? (check "SECRETS_AGE_IDENTITY" nil))))
    (testing "a set, non-blank value passes through verbatim"
      (is (= "  AGE-SECRET-KEY-1X\n" (check "SECRETS_AGE_IDENTITY" "  AGE-SECRET-KEY-1X\n")))
      (is (= "/keys/id.txt" (check "SECRETS_AGE_IDENTITY_FILE" "/keys/id.txt"))))
    (testing "set-but-empty throws instead of resolving to an unusable identity"
      (doseq [k ["SECRETS_AGE_IDENTITY_FILE" "SECRETS_AGE_IDENTITY" "SECRETS_AGE_IDENTITY_B64"]]
        (let [e (is (thrown-with-msg? clojure.lang.ExceptionInfo
                                      #"is set but empty"
                                      (check k "")))]
          (is (= k (:env (ex-data e))) "the error names the offending variable")
          (is (re-find (re-pattern k) (ex-message e))))))
    (testing "whitespace-only counts as empty — never a usable path or key"
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"is set but empty"
                            (check "SECRETS_AGE_IDENTITY" "   \n"))))))
