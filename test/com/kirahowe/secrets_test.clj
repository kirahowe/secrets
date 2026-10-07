(ns com.kirahowe.secrets-test
  "End-to-end tests exercising the real `age` binary. They require `age` and
  `age-keygen` on the PATH (brew install age). Each test runs in a throwaway
  temp directory with a freshly generated key."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.java.shell :as shell]
            [clojure.string :as str]
            [clojure.test :refer [are deftest is testing use-fixtures]]
            [clojure.test.check.generators :as gen]
            [com.kirahowe.secrets :as secrets]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.fs :as fs]
            [com.kirahowe.secrets.generators :as g]
            [com.kirahowe.secrets.manifest :as manifest]
            [com.kirahowe.secrets.safe-edn :as safe-edn]
            [com.kirahowe.secrets.source :as source]
            [com.kirahowe.secrets.test-env :as test-env]))

(def ^:dynamic ^:private *dir* nil)
(def ^:dynamic ^:private *key* nil)

(defn- with-tmp-key [f]
  (let [dir (str (java.nio.file.Files/createTempDirectory
                  "kira-secrets-test"
                  (into-array java.nio.file.attribute.FileAttribute [])))
        key-file (str dir "/key.txt")]
    (age/keygen! key-file)
    (binding [*dir* dir *key* key-file]
      (try
        (f)
        (finally
          (doseq [path (reverse (file-seq (io/file dir)))]
            (.delete path)))))))

(use-fixtures :each with-tmp-key)

;;;; Core runtime

(defn- encrypt-edn!
  "Write `m` as EDN, encrypt it to <dir>/secrets.edn.age, drop the plaintext,
  and return the ciphertext path. The optional identity makes wrong-key
  ciphertext fixtures possible without bypassing the real age CLI."
  ([m] (encrypt-edn! m *key*))
  ([m identity-file]
   (let [plain (str *dir* "/plain.edn")
         enc (str *dir* "/secrets.edn.age")]
     (spit plain (pr-str m))
     (age/encrypt-file! identity-file plain enc)
     (.delete (io/file plain))
     enc)))

(defn- permission-names
  "POSIX permissions of `path` itself, as names (`\"OWNER_READ\"` …). Names read
  better in a failure message than enum values, and they are what a reader
  checking an octal mode against these tests wants to see."
  [path]
  (set (map str (java.nio.file.Files/getPosixFilePermissions
                 (.toPath (io/file path))
                 (into-array java.nio.file.LinkOption [])))))

(def ^:private owner-only-names #{"OWNER_READ" "OWNER_WRITE"})

(deftest expand-home-test
  (let [home (System/getProperty "user.home")]
    (testing "only ~ and a leading ~/ name the home directory"
      (is (= home (secrets/expand-home "~")))
      (is (= (str home "/x") (secrets/expand-home "~/x")))
      (is (= (str home "/.config/x") (secrets/expand-home "~/.config/x"))))
    (testing "every other string is returned unchanged"
      (doseq [path ["~bob/x" "~~" "a~/x" "/abs/path" "" " "]]
        (is (= path (secrets/expand-home path)) (pr-str path))))
    (testing "nil becomes the empty string"
      (is (= "" (secrets/expand-home nil))))))

(deftest age-version-test
  (testing "successful stdout is trimmed"
    (with-redefs [shell/sh (fn [& args]
                             (is (= ["age" "--version"] args))
                             {:exit 0 :out "  age 1.2.3 \n" :err ""})]
      (is (= "age 1.2.3" (age/version)))))
  (testing "successful stderr is used when stdout is blank"
    (with-redefs [shell/sh (fn [& _]
                             {:exit 0 :out " \n" :err " age 1.2.3 \n"})]
      (is (= "age 1.2.3" (age/version)))))
  (testing "nonzero exit returns nil even with stderr"
    (with-redefs [shell/sh (fn [& _]
                             {:exit 1 :out "" :err "age failed with sensitive detail"})]
      (is (nil? (age/version)))))
  (testing "execution exceptions return nil"
    (with-redefs [shell/sh (fn [& _]
                             (throw (java.io.IOException. "age is unavailable")))]
      (is (nil? (age/version)))))
  (testing "installed status follows version presence"
    (with-redefs [age/version (constantly "age 1.2.3")]
      (is (true? (age/installed?))))
    (with-redefs [age/version (constantly nil)]
      (is (false? (age/installed?))))))

(deftest age-roundtrip-test
  (testing "encrypt then decrypt returns the original bytes"
    (let [enc (encrypt-edn! {:database/url "jdbc:postgresql://h/db"
                             :auth/admins #{"a@b.com" "c@d.com"}})]
      (is (.exists (io/file enc)))
      (is (not (re-find #"jdbc" (slurp enc))) "ciphertext does not leak plaintext")
      (let [m (secrets/load-secrets enc *key*)]
        (is (= "jdbc:postgresql://h/db" (secrets/get-secret m :database/url)))
        (is (= #{"a@b.com" "c@d.com"} (secrets/get-secret m :auth/admins))
            "native EDN sets survive the round trip")))))

(deftest get-secret-paths-test
  (let [m (secrets/load-secrets (encrypt-edn! {:r2 {:account-id "acc"}}) *key*)]
    (is (= "acc" (secrets/get-secret m [:r2 :account-id])))
    (is (nil? (secrets/get-secret m [:r2 :missing])))
    (is (= :dflt (secrets/get-secret m [:r2 :missing] :dflt)))
    (is (= :dflt (secrets/get-secret m :nope :dflt)))))

(deftest public-key-test
  (is (re-find #"^age1" (age/public-key *key*)))
  (is (nil? (age/public-key (str *dir* "/does-not-exist")))))

;;;; Command-line option boundary

(defn- with-cwd-entry
  "Run `(f entry)` on a working-directory entry named exactly `entry-name`,
  then delete it. A dash-leading argv element can only come from a
  cwd-relative path, so these fixtures cannot live in the absolute temp dir
  the rest of the suite uses. Refuses to touch a pre-existing entry rather
  than clobbering it, and cleans up even when an assertion fails."
  [entry-name f]
  (let [entry (io/file entry-name)]
    (when (.exists entry)
      (throw (ex-info "refusing to clobber an existing working-directory entry"
                      {:entry entry-name})))
    (try
      (f entry)
      (finally
        (doseq [p (reverse (file-seq entry))] (.delete p))))))

(deftest encrypt-input-named-like-an-age-option-test
  (testing "a plaintext file named --armor is encrypted, never read as a flag"
    (let [payload "{:option/boundary \"encrypt\"}"
          out (str *dir* "/armor-named-input.age")]
      (with-cwd-entry "--armor"
        (fn [in]
          (spit in payload)
          (age/encrypt-file! *key* (str in) out)
          (is (= payload (age/decrypt *key* out))
              "age encrypts the file rather than armoring an encryption of stdin"))))))

(deftest decrypt-input-named-like-an-age-option-test
  (let [payload "{:option/boundary \"decrypt\"}"
        plain (str *dir* "/option-named.edn")
        enc (str *dir* "/option-named.age")]
    (spit plain payload)
    (age/encrypt-file! *key* plain enc)
    (doseq [entry-name ["--version" "--help"]]
      (testing (str "a ciphertext named " entry-name " is decrypted as ciphertext")
        (with-cwd-entry entry-name
          (fn [ct]
            (io/copy (io/file enc) ct)
            (let [plaintext (String. (age/decrypt-bytes *key* (str ct)) "UTF-8")]
              (is (= payload plaintext) "the authenticated plaintext is returned")
              (is (seq plaintext) "age's empty option output is never plaintext")
              (is (not (re-find #"^v?\d+\.\d+\.\d+" plaintext))
                  "age's own version output is never plaintext"))))))))

(deftest dash-only-filename-is-a-path-not-stdin-test
  (let [payload "{:option/boundary \"dash\"}"]
    (testing "a plaintext file named - is encrypted instead of reading stdin"
      (let [out (str *dir* "/dash-input.age")]
        (with-cwd-entry "-"
          (fn [in]
            (spit in payload)
            (age/encrypt-file! *key* (str in) out)
            (is (= payload (age/decrypt *key* out)))))))
    (testing "a ciphertext named - is decrypted instead of reading stdin"
      (let [plain (str *dir* "/dash-plain.edn")
            enc (str *dir* "/dash-plain.age")]
        (spit plain payload)
        (age/encrypt-file! *key* plain enc)
        (with-cwd-entry "-"
          (fn [ct]
            (io/copy (io/file enc) ct)
            (is (= payload (age/decrypt *key* (str ct))))))))))

(deftest dash-leading-relative-paths-work-for-every-path-argument-test
  (let [payload "{:option/boundary \"relative\"}"
        plain "-secrets-boundary/plain.edn"
        identity-file "-secrets-boundary/key.txt"
        recipients-file "-secrets-boundary/recipients.txt"]
    (with-cwd-entry "-secrets-boundary"
      (fn [_]
        (io/make-parents plain)
        (spit plain payload)
        (io/copy (io/file *key*) (io/file identity-file))
        (spit recipients-file (str (age/public-key *key*) "\n"))
        (testing "input, output and identity file may all start with a dash"
          (let [out "-secrets-boundary/identity.age"]
            (age/encrypt-file! {:identity-file identity-file} plain out)
            (is (= payload (age/decrypt identity-file out)))))
        (testing "a dash-leading recipients file encrypts to that recipient"
          (let [out "-secrets-boundary/recipients.age"]
            (age/encrypt-file! {:recipients-file recipients-file} plain out)
            (is (= payload (age/decrypt *key* out)))))))))

(deftest a-file-named-dash-is-a-path-for-every-age-path-role-test
  (let [payload "{:option/boundary \"dash-roles\"}"
        plain (str *dir* "/dash-roles.edn")]
    (spit plain payload)
    (testing "an identity file named - is read from disk, never from stdin"
      (let [enc (str *dir* "/dash-roles-identity.age")]
        (age/encrypt-file! *key* plain enc)
        (with-cwd-entry "-"
          (fn [id]
            (io/copy (io/file *key*) id)
            (is (= payload (age/decrypt "-" enc)))))))
    (testing "a recipients file named - is read from disk, never from stdin"
      (let [out (str *dir* "/dash-roles-recipients.age")]
        (with-cwd-entry "-"
          (fn [rf]
            (spit rf (str (age/public-key *key*) "\n"))
            (age/encrypt-file! {:recipients-file "-"} plain out)))
        (is (= payload (age/decrypt *key* out)))))
    (testing "an output named - is a file, never stdout"
      (with-cwd-entry "-"
        (fn [out]
          (age/encrypt-file! *key* plain "-")
          (is (.isFile out) "age wrote a file rather than streaming to stdout")
          (is (= payload (age/decrypt *key* "-"))))))))

;; A deliberate argv-shape test. `path-arg` already rewrites a dash-leading
;; positional to `./-name`, so dropping the `--` terminator changes nothing a
;; behavioural test can observe; only the terminator's position in the argv
;; pins it down. The `age --version` probe is answered so that
;; `ensure-installed!` still passes.
(deftest age-argv-shape-test
  (let [calls (atom [])
        recording (fn [result]
                    (fn [& args]
                      (let [argv (vec (take-while string? args))]
                        (if (= ["age" "--version"] argv)
                          {:exit 0 :out "v1.3.1" :err ""}
                          (do (swap! calls conj argv) result)))))
        encrypt-argv (fn [recipients in out]
                       (reset! calls [])
                       (with-redefs [shell/sh (recording {:exit 0 :err ""})]
                         (age/encrypt-file! recipients in out))
                       (first @calls))
        decrypt-argv (fn [identity-file in]
                       (reset! calls [])
                       ;; `sh` cannot bound the plaintext it captures, so
                       ;; decryption runs at the bounded-stream seam and the
                       ;; argv is recorded there. `sh` answers only the
                       ;; `age --version` probe.
                       (with-redefs [shell/sh (recording {:exit 0 :out (byte-array 0) :err ""})
                                     age/stream-bounded-stdout!
                                     (fn [argv & _]
                                       (swap! calls conj (vec argv))
                                       {:exit 0 :err ""})]
                         (age/decrypt-bytes identity-file in))
                       (first @calls))]
    (testing "the encrypt terminator sits immediately before the input operand"
      (let [argv (encrypt-argv "key.txt" "-in.edn" "out.age")]
        (is (= ["--" "./-in.edn"] (take-last 2 argv)) (pr-str argv))
        (is (= ["age" "-e" "-i" "key.txt" "-o" "out.age" "--" "./-in.edn"] argv))))
    (testing "the decrypt terminator sits immediately before the input operand"
      (let [argv (decrypt-argv "key.txt" "-in.age")]
        (is (= ["--" "./-in.age"] (take-last 2 argv)) (pr-str argv))
        (is (= ["age" "-d" "-i" "key.txt" "--" "./-in.age"] argv))))
    (testing "a recipient is a recipient string, not a path, so it passes verbatim"
      (is (= ["age" "-e" "-r" "-not-a-path" "-o" "out.age" "--" "plain.edn"]
             (encrypt-argv {:recipients ["-not-a-path"]} "plain.edn" "out.age"))))
    (testing "-i, -R and -o render an exact - as ./-"
      (is (= ["age" "-e" "-i" "./-" "-R" "./-" "-o" "./-" "--" "plain.edn"]
             (encrypt-argv {:identity-file "-" :recipients-file "-"} "plain.edn" "-")))
      (is (= ["age" "-d" "-i" "./-" "--" "plain.age"] (decrypt-argv "-" "plain.age"))))))

(deftest blank-and-nil-age-paths-fail-closed-test
  (let [plain (str *dir* "/blank-source.edn")
        enc (str *dir* "/blank-source.age")]
    (spit plain "{:option/boundary \"blank\"}")
    (age/encrypt-file! *key* plain enc)
    (testing "a blank or nil encrypt input is refused, never taken as stdin"
      (doseq [[label in] [["empty" ""] ["spaces" "   "] ["nil" nil]]]
        (let [out (str *dir* "/blank-" label ".age")]
          (is (thrown-with-msg? clojure.lang.ExceptionInfo #"blank"
                                (age/encrypt-file! *key* in out))
              (str "input " (pr-str in) " names no file"))
          (is (not (.exists (io/file out)))
              (str "nothing is written for input " (pr-str in))))))
    (testing "a blank or nil decrypt input is refused, never taken as stdin"
      (doseq [in ["" "   " nil]]
        (is (thrown-with-msg? clojure.lang.ExceptionInfo #"blank"
                              (age/decrypt-bytes *key* in))
            (str "input " (pr-str in) " names no file"))))
    (testing "a blank identity file is refused on both paths"
      (let [out (str *dir* "/blank-identity.age")]
        (is (thrown-with-msg? clojure.lang.ExceptionInfo #"blank"
                              (age/encrypt-file! "" plain out)))
        (is (not (.exists (io/file out))) "nothing is written for a blank identity")
        (is (thrown-with-msg? clojure.lang.ExceptionInfo #"blank"
                              (age/decrypt-bytes "" enc)))))
    (testing "a blank output, a blank recipients file and a nil identity fail closed"
      (let [out (str *dir* "/blank-role.age")]
        (is (thrown-with-msg? clojure.lang.ExceptionInfo #"blank"
                              (age/encrypt-file! *key* plain "")))
        (is (thrown-with-msg? clojure.lang.ExceptionInfo #"blank"
                              (age/encrypt-file! {:recipients-file ""} plain out)))
        (is (thrown-with-msg? clojure.lang.ExceptionInfo #"blank"
                              (age/encrypt-file! nil plain out))
            "a bare nil names a blank identity file, not \"no recipients at all\"")
        (is (not (.exists (io/file out))) "nothing is written for any blank role")))
    (testing "keygen! refuses a blank path instead of resolving to a directory"
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"blank" (age/keygen! ""))))))

(deftest invalid-age-paths-run-no-subprocesses-test
  (let [shell-calls (atom 0)
        invalid-calls
        [["nil keygen path" #(age/keygen! nil)]
         ["whitespace keygen path" #(age/keygen! "   ")]
         ["nil identity-file map path"
          #(age/encrypt-file! {:identity-file nil
                               :recipients ["age1-valid-looking-recipient-value"]}
                              "plain"
                              "out")]
         ["whitespace identity-file map path"
          #(age/encrypt-file! {:identity-file "   "
                               :recipients ["age1-valid-looking-recipient-value"]}
                              "plain"
                              "out")]
         ["nil recipients-file map path"
          #(age/encrypt-file! {:recipients-file nil} "plain" "out")]
         ["whitespace recipients-file map path"
          #(age/encrypt-file! {:recipients-file "   "} "plain" "out")]
         ["nil encrypt output" #(age/encrypt-file! "key" "plain" nil)]
         ["whitespace encrypt output" #(age/encrypt-file! "key" "plain" "   ")]
         ["nil encrypt input" #(age/encrypt-file! "key" nil "out")]
         ["whitespace encrypt input" #(age/encrypt-file! "key" "   " "out")]
         ["nil decrypt identity" #(age/decrypt-bytes nil "cipher")]
         ["whitespace decrypt identity" #(age/decrypt-bytes "   " "cipher")]
         ["nil decrypt input" #(age/decrypt-bytes "key" nil)]
         ["whitespace decrypt input" #(age/decrypt-bytes "key" "   ")]]]
    (with-redefs [shell/sh (fn [& _]
                             (swap! shell-calls inc)
                             (throw (ex-info "subprocess ran" {})))
                  age/stream-bounded-stdout! (fn [& _]
                                               (swap! shell-calls inc)
                                               (throw (ex-info "subprocess ran" {})))]
      (doseq [[label invoke] invalid-calls]
        (reset! shell-calls 0)
        (is (thrown-with-msg? clojure.lang.ExceptionInfo #"blank" (invoke)) label)
        (is (zero? @shell-calls)
            (str label " must fail before probing or running a subprocess"))))))

(deftest age-path-handling-control-test
  (testing "no-regression control: absolute paths still round trip"
    (let [payload "{:option/boundary \"control\"}"
          plain (str *dir* "/control.edn")
          out (str *dir* "/control.age")]
      (spit plain payload)
      (age/encrypt-file! *key* plain out)
      (is (= payload (age/decrypt *key* out)))
      (testing "and a :recipients list of literal age1… strings is untouched"
        (let [multi (str *dir* "/control-multi.age")]
          (age/encrypt-file! {:recipients [(age/public-key *key*)]} plain multi)
          (is (= payload (age/decrypt *key* multi)))))
      (testing "and the wrong key still fails with the original message"
        (let [other (str *dir* "/control-other-key.txt")]
          (age/keygen! other)
          (is (thrown-with-msg? clojure.lang.ExceptionInfo #"age decryption failed"
                                (age/decrypt other out))))))))

;;;; Reader literals

(deftest reader-literals-present-test
  (let [enc (encrypt-edn! {:database/url "jdbc:x" :llm/api-key "sk-123"})
        readers (secrets/reader-literals {:file enc :identity-file *key*})
        cfg (edn/read-string
             {:readers readers}
             "{:url #secret/req :database/url
                   :key #secret/opt :llm/api-key
                   :absent #secret/opt :not-there}")]
    (is (= "jdbc:x" (:url cfg)))
    (is (= "sk-123" (:key cfg)))
    (is (nil? (:absent cfg)) "#secret/opt on a missing key is nil")))

(deftest reader-required-missing-throws-test
  (let [enc (encrypt-edn! {:present 1})
        readers (secrets/reader-literals {:file enc :identity-file *key*})]
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #":totally-absent is missing from the secrets file"
         (edn/read-string {:readers readers} "#secret/req :totally-absent"))
        "the error names the missing key rather than failing generically")))

(deftest reader-absent-file-test
  (testing "no secrets file on disk: #secret/opt → nil, #secret/req → throws"
    (let [readers (secrets/reader-literals {:file (str *dir* "/nope.age")
                                            :identity-file *key*})]
      (is (nil? (edn/read-string {:readers readers} "#secret/opt :anything")))
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo #"no secrets file found"
           (edn/read-string {:readers readers} "#secret/req :anything"))))))

(deftest reader-absent-identity-test
  (testing "present secrets file with missing identity: opt returns nil and req throws"
    (let [enc (encrypt-edn! {:k "v"})
          readers (secrets/reader-literals {:file enc
                                            :identity-file
                                            (str *dir* "/no-such-key.txt")})]
      (is (nil? (edn/read-string {:readers readers} "#secret/opt :k")))
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo #"identity"
           (edn/read-string {:readers readers} "#secret/req :k"))))))

(deftest reader-decrypts-once-test
  (testing "many secret tags share a single decryption"
    (let [enc (encrypt-edn! {:a 1 :b 2 :c 3})
          calls (atom 0)
          real age/decrypt]
      (with-redefs [age/decrypt (fn [& args]
                                  (swap! calls inc)
                                  (apply real args))]
        (let [readers (secrets/reader-literals {:file enc :identity-file *key*})
              cfg (edn/read-string
                   {:readers readers}
                   "[#secret/req :a #secret/req :b #secret/opt :c #secret/opt :missing]")]
          (is (= [1 2 3 nil] cfg))
          (is (= 1 @calls) "decryption is memoized for this readers map"))))))

(deftest reader-cache-lifecycle-test
  (testing "one readers map keeps its load; a new map sees edited ciphertext"
    (let [enc (encrypt-edn! {:v :before})
          calls (atom 0)
          real age/decrypt]
      (with-redefs [age/decrypt (fn [& args]
                                  (swap! calls inc)
                                  (apply real args))]
        (let [readers (secrets/reader-literals {:file enc :identity-file *key*})]
          (is (= :before
                 (edn/read-string {:readers readers} "#secret/req :v")))
          (encrypt-edn! {:v :after})
          (is (= :before
                 (edn/read-string {:readers readers} "#secret/req :v"))
              "the original readers map keeps its first loaded store")
          (is (= :after
                 (edn/read-string
                  {:readers (secrets/reader-literals
                             {:file enc :identity-file *key*})}
                  "#secret/req :v"))
              "recreating the readers map decrypts the current ciphertext")
          (is (= 2 @calls)
              "each native readers map decrypts its store at most once"))))))

(deftest reader-caches-real-decryption-failure-test
  (testing "a wrong-key failure stays cached until the readers map is recreated"
    (let [wrong-key (str *dir* "/wrong-key.txt")
          _ (age/keygen! wrong-key)
          enc (encrypt-edn! {:v :unreadable} wrong-key)
          calls (atom 0)
          real age/decrypt]
      (with-redefs [age/decrypt (fn [& args]
                                  (swap! calls inc)
                                  (apply real args))]
        (let [readers (secrets/reader-literals {:file enc :identity-file *key*})]
          (is (thrown-with-msg?
               clojure.lang.ExceptionInfo #"age decryption failed"
               (edn/read-string {:readers readers} "#secret/req :v"))
              "the first read genuinely asks age to decrypt wrong-key ciphertext")
          (encrypt-edn! {:v :repaired})
          (is (thrown-with-msg?
               clojure.lang.ExceptionInfo #"age decryption failed"
               (edn/read-string {:readers readers} "#secret/req :v"))
              "repairing the ciphertext does not retry a cached failure")
          (is (= 1 @calls)
              "the same readers map rethrows the cached decryption failure")
          (is (= :repaired
                 (edn/read-string
                  {:readers (secrets/reader-literals
                             {:file enc :identity-file *key*})}
                  "#secret/req :v"))
              "a newly constructed readers map decrypts the repaired ciphertext")
          (is (= 2 @calls)
              "only the new readers map performs the successful retry"))))))

;;;; Operation-owned identities

(deftest operation-owned-identity-test
  (let [enc (encrypt-edn! {:k "v"})
        contents (slurp *key*)
        paths (atom [])
        real-decrypt age/decrypt]
    (testing "raw injected identity decrypts and is private only while used"
      (with-redefs-fn
        (merge (test-env/getenv-redefs {"SECRETS_AGE_IDENTITY" contents})
               {#'age/decrypt (fn [identity & args]
                                (swap! paths conj identity)
                                (is (= owner-only-names (permission-names identity)))
                                (apply real-decrypt identity args))})
        (fn []
          (is (= {:k "v"} (secrets/load-secrets enc nil)))))
      (is (= 1 (count @paths)))
      (is (not (.exists (io/file (first @paths))))))
    (testing "base64 has the same scoped lifecycle"
      (let [encoded (.encodeToString (java.util.Base64/getEncoder)
                                     (.getBytes contents "UTF-8"))
            path (atom nil)]
        (with-redefs-fn
          (test-env/getenv-redefs {"SECRETS_AGE_IDENTITY_B64" encoded})
          (fn []
            (is (= {:k "v"}
                   (secrets/with-identity nil
                     (fn [{:keys [identity-file]}]
                       (reset! path identity-file)
                       (secrets/load-secrets enc identity-file)))))))
        (is (not (.exists (io/file @path))))))))

(deftest operation-owned-identity-cleanup-test
  (let [contents (slurp *key*)
        path (atom nil)]
    (testing "callback failures still delete the temporary identity"
      (with-redefs-fn
        (test-env/getenv-redefs {"SECRETS_AGE_IDENTITY" contents})
        (fn []
          (let [e (try
                    (secrets/with-identity nil
                      (fn [{:keys [identity-file]}]
                        (reset! path identity-file)
                        (throw (ex-info "callback failed" {:reason :callback-failed}))))
                    (catch clojure.lang.ExceptionInfo e e))]
            (is (= :callback-failed (:reason (ex-data e)))))))
      (is (not (.exists (io/file @path)))))
    (testing "a failed write removes its partial temporary file"
      (let [created (atom nil)
            real-temp fs/owner-only-temp-file!
            real-spit spit
            write-sentinel "SENSITIVE-IDENTITY-WRITE-FAILURE"]
        (with-redefs-fn
          (merge (test-env/getenv-redefs {"SECRETS_AGE_IDENTITY" contents})
                 {#'fs/owner-only-temp-file! (fn [& args]
                                               (let [file (apply real-temp args)]
                                                 (reset! created file)
                                                 file))
                  #'clojure.core/spit (fn [file _]
                                        (real-spit file "partial identity")
                                        (throw (java.io.IOException. write-sentinel)))})
          (fn []
            (let [e (try (secrets/with-identity nil identity)
                         (catch clojure.lang.ExceptionInfo e e))]
              (is (= :identity-not-materialized (:reason (ex-data e))))
              (is (nil? (ex-cause e)))
              (is (not (str/includes? (pr-str e) write-sentinel))))))
        (is (not (.exists ^java.io.File @created)))))
    (testing "an Error during the write removes the file and propagates as itself"
      (let [created (atom nil)
            real-temp fs/owner-only-temp-file!
            real-spit spit
            failure (Error. "forced write error")]
        (with-redefs-fn
          (merge (test-env/getenv-redefs {"SECRETS_AGE_IDENTITY" contents})
                 {#'fs/owner-only-temp-file! (fn [& args]
                                               (reset! created (apply real-temp args)))
                  #'clojure.core/spit (fn [file _]
                                        (real-spit file "partial identity")
                                        (throw failure))})
          (fn []
            (is (identical? failure (try (secrets/with-identity nil identity)
                                         (catch Throwable t t))))))
        (is (some? @created))
        (is (not (.exists ^java.io.File @created)))))
    (testing "a write failure names a file its cleanup could not delete"
      (doseq [[label failure delete!]
              [["an Error carries the cleanup failure as suppressed"
                (Error. "forced write error") (constantly false)]
               ["a delete that throws cannot replace the write failure"
                (java.io.IOException. "forced write failure")
                (fn [_] (throw (IllegalStateException. "forced delete failure")))]]]
        (testing label
          (let [created (atom nil)
                real-temp fs/owner-only-temp-file!]
            (try
              (let [thrown (with-redefs-fn
                             (merge (test-env/getenv-redefs {"SECRETS_AGE_IDENTITY" contents})
                                    {#'fs/owner-only-temp-file!
                                     (fn [& args] (reset! created (apply real-temp args)))
                                     #'clojure.core/spit (fn [_ _] (throw failure))
                                     #'secrets/try-delete-identity-file! delete!})
                             (fn []
                               (try (secrets/with-identity nil identity)
                                    (catch Throwable t t))))
                    leftover (.getAbsolutePath ^java.io.File @created)
                    cleanup (if (instance? Error failure)
                              (some-> ^Throwable thrown .getSuppressed first ex-data)
                              (:cleanup (ex-data thrown)))]
                (if (instance? Error failure)
                  (is (identical? failure thrown))
                  (is (= :identity-not-materialized (:reason (ex-data thrown)))))
                (is (= {:reason :identity-cleanup-failed
                        :identity-file leftover
                        :identity-source :secrets-age-identity}
                       cleanup)))
              (finally
                (some-> ^java.io.File @created .delete)))))))
    (testing "deletion failures report each leftover, including when the callback fails"
      (doseq [body-fails? [false true]]
        (with-redefs-fn
          (merge (test-env/getenv-redefs {"SECRETS_AGE_IDENTITY" contents})
                 {#'secrets/try-delete-identity-file! (constantly false)})
          (fn []
            (try
              (let [e (try
                        (secrets/with-identity nil
                          (fn [{:keys [identity-file]}]
                            (reset! path identity-file)
                            (if body-fails?
                              (throw (ex-info "callback failed" {:reason :callback-failed}))
                              :completed)))
                        (catch clojure.lang.ExceptionInfo e e))
                    data (ex-data e)
                    cleanup (if body-fails? (:cleanup data) data)]
                (is (= :identity-cleanup-failed (:reason cleanup)))
                (is (= @path (:identity-file cleanup)))
                (is (.exists (io/file @path)))
                (when body-fails?
                  (is (= :callback-failed (:reason data)))))
              (finally
                (when @path (.delete (io/file @path)))))))))))

(deftest operation-owned-identities-are-independent-test
  (let [contents (slurp *key*)
        entered (promise)
        release (promise)
        work (fn []
               (secrets/with-identity nil
                 (fn [{:keys [identity-file]}]
                   (deliver entered identity-file)
                   (deref release 10000 :timed-out))))]
    (with-redefs-fn
      (test-env/getenv-redefs {"SECRETS_AGE_IDENTITY" contents})
      (fn []
        (let [one (future (work))
              first-path (deref entered 10000 nil)
              second-path (secrets/with-identity nil
                            (fn [{:keys [identity-file]}] identity-file))]
          (try
            (is (not= first-path second-path))
            (is (not (.exists (io/file second-path))) "the second scope already cleaned up")
            (is (.exists (io/file first-path)) "the first scope still owns its file")
            (finally
              (deliver release :done)))
          (is (= :done (deref one 10000 :timed-out)))
          (is (not (.exists (io/file first-path)))))))))

(deftest b64-identity-decode-test
  (let [decode @#'secrets/decode-b64-identity
        raw "AGE-SECRET-KEY-1EXAMPLE\n"
        b64 (.encodeToString (java.util.Base64/getEncoder)
                             (.getBytes raw "UTF-8"))
        whitespace [["space" " "]
                    ["horizontal tab" "\t"]
                    ["carriage return" "\r"]
                    ["line feed" "\n"]]
        invalid [["junk at the beginning" "%QUJD"]
                 ["junk in the middle" "QU%JD"]
                 ["junk at the end" "QUJD%%%"]
                 ["other punctuation" "QUJ!D"]
                 ["Unicode nonbreaking space" "QU\u00A0JD"]
                 ["Unicode em space" "QU\u2003JD"]
                 ["padding at the beginning" "=QUJD"]
                 ["padding in the middle" "QU=JD"]
                 ["short padding" "Zg="]
                 ["excess padding" "Zg==="]
                 ["one-character length" "A"]
                 ["five-character length" "ABCDE"]
                 ["omitted double padding" "Zg"]
                 ["omitted single padding" "Zm8"]
                 ["nonzero padding bits" "Zh=="]]]
    (testing "canonical unwrapped base64 round-trips"
      (is (= raw (decode b64)))
      (is (= "\uFFFF" (decode "77+/"))
          "the standard alphabet's + and / boundaries remain valid"))
    (testing "only documented ASCII transport whitespace is removed"
      (doseq [[label s] whitespace
              [position wrapped] [["beginning" (str s b64)]
                                  ["middle" (str (subs b64 0 2) s (subs b64 2))]
                                  ["end" (str b64 s)]]]
        (is (= raw (decode wrapped)) (str label " at the " position)))
      (is (= raw (decode (str "\t" (subs b64 0 8) "\r\n"
                              (subs b64 8) " ")))
          "mixed wrapping and multiline transport round-trips"))
    (testing "junk, Unicode whitespace, malformed padding, and ambiguous encodings fail"
      (doseq [[label value] invalid]
        (let [e (try (decode value)
                     nil
                     (catch clojure.lang.ExceptionInfo e e))]
          (is (some? e) label)
          (when e
            (is (= {:env "SECRETS_AGE_IDENTITY_B64"} (ex-data e)) label)
            (is (re-find #"SECRETS_AGE_IDENTITY_B64.*base64-encoded"
                         (ex-message e))
                label)
            (is (nil? (ex-cause e)) label)))))))

(deftest b64-identity-input-boundary-test
  (let [invalid "QUJD%%%identity-token-sentinel"
        materializations (atom 0)]
    (with-redefs-fn
      (merge (test-env/getenv-redefs {"SECRETS_AGE_IDENTITY_B64" invalid})
             {#'fs/owner-only-temp-file!
              (fn [& _]
                (swap! materializations inc)
                "unreachable")})
      (fn []
        (let [e (try (secrets/with-identity nil identity)
                     nil
                     (catch clojure.lang.ExceptionInfo e e))
              rendered (str (pr-str e) (pr-str (ex-data e)) (ex-message e))]
          (is (= {:env "SECRETS_AGE_IDENTITY_B64"} (ex-data e)))
          (is (re-find #"base64-encoded age key file contents" (ex-message e)))
          (is (str/includes? (ex-message e) "SECRETS_AGE_IDENTITY"))
          (is (nil? (ex-cause e)))
          (is (not (str/includes? rendered invalid)))
          (is (zero? @materializations)
              "invalid input is rejected before identity materialization"))))))

(deftest load-secrets-opts-map-test
  (let [enc (encrypt-edn! {:k "v"})]
    (is (= {:k "v"} (secrets/load-secrets enc {:identity-file *key*})))
    (is (thrown-with-msg?
         clojure.lang.ExceptionInfo #"(?i)no age identity.*SECRETS_AGE_IDENTITY_FILE"
         (secrets/load-secrets enc {:identity-file (str *dir* "/nope")}))
        "a nonexistent identity file throws with the remediation options")))

;;;; Load-secrets errors

(deftest load-secrets-nil-source-throws-test
  (testing "nil source names the classpath-resource cause"
    (let [e (is (thrown-with-msg?
                 clojure.lang.ExceptionInfo #"(?i)source is nil"
                 (secrets/load-secrets nil *key*)))]
      (is (= :no-file (:reason (ex-data e))))
      (is (nil? (:source (ex-data e))))
      (is (re-find #"(?i)classpath" (ex-message e)))
      (is (re-find #"bb secrets new" (ex-message e))))))

(deftest load-secrets-missing-file-throws-test
  (testing "a missing path names the path rather than throwing FileNotFoundException"
    (let [missing (str *dir* "/nope.edn.age")
          e (is (thrown-with-msg?
                 clojure.lang.ExceptionInfo #"(?i)secrets file not found"
                 (secrets/load-secrets missing *key*)))]
      (is (= :no-file (:reason (ex-data e))))
      (is (= {:kind :file :path missing} (:source (ex-data e)))
          "a caller-supplied path is kept: it is the caller's own, and it is the answer")
      (is (re-find (re-pattern (java.util.regex.Pattern/quote missing)) (ex-message e))
          "the error names the offending path")
      (is (re-find #"bb secrets new" (ex-message e))))))

(deftest load-secrets-missing-identity-throws-test
  (testing "missing identity file: :reason :no-identity, wording unchanged"
    (let [enc (encrypt-edn! {:k "v"})
          e (is (thrown-with-msg?
                 clojure.lang.ExceptionInfo #"(?i)no age identity.*SECRETS_AGE_IDENTITY_FILE"
                 (secrets/load-secrets enc (str *dir* "/no-such-key.txt"))))]
      (is (= :no-identity (:reason (ex-data e)))))))

(deftest load-secrets-success-unaffected-test
  (testing "a successful load is unaffected by the new error paths"
    (let [enc (encrypt-edn! {:k "v"})]
      (is (= {:k "v"} (secrets/load-secrets enc *key*))))))

(defn- jar-source!
  "Write `encrypted` as `entry` in a local jar and return its `jar:file:` URI."
  [encrypted jar-name entry]
  (let [jar (io/file *dir* jar-name)]
    (with-open [zos (java.util.zip.ZipOutputStream. (io/output-stream jar))]
      (.putNextEntry zos (java.util.zip.ZipEntry. entry))
      (io/copy (io/file encrypted) zos)
      (.closeEntry zos))
    (java.net.URI. (str "jar:" (.toURI jar) "!/" entry))))

(def ^:private ^:dynamic *guarded-url-spec* nil)
(def ^:private ^:dynamic *guarded-url-invocations* nil)

(defn- guarded-url
  "Build a JVM-only URL whose handler records every method policy must avoid.

  The fixed form is read at runtime so Babashka never resolves the JVM-only
  `URLStreamHandler` class while analyzing this test namespace."
  [spec invoked]
  (binding [*ns* (the-ns 'com.kirahowe.secrets-test)
            *guarded-url-spec* spec
            *guarded-url-invocations* invoked]
    (eval
     (read-string
      "(java.net.URL.
        nil *guarded-url-spec*
        (proxy [java.net.URLStreamHandler] []
          (openConnection [_]
            (swap! *guarded-url-invocations* inc)
            (throw (AssertionError. \"A caller-provided URL handler was opened.\")))
          (toExternalForm [url]
            (swap! *guarded-url-invocations* inc)
            (proxy-super toExternalForm url))))"))))

(deftest local-source-loading-test
  (let [enc (encrypt-edn! {:from :local})
        file (io/file enc)
        file-uri (.toURI file)
        jar-uri (jar-source! enc "app.jar" "secrets.edn.age")]
    (testing "filesystem paths and local file locators remain accepted"
      (doseq [source [enc file (.toPath file) (str file-uri) file-uri (.toURL file-uri)]]
        (is (= {:from :local} (secrets/load-secrets source *key*)))))
    (testing "local classpath jar resources remain accepted"
      (doseq [source [(str jar-uri) jar-uri (.toURL jar-uri)]]
        (is (= {:from :local} (secrets/load-secrets source *key*)))))
    (testing "an allowed-looking caller URL cannot substitute its own I/O handler"
      (if (System/getProperty "babashka.version")
        (is true "JVM-only hostile URLStreamHandler coverage")
        (doseq [spec [(str file-uri) (str jar-uri)]]
          (let [invoked (atom 0)]
            (is (= {:from :local}
                   (secrets/load-secrets (guarded-url spec invoked) *key*)))
            (is (zero? @invoked)
                "classification avoids handler rendering and I/O dispatch")))))))

;;;; Multi-recipient encryption

(deftest valid-recipient?-test
  (is (age/valid-recipient? (age/public-key *key*)))
  (is (age/valid-recipient? "  age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p  "))
  (is (not (age/valid-recipient? "not-a-key")))
  (is (not (age/valid-recipient? nil))))

(deftest multi-recipient-roundtrip-test
  (testing "a file encrypted to two recipients decrypts with either key"
    (let [key2 (str *dir* "/key2.txt")
          _ (age/keygen! key2)
          pub1 (age/public-key *key*)
          pub2 (age/public-key key2)
          plain (str *dir* "/p.edn")
          enc (str *dir* "/multi.edn.age")]
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

(deftest single-key-still-works-test
  (testing "passing a bare identity path encrypts to that identity (back-compat)"
    (let [plain (str *dir* "/p.edn")
          enc (str *dir* "/single.edn.age")]
      (spit plain (pr-str {:y 2}))
      (age/encrypt-file! *key* plain enc)
      (is (= {:y 2} (secrets/load-secrets enc *key*))))))

(deftest bare-public-key-guard-test
  (testing "a bare age1… public key is rejected as an identity-file path"
    (let [plain (str *dir* "/p.edn")]
      (spit plain (pr-str {:z 3}))
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo #":recipients"
           (age/encrypt-file! (age/public-key *key*)
                              plain
                              (str *dir* "/x.age")))))))

(deftest binary-roundtrip-test
  (testing "decrypt-bytes preserves binary plaintext exactly"
    (let [payload (byte-array (mapv unchecked-byte [0 1 2 255 254 10 13]))
          plain (io/file *dir* "bin.dat")
          enc (str *dir* "/bin.dat.age")]
      (io/copy payload plain)
      (age/encrypt-file! *key* plain enc)
      (is (java.util.Arrays/equals payload (age/decrypt-bytes *key* enc))))))

;;;; Atomic moves

(deftest atomic-move-replaces-the-target-entry-test
  (testing "Path, File, and string arguments all move, and the target is returned"
    (doseq [[label coerce] [["string" str] ["File" io/file] ["Path" #(.toPath (io/file %))]]]
      (let [source (str *dir* "/move-source-" label)
            target (str *dir* "/move-target-" label)]
        (spit source "fresh")
        (spit target "stale")
        (is (= (coerce target) (fs/atomic-move! (coerce source) (coerce target))) label)
        (is (= "fresh" (slurp target)) label)
        (is (not (.exists (io/file source))) label))))
  (testing "a link at the target is replaced as a link, never written through"
    (let [canary (str *dir* "/move-canary")
          source (str *dir* "/move-source")
          link (str *dir* "/move-link")]
      (spit canary "canary")
      (spit source "fresh")
      (java.nio.file.Files/createSymbolicLink
       (.toPath (io/file link)) (.toPath (io/file canary))
       (into-array java.nio.file.attribute.FileAttribute []))
      (fs/atomic-move! source link)
      (is (= "canary" (slurp canary)) "the link's old target is untouched")
      (is (not (java.nio.file.Files/isSymbolicLink (.toPath (io/file link)))))
      (is (= "fresh" (slurp link)))))
  (testing "an ordinary failure propagates unchanged and leaves the source"
    (let [source (str *dir* "/move-kept")]
      (spit source "kept")
      (is (thrown? java.io.IOException
                   (fs/atomic-move! source (str *dir* "/no-such-dir/target"))))
      (is (= "kept" (slurp source))))))

(deftest keygen-replaces-an-existing-key-through-the-atomic-move-test
  (let [key-file (io/file *dir* "replaced-key.txt")
        _ (age/keygen! key-file)
        before (slurp key-file)
        moves (atom [])
        real-move fs/atomic-move!]
    (testing "a failed move leaves the existing key whole and no staging behind"
      (with-redefs [fs/atomic-move! (fn [& _] (throw (ex-info "forced move failure" {})))]
        (is (thrown-with-msg? clojure.lang.ExceptionInfo #"forced move failure"
                              (age/keygen! key-file))))
      (is (= before (slurp key-file)))
      (is (empty? (filter #(str/includes? % ".keygen") (seq (.list (io/file *dir*)))))))
    (testing "the new key reaches its path by one atomic move from inside its directory"
      (with-redefs [fs/atomic-move! (fn [source target]
                                      (swap! moves conj [(io/file (str source))
                                                         (io/file (str target))])
                                      (real-move source target))]
        (let [recipient (age/keygen! key-file)]
          (is (= recipient (age/public-key key-file)))))
      (let [[[source target]] @moves]
        (is (= 1 (count @moves)))
        (is (= (.getAbsoluteFile key-file) target))
        (is (= (.getParentFile target) (.getParentFile (.getParentFile source)))))
      (is (not= before (slurp key-file)))
      (is (= owner-only-names (permission-names key-file))))))

;;;; Fixed bounds

(defn- with-bound
  "Run `f` with the private bound constant held by var `v` set to `n`."
  [v n f]
  (with-redefs-fn {v n} f))

(defn- temp-source-copies
  "The ciphertext temp copies `source/acquire!` may have left behind, by name."
  []
  (set (filterv #(re-matches #"^secrets-.*\.age$" %)
                (seq (.list (io/file (System/getProperty "java.io.tmpdir")))))))

(defn- acquire-source
  "Run `source/acquire!` with the source bound set to `limit`, running any
  cleanup, and return `[:ok byte-count]` or the failure `:reason`."
  [source limit]
  (with-bound #'source/max-source-bytes limit
    #(try
       (let [[f cleanup!] (source/acquire! source (source/descriptor source))]
         (try [:ok (.length f)] (finally (cleanup!))))
       (catch clojure.lang.ExceptionInfo e (:reason (ex-data e))))))

(defn- source-policy-failure
  "Return the policy exception for `source`, asserting the load did not proceed."
  [source]
  (let [e (try
            (secrets/load-secrets source *key*)
            nil
            (catch clojure.lang.ExceptionInfo e e))]
    (is (some? e) "the source must be rejected")
    e))

(defn- tracked-http-source!
  "Start a loopback endpoint, returning its URL, request signal, and cleanup."
  [response]
  (let [server (java.net.ServerSocket. 0)
        requested (promise)
        worker (future
                 (try
                   (with-open [socket (.accept server)]
                     (deliver requested true)
                     (if response
                       (let [out (.getOutputStream socket)]
                         (.write out (.getBytes ^String response "UTF-8"))
                         (.flush out))
                       (Thread/sleep 5000)))
                   (catch java.net.SocketException _)
                   (finally
                     (.close server))))]
    {:url (str "http://127.0.0.1:" (.getLocalPort server) "/store.age")
     :requested requested
     :cleanup! (fn []
                 (.close server)
                 (future-cancel worker))}))

(defn- encrypt-sized!
  "Encrypt a store whose EDN plaintext is exactly `n` bytes and return the
  ciphertext path."
  [n label]
  (let [pad (- n (count "{:pad \"\"}"))
        plain (str *dir* "/" label ".edn")
        enc (str *dir* "/" label ".age")]
    (spit plain (str "{:pad \"" (apply str (repeat pad \a)) "\"}"))
    (age/encrypt-file! *key* plain enc)
    (.delete (io/file plain))
    enc))

(deftest source-size-boundary-test
  (let [enc (encrypt-edn! {:k "v"})
        size (.length (io/file enc))
        jar-uri (jar-source! enc "bounded.jar" "store.age")
        before (temp-source-copies)]
    (testing "a path used in place is checked without being copied"
      (is (= [:ok size] (acquire-source enc size)) "exactly at the limit is accepted")
      (is (= :source-too-large (acquire-source enc (dec size))) "one byte over is refused"))
    (testing "a classpath jar entry is counted while it is copied"
      (is (= [:ok size] (acquire-source jar-uri size)))
      (is (= :source-too-large (acquire-source jar-uri (dec size)))))
    (testing "load-secrets reports the bound it refused, and no source content"
      (is (= {:k "v"} (with-bound #'source/max-source-bytes size
                        #(secrets/load-secrets jar-uri {:identity-file *key*}))))
      (let [e (with-bound #'source/max-source-bytes (dec size)
                #(try (secrets/load-secrets jar-uri {:identity-file *key*})
                      (catch clojure.lang.ExceptionInfo e e)))]
        (is (= :source-too-large (:reason (ex-data e))))
        (is (= (dec size) (:limit (ex-data e))))
        (is (= size (:observed (ex-data e))))
        (is (= #{:reason :limit :observed :source} (set (keys (ex-data e))))
            "one shape: the reason, the bound, the observed size, and the source")
        (is (str/includes? (ex-message e) "bounded.jar") "the message names the source")))
    (testing "the bound is 16 MiB"
      (is (= 16777216 @#'source/max-source-bytes)))
    (is (= before (temp-source-copies))
        "no completed or partial ciphertext copy survives cleanup")))

(deftest remote-source-policy-test
  (testing "nonlocal and malformed nested locators are rejected by shape"
    (doseq [source ["ftp://example.com/store.age"
                    "gopher://example.com/store.age"
                    "jar:http://example.com/app.jar!/store.age"
                    "jar:jar:file:/tmp/app.jar!/nested.jar!/store.age"
                    "file://127.0.0.1/share/store.age"
                    (java.io.ByteArrayInputStream. (byte-array 0))]]
      (let [e (source-policy-failure source)]
        (is (= :disallowed-source (:reason (ex-data e)))))))
  (testing "loopback, private, redirects, and pre-byte stalls are rejected by URL shape"
    (doseq [[label spec]
            [["loopback target" "http://127.0.0.1:8080/store.age"]
             ["private target" "https://10.0.0.1/store.age"]
             ["redirect hop" "http://127.0.0.1:8080/redirect-to-private"]
             ["connection stall" "http://192.0.2.1:81/connect-stall"]
             ["read stall before the first byte" "http://127.0.0.1:8080/read-stall"]]]
      (testing label
        (let [e (source-policy-failure (java.net.URL. spec))]
          (is (= :disallowed-source (:reason (ex-data e))))))))
  (testing "controlled direct, redirect, and read-stall endpoints receive no request"
    (doseq [[label response]
            [["direct response" "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"]
             ["redirect hop" "HTTP/1.1 302 Found\r\nLocation: http://10.0.0.1/\r\n\r\n"]
             ["read stall before first byte" nil]]]
      (testing label
        (let [{:keys [url requested cleanup!]} (tracked-http-source! response)
              attempt (future (source-policy-failure url))]
          (try
            (let [result (deref attempt 1000 ::timed-out)]
              (is (not= ::timed-out result) "local-only rejection does not wait on transport")
              (when (instance? clojure.lang.ExceptionInfo result)
                (is (= :disallowed-source (:reason (ex-data result)))))
              (is (not (realized? requested)) "the endpoint accepted no connection"))
            (finally
              (cleanup!)
              (future-cancel attempt))))))))

(deftest plaintext-size-boundary-test
  (let [limit 4096
        bounded (fn [f] (with-bound #'age/max-plaintext-bytes limit f))
        exact (encrypt-sized! limit "plaintext-exact")
        over (encrypt-sized! (inc limit) "plaintext-over")]
    (testing "the bound is 8 MiB"
      (is (= 8388608 age/max-plaintext-bytes)))
    (testing "a plaintext exactly at the bound decrypts and loads"
      (is (= limit (alength (bounded #(age/decrypt-bytes *key* exact)))))
      (is (string? (:pad (bounded #(secrets/load-secrets exact {:identity-file *key*}))))))
    (testing "one byte over is refused without disclosing any plaintext"
      (let [e (bounded #(try (age/decrypt-bytes *key* over)
                             (catch clojure.lang.ExceptionInfo e e)))
            data (ex-data e)]
        (is (= {:reason :plaintext-too-large
                :limit limit
                :observed (inc limit)
                :encrypted-file over
                :identity-file *key*}
               data)
            "one shape: the reason, the bound, the bytes read, and the paths")
        (is (str/includes? (ex-message e) over) "the message names the file")
        (is (not (re-find #"aaa" (ex-message e))) "the message carries no plaintext")
        (is (not (re-find #"aaa" (pr-str data))) "and neither does the ex-data")))
    (testing "load-secrets refuses it for the same reason"
      (is (= :plaintext-too-large
             (:reason (ex-data (bounded #(try (secrets/load-secrets over {:identity-file *key*})
                                              (catch clojure.lang.ExceptionInfo e e))))))))))

(deftest oversized-plaintext-terminates-the-subprocess-test
  ;; A controlled process standing in for age: it emits forever and ignores
  ;; SIGPIPE, so closing its stdout does not end it and only an explicit
  ;; destroy can. It publishes its own pid, and `kill -0` answers for it
  ;; afterwards. The call runs under a timeout so a bound that stops working
  ;; fails the test and does not hang it.
  (let [pid-file (str *dir* "/emitter.pid")
        script (str "trap '' PIPE; echo $$ > " pid-file
                    "; while :; do printf 'AAAAAAAAAAAAAAAA' 2>/dev/null; done")
        limit 4096
        out (java.io.ByteArrayOutputStream.)
        call (future
               (with-bound #'age/max-plaintext-bytes limit
                 #(try (#'age/stream-bounded-stdout! ["/bin/sh" "-c" script] out {})
                       (catch clojure.lang.ExceptionInfo e e))))
        e (deref call 15000 :timed-out)
        pid (str/trim (slurp pid-file))
        alive? (fn [] (zero? (:exit (shell/sh "kill" "-0" pid))))]
    (try
      (is (not= :timed-out e) "the capture returns promptly and does not read forever")
      (is (= :plaintext-too-large (:reason (ex-data e))))
      (is (= (inc limit) (:observed (ex-data e)))
          "nothing beyond one byte past the bound was ever read")
      (is (<= (.size out) limit) "and nothing past the bound was written")
      (is (not (re-find #"AAA" (str (ex-message e) (pr-str (ex-data e)))))
          "no captured output reaches the failure")
      (is (not (alive?))
          "the emitter is gone: it was destroyed, not left writing to a closed pipe")
      (finally
        (future-cancel call)
        (when (alive?) (shell/sh "kill" "-9" pid))))))

(deftest edn-depth-scan-test
  (let [depth #(#'safe-edn/nesting-depth %)
        read-edn #(#'secrets/read-secrets-edn %)
        nested (fn [n] (str (apply str (repeat n \[)) (apply str (repeat n \]))))]
    (testing "only delimiters that are structure count as depth"
      (are [expected s] (= expected (depth s))
        0 ":k 1"
        1 "{:a 1}"
        2 "{:a [1 2]}"
        1 "#{1 2}"
        3 "{:a #{[1]}}"
        3 "{:a [1 {:b 2}]}"
        0 "\"[[[[\""
        1 "{:a \"]}\"}"
        0 "\"\\\"[[\""
        0 "\\["
        1 "; [[[ {{{\n{}"
        0 "}}}"
        3 "[[["))
    (testing "nesting at the limit parses and one past it is refused"
      (is (= 100 (depth (nested 100))))
      (is (= 101 (depth (nested 101))))
      (is (vector? (read-edn (nested 100))))
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"past the limit of 100"
                            (read-edn (nested 101)))))
    (testing "nesting deep enough to overflow a real parse is refused without parsing"
      (let [bomb (apply str (repeat 200000 \[))]
        (is (= 200000 (depth bomb)))
        (is (thrown-with-msg? clojure.lang.ExceptionInfo #"past the limit of 100" (read-edn bomb))
            "clojure.edn never sees it, so no StackOverflowError can happen")))
    (testing "balance is the parser's business, not the scanner's"
      (is (= 1 (depth "{:a 1")))
      (is (thrown? Exception (read-edn "{:a 1"))))))

(deftest edn-failure-helpers-test
  (testing "failure-data keeps the allowlisted fields and nothing else"
    (is (= {:reason :edn-too-deep :depth 3 :limit 2}
           (safe-edn/failure-data (with-bound #'safe-edn/max-depth 2
                                    #(safe-edn/parse "[[[1]]]")))))
    (is (= {:reason :edn-malformed :line 2 :column 1}
           (safe-edn/failure-data {:ok? false :reason :edn-malformed :line 2 :column 1
                                   :value "SECRET" :message "SECRET"}))))
  (testing "failure-location renders whatever position is known"
    (are [failure fragment] (= fragment (safe-edn/failure-location failure))
      {:line 3 :column 7} " at line 3, column 7"
      {:line 3} " at line 3"
      {:column 7} " at column 7"
      {} "")))

(deftest edn-parse-failures-are-content-free-test
  (let [sentinel "123SENTINELSECRET"
        rendered (fn [e]
                   (str/join
                    "\n"
                    (for [link (take-while some? (iterate ex-cause e))
                          part [(pr-str link)
                                (str (ex-message link))
                                (pr-str (ex-data link))]]
                      part)))]
    (testing "stable reasons distinguish each content-free failure class"
      (are [reason s] (= reason (:reason (safe-edn/parse s)))
        :edn-empty ""
        :edn-empty "  ; comment only"
        :edn-extra-values "{:one 1} {:two 2}"
        :edn-malformed sentinel
        :edn-malformed "{:unfinished"))
    (testing "only numeric parser location metadata is retained"
      (with-redefs [edn/read (fn [& _]
                               (throw
                                (ex-info (str "Invalid number: " sentinel)
                                         {:line 7
                                          :column 11
                                          :token sentinel
                                          :source-fragment sentinel})))]
        (is (= {:ok? false
                :reason :edn-malformed
                :line 7
                :column 11}
               (safe-edn/parse sentinel)))))
    (testing "the runtime exception chain drops parser messages, data, and causes"
      (let [plain (str *dir* "/malformed-secret.edn")
            encrypted (str *dir* "/malformed-secret.edn.age")]
        (spit plain sentinel)
        (age/encrypt-file! *key* plain encrypted)
        (.delete (io/file plain))
        (let [e (try
                  (secrets/load-secrets encrypted *key*)
                  nil
                  (catch Exception e e))
              diagnostic (rendered e)]
          (is (some? e) "the malformed decrypted store must fail")
          (is (= :edn-malformed (:reason (ex-data e))))
          (is (nil? (ex-cause e)) "no parser-derived exception is retained")
          (is (not (str/includes? diagnostic sentinel)))
          (is (not (str/includes? diagnostic "Invalid number")))
          (is (str/includes? (ex-message e) "malformed EDN syntax")))))))

(deftest limits-are-not-an-option-test
  (let [enc (encrypt-edn! {:k "v"})]
    (testing "a :limits option changes nothing: the bounds are fixed"
      (is (= {:k "v"}
             (secrets/load-secrets enc {:identity-file *key*
                                        :limits {:max-plaintext-bytes 1
                                                 :max-source-bytes 1
                                                 :max-edn-depth 0}})))
      (is (= "v"
             (edn/read-string
              {:readers (secrets/reader-literals {:file enc
                                                  :identity-file *key*
                                                  :limits {:max-edn-depth 0}})}
              "#secret/req :k"))))
    (testing "the limit configuration surface is gone"
      (doseq [[ns-sym var-sym] [['com.kirahowe.secrets 'default-limits]
                                ['com.kirahowe.secrets 'resolve-limits]
                                ['com.kirahowe.secrets.age 'resolve-limits]
                                ['com.kirahowe.secrets.age 'default-max-plaintext-bytes]
                                ['com.kirahowe.secrets.safe-edn 'default-max-depth]]]
        (is (nil? (ns-resolve ns-sym var-sym)) (str ns-sym "/" var-sym))))))

;;;; Redacted source diagnostics

(def ^:private source-sentinels
  "One sentinel per sensitive field a source can carry, so a leak names the
  field it leaked from rather than only that something leaked."
  {:userinfo "SENTINELuserinfoMUSTNEVERAPPEAR"
   :query "SENTINELqueryMUSTNEVERAPPEAR"
   :fragment "SENTINELfragmentMUSTNEVERAPPEAR"
   :to-string "SENTINELtoStringMUSTNEVERAPPEAR"})

(defn- leaked
  "Every sentinel field name `text` contains, so an assertion reads as the list
  of fields that leaked."
  [text]
  (vec (sort (for [[field sentinel] source-sentinels
                   :when (str/includes? text sentinel)]
               field))))

(defn- rendered-chain
  "Everything an exception chain can show a logger: each link's printed form —
  `print-method` for a Throwable renders `:via`, so printing a wrapper prints
  its causes' messages and data too — plus every message and every `ex-data` on
  its own, so a wrapped cause is not the link nobody rendered."
  [e]
  (str/join "\n"
            (for [link (take-while some? (iterate #(.getCause ^Throwable %) e))
                  part [(pr-str link) (str (ex-message link)) (pr-str (ex-data link))]]
              part)))

(defn- sentinel-url
  "A URL reaching `port` whose userinfo, query, and fragment each carry a
  sentinel — the shape of a signed URL with an embedded password."
  [port]
  (str "http://user:" (:userinfo source-sentinels) "@127.0.0.1:" port "/store.age"
       "?X-Amz-Signature=" (:query source-sentinels)
       "#" (:fragment source-sentinels)))

(defn- load-failure
  "The exception `load-secrets` throws for `source` under `opts`, asserting that
  the call really did fail: a case that stopped failing would otherwise pass
  every sentinel check by rendering nothing. `opts` is passed exactly as given,
  so a case that must resolve its identity from the environment can."
  [source opts]
  (let [e (try
            (secrets/load-secrets source opts)
            nil
            (catch Exception e e))]
    (is (some? e) "the case under test really failed")
    e))

(deftest source-descriptors-drop-credentials-test
  (let [describe source/descriptor
        signed (str "https://user:" (:userinfo source-sentinels)
                    "@example.com:8443/store.age")]
    (testing "a locator keeps scheme, host, port, and path, and nothing else"
      (are [source expected] (= expected (describe source))
        signed
        {:kind :url :scheme "https" :host "example.com" :port 8443 :path "/store.age"}

        (java.net.URL. signed)
        {:kind :url :scheme "https" :host "example.com" :port 8443 :path "/store.age"}

        (str "https://example.com/store.age?X-Amz-Signature=" (:query source-sentinels))
        {:kind :url :scheme "https" :host "example.com" :path "/store.age"}

        (str "https://example.com/store.age#" (:fragment source-sentinels))
        {:kind :url :scheme "https" :host "example.com" :path "/store.age"}

        "file:///srv/secrets/store.age"
        {:kind :url :scheme "file" :path "/srv/secrets/store.age"}

        "jar:file:/srv/app.jar!/secrets.edn.age"
        {:kind :url :scheme "jar:file" :path "/srv/app.jar!/secrets.edn.age"}))
    (testing "a path is kept; anything else contributes only its class"
      (are [source expected] (= expected (describe source))
        "/srv/secrets/store.age" {:kind :file :path "/srv/secrets/store.age"}
        (io/file "/srv/secrets/store.age") {:kind :file :path "/srv/secrets/store.age"}
        (java.io.ByteArrayInputStream. (byte-array 0))
        {:kind :object :class "java.io.ByteArrayInputStream"}
        (StringBuilder. (:to-string source-sentinels))
        {:kind :object :class "java.lang.StringBuilder"}
        nil nil))
    (testing "no descriptor carries a sentinel, whichever field held it"
      (doseq [source [signed
                      (java.net.URL. signed)
                      (str "https://example.com/s.age?sig=" (:query source-sentinels))
                      (str "https://example.com/s.age#" (:fragment source-sentinels))
                      (StringBuilder. (:to-string source-sentinels))]]
        (is (= [] (leaked (pr-str (describe source)))))))))

(deftest source-failures-carry-no-sentinel-test
  (let [chain (fn [source]
                (rendered-chain
                 (load-failure source {:identity-file *key*})))]
    (testing "policy failures retain no sensitive locator field"
      (doseq [source [(sentinel-url 8443)
                      (str "https://example.com/s.age?sig=" (:query source-sentinels))
                      (str "https://example.com/s.age#" (:fragment source-sentinels))]]
        (is (= [] (leaked (chain source))))))
    (testing "a source object whose toString is the credential"
      (is (= [] (leaked (chain (StringBuilder. (:to-string source-sentinels)))))))))

(deftest diagnostics-remain-actionable-test
  (let [wrong-key (str *dir* "/wrong-key.txt")
        _ (age/keygen! wrong-key)
        enc (encrypt-edn! {:nested {:deep {:deeper "v"}}})
        jar-uri (jar-source! enc "diagnostics.jar" "store.age")
        descriptor (source/descriptor jar-uri)
        failure (fn [source opts]
                  (load-failure source (merge {:identity-file *key*} opts)))]
    (testing "a disallowed locator explains the local-only policy"
      (let [e (failure (sentinel-url 8443) nil)
            data (ex-data e)]
        (is (= :disallowed-source (:reason data)))
        (is (= {:kind :url :scheme "http" :host "127.0.0.1"
                :port 8443 :path "/store.age"}
               (:source data)))
        (is (str/includes? (ex-message e) "local-only"))))
    (testing "an oversized local resource names the bound and safe descriptor"
      (let [e (with-bound #'source/max-source-bytes 1 #(failure jar-uri nil))
            data (ex-data e)]
        (is (= :source-too-large (:reason data)))
        (is (= 1 (:limit data)))
        (is (pos? (:observed data)))
        (is (= descriptor (:source data)))
        (is (str/includes? (ex-message e) "larger than the 1 byte limit"))))
    (testing "a wrong key still says so and names the local resource"
      (let [e (failure jar-uri {:identity-file wrong-key})
            data (ex-data e)]
        (is (= "age decryption failed" (ex-message e)))
        (is (str/includes? (:hint data) "Wrong key"))
        (is (seq (:error data)) "the captured stderr is still there")
        (is (= descriptor (:source data)))))
    (testing "an EDN plaintext past its depth bound keeps its reason and source"
      (let [e (with-bound #'safe-edn/max-depth 1 #(failure jar-uri nil))
            data (ex-data e)]
        (is (= :edn-too-deep (:reason data)))
        (is (= 1 (:limit data)))
        (is (= descriptor (:source data)))
        (is (= #{:reason :depth :limit :source} (set (keys data)))
            "only the allowlisted parse fields and the source reach the error")
        (is (str/includes? (ex-message e) "past the limit of 1"))))
    (testing "a rejected object says its class, never its toString"
      (let [e (failure (StringBuilder. (:to-string source-sentinels)) nil)
            data (ex-data e)]
        (is (= :disallowed-source (:reason data)))
        (is (= {:kind :object :class "java.lang.StringBuilder"} (:source data)))
        (is (str/includes? (ex-message e) "an instance of java.lang.StringBuilder"))))))

(deftest source-copy-is-deleted-on-any-failure-test
  (let [enc (encrypt-edn! {:k "v"})
        jar-uri (jar-source! enc "copy-failure.jar" "store.age")
        real-temp fs/owner-only-temp-file!]
    (doseq [failure [(java.io.IOException. "forced copy failure")
                     (Error. "forced copy failure")]]
      (testing (.getName (class failure))
        (let [created (atom nil)]
          (with-redefs-fn
            {#'fs/owner-only-temp-file! (fn [& args]
                                          (reset! created (apply real-temp args)))
             #'source/copy-source! (fn [_ _ ^java.io.OutputStream out]
                                     (.write out (.getBytes "partial ciphertext"))
                                     (throw failure))}
            (fn []
              (is (some? (try (secrets/load-secrets jar-uri *key*)
                              nil
                              (catch Throwable t t))))))
          (is (some? @created) "the copy was started")
          (is (not (.exists ^java.io.File @created))))))))

(deftest locator-scheme-test
  (are [s scheme] (= scheme (source/locator-scheme s))
    "https://user:pw@host/key" "https"
    "HTTPS://host/key" "https"
    "jar:file:/app.jar!/store.age" "jar"
    "file:/keys/id.txt" "file"
    "/keys/id.txt" nil
    "keys/id.txt" nil
    "~/.config/app/key.txt" nil
    "C:\\keys\\id.txt" nil
    "c:/keys/id.txt" nil
    "" nil
    " https://host/key" "https"
    "\thttps://host/key" "https"
    "\nhttps://host/key\n" "https"
    "key:txt" "key"
    "prod:key.txt" "prod"
    "./key:txt" nil
    "/keys/a:b/id.txt" nil
    "  /keys/id.txt" nil))

(deftest default-key-file-test
  (is (= (str (System/getProperty "user.home") "/.config/myapp/key.txt")
         (secrets/default-key-file "myapp")))
  (testing "an :app option resolves to it when no identity variable is set"
    (with-redefs-fn (test-env/getenv-redefs {})
      (fn []
        (is (= {:identity-file (secrets/default-key-file "myapp")
                :identity-source :default-key-file}
               (secrets/with-identity {:app "myapp"} identity)))))))

(deftest identity-and-file-locators-are-refused-by-scheme-test
  (let [enc (encrypt-edn! {:k "v"})
        locator (str "https://user:" (:userinfo source-sentinels) "@host.example/key.txt"
                     "?token=" (:query source-sentinels)
                     "#" (:fragment source-sentinels))
        failure (fn [thunk]
                  (let [e (try (thunk) nil (catch Exception e e))]
                    (is (some? e) "the case under test really failed")
                    e))
        with-env (fn [value thunk]
                   (with-redefs-fn
                     (test-env/getenv-redefs {"SECRETS_AGE_IDENTITY_FILE" value})
                     thunk))]
    (doseq [[prefix prefix-name] [["" "no"] [" " "a space"] ["\t" "a tab"] ["\n" "a newline"]]
            :let [locator (str prefix locator)]]
      (testing (str "with " prefix-name " prefix")
        (doseq [[label identity-source thunk]
                [["an :identity-file option" :identity-file
                  #(secrets/load-secrets enc {:identity-file locator})]
                 ["a bare identity argument" :identity-file
                  #(secrets/load-secrets enc locator)]
                 ["SECRETS_AGE_IDENTITY_FILE" :secrets-age-identity-file
                  #(with-env locator (fn [] (secrets/load-secrets enc nil)))]
                 ["a :key-file option" :configured-key-file
                  #(secrets/with-identity {:key-file locator} identity)]
                 ["a reader identity, at the first tag read" :identity-file
                  #(edn/read-string
                    {:readers (secrets/reader-literals {:file enc :identity-file locator})}
                    "#secret/req :k")]]]
          (testing label
            (when-let [e (failure thunk)]
              (is (= {:reason :disallowed-identity :scheme "https"
                      :identity-source identity-source}
                     (ex-data e)))
              (is (str/includes? (ex-message e) "URI scheme https:."))
              (is (str/includes? (ex-message e) "with ./"))
              (is (not (str/includes? (rendered-chain e) "host.example")))
              (is (= [] (leaked (rendered-chain e)))))))
        (doseq [[option expected] [[:file "local filesystem path"]
                                   [:resource "classpath resource name"]]]
          (testing (str "a reader " option)
            (when-let [e (failure #(secrets/reader-literals {option locator
                                                             :identity-file *key*}))]
              (is (= {:reason :disallowed-source
                      :source {:kind :url :scheme "https" :host "host.example"
                               :path "/key.txt"}}
                     (ex-data e))
                  "the same descriptor shape a load failure carries")
              (is (str/includes? (ex-message e) (str "The secrets " option " must be a " expected)))
              (is (str/includes? (ex-message e) "URI scheme https:."))
              (is (= [] (leaked (rendered-chain e)))))))))
    (testing "a File built from a locator is refused the same way"
      (is (= :disallowed-identity
             (:reason (ex-data (failure #(secrets/load-secrets enc (io/file locator))))))))
    (testing "a bare relative name with a colon is refused, with the way to name it"
      (let [e (failure #(secrets/load-secrets enc "key:txt"))]
        (is (= {:reason :disallowed-identity :scheme "key" :identity-source :identity-file}
               (ex-data e)))
        (is (str/includes? (ex-message e) "Prefix a relative path that contains a colon with ./"))))
    (testing "a ./ prefix or an absolute path makes a name with a colon a path"
      (is (= {:identity-file "./key:txt" :identity-source :identity-file}
             (secrets/with-identity "./key:txt" identity)))
      (let [colon-dir (io/file *dir* "a:b")
            colon-key (io/file colon-dir "key:txt")]
        (.mkdirs colon-dir)
        (spit colon-key (slurp *key*))
        (is (= {:k "v"} (secrets/load-secrets enc (str colon-key))))
        (is (= {:k "v"} (secrets/load-secrets enc {:identity-file (str colon-key)})))))
    (testing "a local identity path that does not exist is still named"
      (let [missing (str *dir* "/no-such-key.txt")
            e (load-failure enc {:identity-file missing})]
        (is (= :no-identity (:reason (ex-data e))))
        (is (str/includes? (ex-message e) missing))))
    (testing "a missing :file is described before :resource"
      (let [missing (str *dir* "/absent.edn.age")
            readers (secrets/reader-literals {:file missing :resource "other.edn.age"
                                              :identity-file *key*})
            e (failure #(edn/read-string {:readers readers} "#secret/req :k"))]
        (is (= missing (:store (ex-data e))))))))

(deftest key-contents-in-a-path-setting-are-never-echoed-test
  (let [enc (encrypt-edn! {:k "v"})
        key-line (gen/generate g/age-secret-key)
        file-text (gen/generate (g/decorated-identity key-line))
        with-env (fn [value thunk]
                   (with-redefs-fn
                     (test-env/getenv-redefs {"SECRETS_AGE_IDENTITY_FILE" value})
                     thunk))]
    (doseq [[shape contents] [["a bare key line" key-line]
                              ["age-keygen file text" file-text]
                              ["a key line after whitespace" (str " \n" key-line)]]
            [label identity-source thunk]
            [["a bare identity argument" :identity-file
              #(secrets/load-secrets enc contents)]
             ["an :identity-file option" :identity-file
              #(secrets/load-secrets enc {:identity-file contents})]
             ["SECRETS_AGE_IDENTITY_FILE" :secrets-age-identity-file
              #(with-env contents (fn [] (secrets/load-secrets enc nil)))]
             ["a :key-file option" :configured-key-file
              #(secrets/with-identity {:key-file contents} identity)]]]
      (testing (str shape " in " label)
        (let [e (try (thunk) nil (catch Exception e e))]
          (is (some? e) "the case under test really failed")
          (when e
            (is (= {:reason :disallowed-identity :identity-source identity-source}
                   (ex-data e)))
            (is (str/includes? (ex-message e) "holds key contents"))
            (is (str/includes? (ex-message e) "SECRETS_AGE_IDENTITY."))
            (is (not (str/includes? (rendered-chain e) key-line)))
            (is (not (str/includes? (rendered-chain e) (subs key-line 16 40))))))))))

;;;; Manifest

(deftest manifest-structure-test
  (let [m {:database/url "jdbc:x"
           :auth {:admins #{"a@b.com" "c@d.com"}}
           :retries 3
           :flag true}
        e (manifest/entries m nil)]
    (is (= :string (:type (e [:database/url]))))
    (is (= :set (:type (e [:auth :admins]))))
    (is (= 2 (:count (e [:auth :admins]))))
    (is (= :integer (:type (e [:retries]))))
    (is (= :boolean (:type (e [:flag]))))
    (is (not (contains? (e [:database/url]) :vhash)) "no hmac key ⇒ no vhash")
    (is (not (contains? (e [:database/url]) :count)) "scalars have no :count")))

(deftest manifest-vhash-detects-value-change-test
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

(defn- leaf-vhash
  "The `:vhash` a keyed manifest records for `v` under the single path `[:x]`."
  [hkey v]
  (:vhash (get (manifest/entries {:x v} hkey) [:x])))

(deftest manifest-encoding-is-injective-test
  (let [hk (manifest/hmac-key (slurp *key*))
        vh #(leaf-vhash hk %)]
    (testing "the collisions the v1 encoding produced"
      (are [left right] (not= (vh left) (vh right))
        '[{a=b c}] '[{a b=c}]
        [[1]] [(list 1)]))
    (testing "delimiters and digits inside payloads cannot be read as framing"
      (are [left right] (not= (vh left) (vh right))
        ["a=b" "c"] ["a" "b=c"]
        ["a;b" "c"] ["a" "b;c"]
        ["s:1:x"] ["s:1:y"]
        ["12" "3"] ["1" "23"]
        ["" "s:0:"] ["s:0:" ""]
        [{"k" "v"} {"j" "w"}] [{"k" "v" "j" "w"}]
        '[foo=bar] '[foo bar]
        [":k" "{}" "}"] ["" ":k{}}"]))
    (testing "nested collection types are distinguished"
      (are [left right] (not= (vh left) (vh right))
        [#{[1]}] [#{(list 1)}]
        [[#{1}]] [#{[1]}]
        [{:k (list 1)}] [{:k [1]}]
        [(list {:k 1})] [[{:k 1}]]
        [#{1}] [[1]]
        [(list 1)] [[1]]))
    (testing "every empty value hashes differently"
      (is (= 6 (count (distinct (map vh [[] (list) #{} {} "" nil]))))))
    (testing "ordering is significant exactly where it is semantic"
      (is (not= (vh [1 2]) (vh [2 1])) "vector order")
      (is (not= (vh [(list 1 2)]) (vh [(list 2 1)])) "list order")
      (is (= (vh #{1 2}) (vh #{2 1})) "set order does not count")
      (is (= (vh [{:a 1 :b 2}]) (vh [{:b 2 :a 1}])) "nor map entry order")
      (let [pairs (map vector [:a :b :c :d :e :f :g :h :i :j] (range))
            hashed (into {} pairs)
            reversed (apply array-map (mapcat identity (reverse pairs)))]
        (is (= 10 (count hashed)) "more than 8 entries, so a real hash map")
        (is (= (vh [hashed]) (vh [reversed]))
            "hash-map iteration order does not reach the encoding")))
    (testing "payloads are framed by code-unit count, not by encoded byte length"
      (is (= (vh ["héllo→"]) (vh ["héllo→"])))
      (is (not= (vh ["héllo→"]) (vh ["héllo?"])))
      (is (not= (vh ["é" "x"]) (vh ["éx"])))
      (is (not= (vh ["→"]) (vh ["a"]))
          "a multi-byte and an ASCII payload declare the same length and still differ"))
    (testing "unpaired surrogates, which no charset encoder preserves, are distinguished"
      (let [high (str (char 0xD800))
            other-high (str (char 0xD801))
            reversed-pair (str (char 0xDE00) (char 0xD83D))]
        (is (= 5 (count (distinct (map vh [high other-high "?" "\ufffd" reversed-pair]))))
            "though UTF-8 substitutes ? for each lone surrogate")
        (is (not= (vh "\uD83D\uDE00") (vh reversed-pair))
            "and a valid pair differs from the same code units reversed")))))

(deftest manifest-entry-paths-do-not-collapse-test
  ;; A symbol containing a space renders exactly like two symbols, so `pr-str`
  ;; is ambiguous across path *elements*. `clojure.edn` cannot read such a
  ;; symbol back, so no encrypted file can carry one — but `entries` is public
  ;; and its ordering must be total for any Clojure data, and the old
  ;; rendered-text comparator let one of these entries overwrite the other,
  ;; silently dropping a manifest line. Hence a constructed key rather than an
  ;; EDN-readable one: among values the reader can produce, `pr-str` is
  ;; unambiguous, so no such pair exists to test with.
  (let [spaced (symbol "a b")
        e (manifest/entries {'a {'b 1} spaced 2} nil)]
    (is (= 2 (count e)) "two distinct paths stay two entries")
    (is (= #{'[a b] [spaced]} (set (keys e))))
    (is (= "[a b]" (pr-str '[a b]) (pr-str [spaced]))
        "and they really are indistinguishable once rendered")))

(deftest manifest-entry-order-is-total-and-stable-test
  (let [m {:b 2 :a {:d 4 :c 3} :e #{1} :f "x" :g nil}
        shuffled #(apply array-map (mapcat identity (shuffle (vec m))))
        paths (keys (manifest/entries m nil))]
    (is (= #{[:a :c] [:a :d] [:b] [:e] [:f] [:g]} (set paths))
        "no path is lost to a comparator that calls two of them equal")
    (dotimes [_ 20]
      (is (= paths (keys (manifest/entries (shuffled) nil)))
          "and the order does not depend on the input map's iteration order"))))

(deftest manifest-render-round-trips-test
  (let [e (manifest/entries {:a 1 :b {:c "x"} :d #{:e}} nil)
        sha "a3f1c2d4e5b6978012345678901234567890123456789012345678901234abcd"]
    (testing "with a :ciphertext-sha it round-trips through the EDN"
      (let [parsed (edn/read-string (manifest/render {:app "myapp" :ciphertext-sha sha} e))]
        (is (= 2 (:version parsed)))
        (is (= "myapp" (:app parsed)))
        (is (= sha (:ciphertext-sha parsed)))
        (is (= e (:keys parsed)) "renders to EDN that reads back to the same entries")))
    (testing "omitted/nil :ciphertext-sha leaves the key out entirely"
      (doseq [hdr [{:app "myapp"} {:app "myapp" :ciphertext-sha nil}]]
        (let [parsed (edn/read-string (manifest/render hdr e))]
          (is (not (contains? parsed :ciphertext-sha)))
          (is (= e (:keys parsed))))))))

(deftest manifest-hmac-key-comment-insensitive-test
  (let [secret "AGE-SECRET-KEY-1QQPXZ6EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE"
        a (str "# created: 2026-01-01\n# public key: age1aaa\n"
               secret "\n")
        b (str "\n# created: 2026-07-14\n# public key: age1bbb\n  "
               secret "  \n\n")
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
        (is (not (java.util.Arrays/equals (manifest/hmac-key ssh)
                                          (manifest/hmac-key a))))))))

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
          a (manifest/entries {:token "old"} hk)
          b (manifest/entries {:token "new"} hk)]
      (is (= [[:token]] (:changed (manifest/diff a b)))))))

(deftest blank-identity-variable-fails-through-with-identity-test
  (let [resolve-under (fn [environment identity-or-opts]
                        (with-redefs-fn (test-env/getenv-redefs environment)
                          (fn []
                            (try
                              (secrets/with-identity identity-or-opts identity)
                              (catch clojure.lang.ExceptionInfo e e)))))]
    (doseq [variable ["SECRETS_AGE_IDENTITY_FILE" "SECRETS_AGE_IDENTITY" "SECRETS_AGE_IDENTITY_B64"]
            blank ["" " \n"]
            :let [environment {variable blank}]]
      (testing (str variable " " (pr-str blank))
        (testing "with no explicit path, resolution stops at the blank variable"
          (doseq [identity-or-opts [nil {:app "myapp"} {:key-file *key*}]]
            (let [e (resolve-under environment identity-or-opts)]
              (is (re-find #"is set but empty" (str (ex-message e))))
              (is (= {:env variable} (ex-data e))))))
        (testing "an explicit path is chosen before any variable is read"
          (doseq [identity-or-opts [*key* {:identity-file *key*}]]
            (is (= {:identity-file *key* :identity-source :identity-file}
                   (resolve-under environment identity-or-opts)))))))))

(deftest blank-identity-env-var-throws-test
  (let [check @#'secrets/identity-env-value]
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

(deftest injected-load-failures-clean-up-without-disclosing-keys-test
  (let [wrong-key (str *dir* "/wrong-key.txt")
        enc (encrypt-edn! {:pad (apply str (repeat 2048 \a))})]
    (age/keygen! wrong-key)
    (doseq [[key bound reason] [[wrong-key age/max-plaintext-bytes nil]
                                [*key* 16 :plaintext-too-large]]]
      (let [contents (slurp key)
            secret-line (first (filter #(str/starts-with? % "AGE-SECRET-KEY-")
                                       (str/split-lines contents)))
            failure (with-redefs-fn
                      (assoc (test-env/getenv-redefs {"SECRETS_AGE_IDENTITY" contents})
                             #'age/max-plaintext-bytes bound)
                      (fn [] (load-failure enc nil)))
            data (ex-data failure)
            path (:identity-file data)]
        (is (string? path))
        (when (string? path)
          (is (not (.exists (io/file path))) "failed decryption deletes its temporary identity"))
        (is (not (str/includes? (rendered-chain failure) secret-line)))
        (if reason
          (is (= reason (:reason data)))
          (do
            (is (= "age decryption failed" (ex-message failure)))
            (is (str/includes? (:hint data) "Wrong key"))))))))
