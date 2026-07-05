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
                 "{:url #secret :database/url
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
         (edn/read-string {:readers readers} "#secret :totally-absent")))))

(deftest reader-absent-file
  (testing "no secrets file on disk: #secret/opt → nil, #secret → throws"
    (let [readers (secrets/reader-literals {:file (str *dir* "/nope.age")
                                            :identity-file *key*})]
      (is (nil? (edn/read-string {:readers readers} "#secret/opt :anything")))
      (is (thrown-with-msg?
           clojure.lang.ExceptionInfo #"no secrets file found"
           (edn/read-string {:readers readers} "#secret :anything"))))))

(deftest reader-decrypts-once
  (testing "many #secret tags share a single decryption"
    (let [enc   (encrypt-edn! {:a 1 :b 2 :c 3})
          calls (atom 0)
          real  age/decrypt]
      (with-redefs [age/decrypt (fn [& args] (swap! calls inc) (apply real args))]
        (let [readers (secrets/reader-literals {:file enc :identity-file *key*})
              cfg     (edn/read-string
                       {:readers readers}
                       "[#secret :a #secret :b #secret/opt :c #secret/opt :missing]")]
          (is (= [1 2 3 nil] cfg))
          (is (= 1 @calls) "decryption is memoized for the process"))))))

(deftest identity-from-env-contents
  (testing "AGE_IDENTITY contents are materialized to a usable keyfile"
    (let [enc      (encrypt-edn! {:k "v"})
          contents (slurp *key*)
          ;; resolve-identity-file prefers AGE_IDENTITY_FILE, so clear nothing —
          ;; instead drive materialize via the public resolution by faking env.
          path     (#'secrets/materialize-identity! contents)]
      (is (.exists (io/file path)))
      (is (= {:k "v"} (secrets/load-secrets enc path))))))

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
        s (manifest/render "myapp" e)
        parsed (edn/read-string s)]
    (is (= 1 (:version parsed)))
    (is (= "myapp" (:app parsed)))
    (is (= e (:keys parsed)) "renders to EDN that reads back to the same entries")))

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
