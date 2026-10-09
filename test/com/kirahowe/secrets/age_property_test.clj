(ns com.kirahowe.secrets.age-property-test
  "Properties of the `age` wrapper. A path argument can only mean a file, and
  a blank one is refused naming its role. A recipient check accepts a real key
  and refuses damaged ones."
  (:require [clojure.java.shell :as shell]
            [clojure.string :as str]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [com.kirahowe.secrets.age :as age]
            [com.kirahowe.secrets.generators :as g]
            [com.kirahowe.secrets.test-env :refer [thrown]]))

;;;; Path arguments

(def ^:private blank-path
  (gen/one-of [(gen/return nil)
               (gen/return "")
               (gen/fmap str/join (gen/vector (gen/elements [\space \tab \newline \return]) 1 4))]))

(def ^:private dash-path
  "A path an option parser would take for a flag or for stdin."
  (gen/let [dashes (gen/fmap #(apply str (repeat % "-")) (gen/choose 1 3))
            rest-of-path (gen/one-of [(gen/return "") g/text (gen/elements ["i" "o -" "-r x"])])]
    (str dashes rest-of-path)))

(def ^:private any-path
  "A path, blank about one time in four."
  (gen/frequency [[1 blank-path] [3 (gen/one-of [dash-path g/text])]]))

(defn- encrypt-argv
  "The argv `encrypt-file!` hands to `age` for these path arguments."
  [recipients in out]
  (let [argv (atom nil)]
    (with-redefs [age/ensure-installed! (constantly nil)
                  shell/sh (fn [& args] (reset! argv (vec args)) {:exit 0})]
      (age/encrypt-file! recipients in out))
    @argv))

(defspec encrypt-names-every-path-after-its-flag-and-never-as-an-option 300
  (prop/for-all [identity-file any-path
                 recipients (gen/vector g/age-recipient 0 3)
                 in any-path
                 out any-path
                 identity? gen/boolean]
    (let [target (cond-> {:recipients recipients}
                   identity? (assoc :identity-file identity-file))
          paths (concat (when identity? [identity-file]) [in out])]
      (if (some #(str/blank? (str %)) paths)
        (let [e (thrown #(encrypt-argv target in out))]
          (and (instance? clojure.lang.ExceptionInfo e)
               (contains? #{:identity :output :input} (:argument (ex-data e)))
               (str/includes? (ex-message e) (name (:argument (ex-data e))))))
        (let [argv (encrypt-argv target in out)
              after-flag (fn [flag] (second (drop-while #(not= flag %) argv)))
              terminator (.indexOf ^java.util.List argv "--")]
          (and (= "age" (first argv))
               (= (- (count argv) 2) terminator)
               (not (str/starts-with? (peek argv) "-"))
               (not (str/starts-with? (after-flag "-o") "-"))
               (= recipients (map second (filter #(= "-r" (first %)) (partition 2 1 argv))))
               (or (not identity?) (not (str/starts-with? (after-flag "-i") "-")))))))))

;;;; Recipients

(defn- mutations
  "Strings made from the recipient `r` that the `age1` rule must refuse: the
  prefix damaged, the key shortened below twenty characters, or one character
  inserted inside the key that is not lower-case alphanumeric."
  [r i k c]
  (let [body-start 4
        inside (+ body-start (mod i (- (count r) body-start)))]
    [(str (subs r 0 (mod i 4)) c (subs r (inc (mod i 4))))
     (subs r 0 (+ body-start (mod k 20)))
     (str (subs r 0 inside) (str/upper-case (str (nth r inside))) (subs r (inc inside)))
     (str (subs r 0 inside) "-" (subs r inside))
     (str (subs r 0 inside) " " (subs r inside))
     (str (subs r 0 inside) "\n" (subs r inside))]))

(defspec valid-recipient-accepts-a-key-and-refuses-damaged-ones 300
  (prop/for-all [r g/age-recipient
                 padding (gen/elements ["" " " "\n" "\t "])
                 i gen/nat
                 k gen/nat
                 c (gen/elements (vec "xyzABCDEFG-_ !."))]
    (and (age/valid-recipient? r)
         (age/valid-recipient? (str padding r padding))
         (not-any? age/valid-recipient?
                   (remove #{r} (mutations r i k c))))))

(defspec valid-recipient-accepts-ssh-lines-with-a-body 100
  (prop/for-all [kind (gen/elements ["ssh-ed25519" "ssh-rsa"])
                 body (gen/not-empty gen/string-alphanumeric)]
    (and (age/valid-recipient? (str kind " " body))
         (not (age/valid-recipient? kind))
         (not (age/valid-recipient? (str "ssh-dsa " body))))))
