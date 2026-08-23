(ns com.kirahowe.secrets.aero
  "Optional `aero.core` integration: installs the `#secret/req` / `#secret/opt`
  reader literals as `aero.core/reader` methods, so an aero config can
  reference this library's encrypted secrets directly instead of every
  consumer copying a `defmethod` snippet into their own code.

  `aero` is NOT a dependency of this library — `deps.edn`'s `:deps` stays
  clean. This namespace only compiles and loads for consumers who already
  have `aero` on their own classpath; requiring it —

      (:require [com.kirahowe.secrets.aero])

  — is the whole integration. There is nothing else to call.

  Why a namespace instead of the README snippet it replaces: a bare
  `(defmethod aero.core/reader 'secret/req …)` needs `aero.core` resolvable at
  *compile* time, which breaks under a babashka project that adds `aero` as a
  runtime dep (`babashka.deps/add-deps`) — a normal arrangement, and the one
  this fix grew out of. And wherever the snippet lives becomes the tag's only
  registration point: a second namespace that reads the same config without
  going through that code never registers the tag, and hits aero's generic
  \"no method in multimethod\" error, which points nowhere near this library.
  Putting the `defmethod` here means requiring the namespace *is* the
  registration, and it happens exactly once no matter how many call sites read
  configs with these tags.

  Two ways to supply the secrets config — the same opts map
  `com.kirahowe.secrets/reader-literals` takes (`:app`/`:resource`, `:file`,
  `:identity-file`):

  • Per read, through aero's own opts. `aero.core/read-config` passes its
    entire opts map to readers as the first argument, so the config is read
    straight off its `:secrets` key:

        (aero.core/read-config \"config.edn\"
          {:profile :evals
           :secrets {:app \"myapp\" :resource \"secrets.edn.age\"}})

  • Process-wide, via `register!`, for the common case of one app reading its
    own config in one place:

        (register! {:app \"myapp\" :resource \"secrets.edn.age\"})

  A per-read `:secrets` opt always wins over the registered default — see
  `secrets-config`. When neither is supplied, reading a `#secret/…` tag throws
  rather than resolving to nil; see `secrets-config` for the error."
  (:require [aero.core]
            [com.kirahowe.secrets :as secrets]))

(defonce ^:private default-config
  (atom nil))

(defn register!
  "Set the process-wide default secrets config used by `#secret/req` /
  `#secret/opt` when an `aero.core/read-config` call doesn't supply its own
  `:secrets` opt. `config` is the same opts map `com.kirahowe.secrets/reader-literals`
  takes (`:app`/`:resource`, `:file`, `:identity-file`).

  A later call replaces the previous value. Per-read `:secrets` options take
  precedence. `(register! nil)` clears the default. Returns `config`."
  [config]
  (reset! default-config config)
  config)

;; {secrets-config -> readers-map}, memoizing `secrets/reader-literals` per
;; distinct config so a config file with several `#secret/…` tags decrypts its
;; store once, not once per tag — see `readers-for`. Keyed on the extracted
;; secrets config map only (never the surrounding aero opts, which also carry
;; `:profile`, `:resolver`, … and would make near-identical opts maps miss the
;; cache for no reason).
(defonce ^:private readers-cache
  (atom {}))

(defn reset-cache!
  "Clear every cached Aero reader map and decrypted store, including cached
  decryption failures. The next `#secret/…` read resolves and decrypts its
  source again. The process-wide default set by `register!` is left intact.
  Useful after editing or repairing secrets in a long-running process."
  []
  (reset! readers-cache {})
  nil)

(defn- secrets-config
  "Resolve the secrets config for one `#secret/…` read: the aero opts' own
  `:secrets` key if present, else the process-wide default from `register!`.
  Throws instead of returning nil when neither is available — nil would
  surface as an NPE or a confusing failure deep inside `secrets/reader-literals`,
  far from anything that tells the reader what to do."
  [aero-opts]
  (or (:secrets aero-opts)
      @default-config
      (throw (ex-info
              (str "No secrets config found for a #secret/… tag. Supply one "
                   "either process-wide with (com.kirahowe.secrets.aero/register! "
                   "{:app \"myapp\" ...}) or per-read via the :secrets key in "
                   "the opts map passed to aero.core/read-config, e.g. "
                   "(aero.core/read-config \"config.edn\" {:secrets {:app \"myapp\"}}).")
              {:aero-opts aero-opts}))))

(defn- readers-for
  "The `#secret/req` / `#secret/opt` reader fns for `config`, built at most
  once per distinct config and cached in `readers-cache` thereafter. The cache
  holds a delay rather than the readers themselves, so two threads reading
  configs at the same time (parallel component start-up) share one decryption
  instead of both shelling out to `age` before either wins the swap."
  [config]
  @(get (swap! readers-cache
               (fn [cache]
                 (if (contains? cache config)
                   cache
                   (assoc cache config (delay (secrets/reader-literals config))))))
        config))

(defmethod aero.core/reader 'secret/req
  [aero-opts _tag value]
  (let [readers (readers-for (secrets-config aero-opts))]
    ((readers 'secret/req) value)))

(defmethod aero.core/reader 'secret/opt
  [aero-opts _tag value]
  (let [readers (readers-for (secrets-config aero-opts))]
    ((readers 'secret/opt) value)))
