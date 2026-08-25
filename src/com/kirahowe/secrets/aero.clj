(ns com.kirahowe.secrets.aero
  "Optional `aero.core` integration: installs the `#secret/req` / `#secret/opt`
  reader literals as `aero.core/reader` methods, so an aero config can
  reference this library's encrypted secrets directly instead of every
  consumer copying a `defmethod` snippet into their own code.

  `aero` is NOT a dependency of this library — `deps.edn`'s `:deps` stays
  clean. This namespace only compiles and loads for consumers who already
  have `aero` on their own classpath; requiring it —

      (:require [com.kirahowe.secrets.aero])

  — installs the integration. Consumers can then pass a secrets configuration
  with each `aero.core/read-config` call.

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

  The preferred way to supply the secrets config is per read, through aero's
  own opts. `aero.core/read-config` passes its entire opts map to readers as the
  first argument, so the config is read straight off its `:secrets` key:

      (aero.core/read-config \"config.edn\"
        {:profile :evals
         :secrets {:app \"myapp\" :resource \"secrets.edn.age\"}})

  `register!` remains available as a compatibility and convenience path for
  applications with one process-wide config:

      (register! {:app \"myapp\" :resource \"secrets.edn.age\"})

  That registration is mutable process state: establish it explicitly during
  application startup, replace it deliberately, and clear it with
  `(register! nil)` when its lifecycle ends. Replacing or clearing it retires
  every decrypted store and cached decryption failure held under it, even when
  the replacement config compares equal — see `readers-for`. A per-read
  `:secrets` opt always wins over the registered default — see
  `secrets-config`. When neither is supplied, reading a `#secret/…` tag throws
  rather than resolving to nil; see `secrets-config` for the error."
  (:require [aero.core]
            [com.kirahowe.secrets :as secrets]))

;;;; Registration and cache lifecycle

;;; `state` holds a registration and the cache that belongs to it:
;;;
;;;     {:generation 0 :config nil :cache {}}
;;;
;;; One atom rather than two, because a registration and the plaintext
;;; decrypted under it have to move together. Held separately, clearing or
;;; replacing the registration left matching cached plaintext — and cached
;;; decryption failures — reachable, so a later registration whose config map
;;; merely compared equal to a retired one inherited the retired lifecycle's
;;; secrets.
;;;
;;; `:cache` maps each secrets config to a delay that realizes
;;; `secrets/reader-literals`, so a config file with several `#secret/…` tags
;;; decrypts its store once, not once per tag — see `readers-for`. It is keyed
;;; on the extracted secrets config map only, never the surrounding aero opts.
;;; Those opts also carry `:profile`, `:resolver`, and other unrelated values
;;; that would make near-identical opts maps miss the cache for no reason.
;;;
;;; Retaining that key for the life of a lifecycle is deliberate and is not a
;;; disclosure route. It holds only what `secrets/reader-literals` accepts —
;;; `:app`, `:resource`/`:file`, `:identity-file`, `:limits` — never a
;;; credential value, and no code path renders it, returns it, or attaches it
;;; to a failure: `aero-opts-descriptor` is what a failure gets. A digest key
;;; would hide those paths while leaving the decrypted store, which is the
;;; sensitive half, in the value beside it; retiring the value is what
;;; `register!` and `reset-cache!` are for.
;;;
;;; `:generation` gives a lifecycle an identity that tests and diagnostics can
;;; name. It is deliberately NOT part of the cache key: replacing `:cache`
;;; wholesale is the single mechanism that retires entries, and putting the
;;; generation in the key would be a second mechanism doing that one job.

(defonce ^:private state
  (atom {:generation 0 :config nil :cache {}}))

(defn register!
  "Set the process-wide default secrets config used by `#secret/req` /
  `#secret/opt` when an `aero.core/read-config` call doesn't supply its own
  `:secrets` opt. Prefer passing `:secrets` per read; registration is a
  compatibility and convenience path for applications with an explicit
  process-wide lifecycle. `config` is the same opts map
  `com.kirahowe.secrets/reader-literals` takes (`:app`/`:resource`, `:file`,
  `:identity-file`).

  A later call replaces the previous value and ends the previous lifecycle:
  every cached decrypted store and cached decryption failure held under it is
  retired, including when `config` compares equal to the config it replaces —
  equal maps from two lifecycles are not one secret. Per-read `:secrets`
  options take precedence. `(register! nil)` is the same operation with no
  config, and so also clears the cache. Returns `config`."
  [config]
  ;; Always clears, even for an equal config: this is a start-up call, so the
  ;; cost is one extra decryption at start-up rather than anything in a hot
  ;; path, and comparing equal is exactly the case that must not share state.
  (swap! state (fn [{:keys [generation]}]
                 {:generation (inc generation) :config config :cache {}}))
  config)

(defn reset-cache!
  "Clear every cached Aero reader map and decrypted store, including cached
  decryption failures. The next `#secret/…` read resolves and decrypts its
  source again. The process-wide default set by `register!` is left intact.
  Useful after editing or repairing secrets in a long-running process."
  []
  (swap! state (fn [s] (-> s (update :generation inc) (assoc :cache {}))))
  nil)

(defn- aero-opts-descriptor
  "Allowlisted metadata about the aero opts one `#secret/…` read was given: the
  `:profile`, which is Aero's own selector and part of what a reader needs to
  know, and the *names* of the keys present.

  Never a value. An opts map can hold a `:resolver`, a database password, or an
  entire configuration, so its shape is diagnosable while its contents are not."
  [aero-opts]
  (cond-> {:aero-opt-keys (vec (sort-by str (keys aero-opts)))}
    (:profile aero-opts) (assoc :profile (:profile aero-opts))))

(defn- secrets-config
  "Resolve the secrets config for one `#secret/…` read: the aero opts' own
  `:secrets` key if present, else the process-wide default from `register!`.
  Throws instead of returning nil when neither is available — nil would
  surface as an NPE or a confusing failure deep inside `secrets/reader-literals`,
  far from anything that tells the reader what to do."
  [aero-opts]
  ;; The config is resolved once per read, so a `register!` racing a read
  ;; affects subsequent reads: this read uses the config that was live when it
  ;; resolved. That is a permitted observation of the old lifecycle, and far
  ;; simpler than resolving the default inside the cache swap below.
  (or (:secrets aero-opts)
      (:config @state)
      (throw (ex-info
              (str "No secrets config found for a #secret/… tag. Supply one "
                   "either process-wide with (com.kirahowe.secrets.aero/register! "
                   "{:app \"myapp\" ...}) or per-read via the :secrets key in "
                   "the opts map passed to aero.core/read-config, e.g. "
                   "(aero.core/read-config \"config.edn\" {:secrets {:app \"myapp\"}}).")
              (aero-opts-descriptor aero-opts)))))

(defn- readers-for
  "The `#secret/req` / `#secret/opt` reader fns for `config`, built at most
  once per distinct config within one lifecycle. The cache holds a delay
  rather than the readers themselves, so two threads reading configs at the
  same time (parallel component start-up) share one decryption instead of both
  shelling out to `age` before either wins the swap.

  The cache key is the whole secrets config map, which is also what tenancy
  means here: two callers passing equal maps deliberately share one decrypted
  store within a lifecycle, and any distinguishing key — a `:tenant`, a
  distinct `:file` — makes a distinct entry. A caller needing isolation
  expresses it in the config; the library cannot see a lifecycle boundary a
  caller never expressed, which is what `register!` and `reset-cache!` are for."
  [config]
  ;; One `swap!` installs the delay and hands back the map it was installed
  ;; into, so the delay deref'd below is always the one live in that value. If
  ;; a `register!` commits first, this `swap!` retries against the new state
  ;; and installs into the NEW cache; a delay from a retired generation can
  ;; never be written into a live one. A reader that took its delay before the
  ;; swap keeps deref'ing it — that is a reader observing the lifecycle it was
  ;; live in, not a resurrected entry.
  (let [{:keys [cache]} (swap! state
                               (fn [s]
                                 (cond-> s
                                   (not (contains? (:cache s) config))
                                   (assoc-in [:cache config]
                                             (delay (secrets/reader-literals config))))))]
    @(get cache config)))

;;;; Aero readers

(defmethod aero.core/reader 'secret/req
  [aero-opts _tag value]
  (let [readers (readers-for (secrets-config aero-opts))]
    ((readers 'secret/req) value)))

(defmethod aero.core/reader 'secret/opt
  [aero-opts _tag value]
  (let [readers (readers-for (secrets-config aero-opts))]
    ((readers 'secret/opt) value)))
