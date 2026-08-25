# 023 — Redact sensitive exception context

Status: `resolved`
Priority: P2
Review classification: Low

## Problem

Runtime exceptions retain/render complete source values and Aero stores full
option maps in error/cache context. Signed URL queries, URL userinfo, raw
identity sources, or sensitive custom options can therefore reach logs and
error-reporting systems (CWE-209).

## Evidence

- [Runtime source errors](../src/com/kirahowe/secrets.clj) at lines 247–276
  retain and render full source values.
- [Aero option handling](../src/com/kirahowe/secrets/aero.clj) at lines 91–108
  stores full options.
- Exposure requires a sensitive URL/option plus exception logging or inspection
  that renders the attached data. The review identified the retention path; it
  does not claim every logging setup prints all exception data.

## Desired outcome

Attach only allowlisted, sanitized metadata to failures and cache keys: safe
source location fields and safe option names/profile, never raw credentials,
identity values, URL queries, userinfo, or whole option maps.

## Acceptance criteria

- [x] URL context retains only needed scheme/host/path metadata with userinfo,
      query, fragment, and credential-like values removed.
- [x] File/stream/custom source descriptions are type-aware and never call
      unrestricted rendering on caller-provided sensitive objects.
- [x] Aero exception data contains allowlisted safe keys/profile metadata, not
      the full options map or raw identity/source values.
- [x] Cache behavior does not require retaining sensitive options; any derived
      key is domain-separated and non-reversible where secrecy matters.
- [x] Sentinel tests inspect exception messages, causes, `ex-data`, printed
      forms, and representative logger output for raw/base64 identities, signed
      URLs, userinfo, query tokens, and custom options.
- [x] Sanitization preserves enough stable context to identify the failing
      source kind and configured profile without obstructing diagnosis.

## Resolution

Exception context is now an allowlist rather than a rendering. One
`source-descriptor` turns any source into type-aware metadata and is used by
every source-bearing `ex-data` and message: a URL keeps scheme, host, port and
path and drops userinfo, query and fragment — which is where a signed URL's
credentials live; a file or path keeps its path; and an `InputStream`, `Reader`,
or arbitrary object yields its **class name only**. That last rule is the point
of criterion 2: `pr-str` or `str` on a caller-provided object invokes a custom
`toString`, which is exactly how a credential-bearing object leaks. The docstring
records the residual risk honestly — a URL *path* can itself carry a token, and
it is kept anyway because without it the diagnostic cannot say which resource
failed.

Aero's `secrets-config` no longer throws with the whole `aero-opts`. It carries
the `:profile` and the *names* of the keys present, never their values, so the
shape of a caller's opts map stays diagnosable while its contents do not travel.

On the cache key, the assessment came back "acceptable, no derived key", and the
reasoning holds: `readers-cache` was already keyed on the *extracted* `:secrets`
config — `:app`, `:resource`/`:file`, `:identity-file`, `:limits` — not on the
caller's opts map, so there is no credential in it by construction. It lives in a
private `defonce` with no accessor, nothing returns or prints it, and the one
failure that used to touch aero opts now carries the descriptor instead. Hashing
it would hide a path and an app name while leaving the decrypted store — the
sensitive half — in the value beside it, so it buys no reduction in disclosure
while adding cost to a lifecycle whose retirement already bounds retention. Issue
012's tenancy semantics are untouched, because the key is still the map.

The two leaks carried forward from issue 022 are closed: `age.clj`'s
`decrypt-bytes` context and `cli.clj`'s `require-identity!`/`verify-keyless` no
longer name a path the library materialized, while a caller-supplied path is
still named — the caller already has it, and naming it is most of the message's
value. `age.clj` cannot depend on `secrets.clj`, so the caller passes the
provenance decision down rather than the library guessing it.

A **third** leak turned up that the earlier audit had missed, and it is the most
interesting one: `reader-literals` laundered provenance by resolving an identity
and then passing it on as an explicit `:identity-file`, which made a materialized
path look caller-supplied to everything downstream — so it reached the Aero
readers' diagnostics through a route neither issue had looked at. Provenance is
now threaded rather than flattened.

Regression tests: `source-descriptors-drop-credentials-test` (a userinfo URL, an
`?X-Amz-Signature` URL, a fragment URL, `java.net.URL`, `file:`, `jar:file:`, a
path string, a `File`, an `InputStream`, a `StringBuilder` whose `toString` is a
sentinel, and nil), `source-failures-carry-no-sentinel-test`,
`materialized-identity-never-appears-in-diagnostics-test`,
`diagnostics-remain-actionable-test`, and
`aero-failure-context-is-allowlisted-test`. The first two render the **whole
exception chain** recursively — `pr-str`, `ex-message`, `ex-data`, and every
`getCause` — because a wrapped cause is the leak nobody checks, and because
Clojure's `print-method` for `Throwable` renders `:via`, so a cause's message is
reachable through `pr-str` of any wrapper.

Verified independently with a real injected identity and a real wrong-key
decryption: no `age-identity-` path anywhere in the rendered chain, and the error
still carries its message, its `:hint`, age's own stderr, and a `:source` of
`{:kind :file :path …}`.

One existing test changed behaviour as this issue mandates:
`load-secrets-missing-file-throws-test` asserted `(= missing (:source (ex-data
e)))`, and `:source` is now a descriptor, so a caller-supplied path lives at
`{:kind :file :path missing}`. The message still names the path.
`load-secrets-nil-source-throws-test` still passes because the nil case now omits
`:source` entirely rather than carrying an explicit nil.

## Non-goals

- Suppressing exceptions or replacing actionable errors with generic success.
- Guaranteeing callers never put secrets into unrelated application logs.
- Logging hashes of low-entropy credentials as a substitute for redaction.

## Verification

Trigger source-open, copy, decrypt, parse, and Aero configuration failures with
unique sentinels in every sensitive field. Recursively render the resulting
exception chain/data and assert no sentinel appears while safe source kind,
host/path where applicable, and profile remain available.

## Dependencies / related files

- [runtime source loading and errors](../src/com/kirahowe/secrets.clj)
- [Aero integration](../src/com/kirahowe/secrets/aero.clj)
- [runtime tests](../test/com/kirahowe/secrets_test.clj)
- [Aero tests](../test/com/kirahowe/secrets/aero_test.clj)
