# 023 — Redact sensitive exception context

Status: `open`
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

- [ ] URL context retains only needed scheme/host/path metadata with userinfo,
      query, fragment, and credential-like values removed.
- [ ] File/stream/custom source descriptions are type-aware and never call
      unrestricted rendering on caller-provided sensitive objects.
- [ ] Aero exception data contains allowlisted safe keys/profile metadata, not
      the full options map or raw identity/source values.
- [ ] Cache behavior does not require retaining sensitive options; any derived
      key is domain-separated and non-reversible where secrecy matters.
- [ ] Sentinel tests inspect exception messages, causes, `ex-data`, printed
      forms, and representative logger output for raw/base64 identities, signed
      URLs, userinfo, query tokens, and custom options.
- [ ] Sanitization preserves enough stable context to identify the failing
      source kind and configured profile without obstructing diagnosis.

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
