# 026 — Restrict release repository

Status: `open`
Priority: P0
Review classification: Confirmed Medium / alpha release blocker

## Problem

The production publisher accepts an arbitrary repository URL from its first CLI
argument or `SECRETS_DEPLOY_REPOSITORY_URL`, then attaches the real Clojars
username and deploy token to that target. No scheme or origin check prevents an
HTTPS lookalike, an attacker-controlled host, or even plaintext HTTP. A release
environment or invocation mistake can therefore disclose publication
credentials before the output explains that an override was used.

The release workflow does not currently set the override, which lowers the
likelihood of accidental use in the normal job. It does not make the production
entry point fail closed.

## Evidence

- [`repository-url`](../build/com/kirahowe/secrets/publish.clj#L41-L58) chooses
  the first nonblank value among the CLI argument, the
  `SECRETS_DEPLOY_REPOSITORY_URL` environment variable, and the fixed
  `https://repo.clojars.org` URL. It performs no scheme, host, port, path, or
  origin validation.
- [`remote-repository`](../build/com/kirahowe/secrets/publish.clj#L109-L117)
  installs the supplied Clojars username and password on the repository built
  from that URL. [`-main`](../build/com/kirahowe/secrets/publish.clj#L162-L173)
  reads the live credentials and passes them to `deploy!` for the selected URL.
- The local recorder test demonstrates the dangerous capability rather than a
  hypothetical library behavior: it selects an `http://127.0.0.1:…` override
  with fixture credentials, then asserts every recorded request is
  authenticated ([`publish!` and
  `dry-run-publication-uploads-the-receipted-bytes-test`](../test/com/kirahowe/secrets/publish_policy_test.clj#L313-L377)).
- [`report!`](../build/com/kirahowe/secrets/publish.clj#L140-L151) prints the
  `OVERRIDE` label, but `-main` calls it only with the return value of `deploy!`.
  The upload and credential transmission have already happened, so the label is
  not a disclosure control.
- The credential-bearing workflow step sets only `CLOJARS_USERNAME` and
  `CLOJARS_PASSWORD`; it does not set the override
  ([`.github/workflows/release.yml`](../.github/workflows/release.yml#L79-L90)).
  This is a likelihood reduction, not an origin restriction.

## Desired outcome

The production `-main` must publish only to the exact HTTPS Clojars origin
`https://repo.clojars.org`. Local recorder coverage should inject its URL and
fixture credentials below the production entry point, into a function whose
test-only inputs cannot change production target selection.

## Acceptance criteria

- [ ] The production entry point has no CLI or environment repository override
      and accepts only the exact `https://repo.clojars.org` origin.
- [ ] Any non-HTTPS, non-Clojars, userinfo-bearing, port-changing, path-changing,
      query-bearing, fragment-bearing, or lookalike target is rejected before
      credentials are attached or network I/O starts.
- [ ] Local publication tests inject an HTTP recorder URL and fixture
      credentials below `-main`, without changing process environment to steer
      the production target.
- [ ] A focused policy test proves production invocation cannot send a request
      to an argument- or environment-selected recorder.
- [ ] Failure output names the rejected target safely and never prints either
      credential.
- [ ] Release documentation and dependency review no longer describe a
      production repository override.

## Non-goals

- Removing the authenticated local recorder test or using real Clojars
  credentials in tests.
- Reimplementing Maven deployment or changing the receipted-artifact checks.
- Treating an after-the-fact warning as equivalent to preventing disclosure.

## Verification

Run the production entry point with a loopback HTTP URL supplied once as an
argument and once through `SECRETS_DEPLOY_REPOSITORY_URL`, while a recorder is
listening. Confirm both invocations fail before the recorder receives a request.
Then call the lower-level deploy seam with fixture credentials and confirm the
existing authenticated dry run still uploads the receipted fixture bytes.

## Dependencies / related files

- [publisher entry point](../build/com/kirahowe/secrets/publish.clj)
- [publisher policy and recorder tests](../test/com/kirahowe/secrets/publish_policy_test.clj)
- [release workflow](../.github/workflows/release.yml)
- [deploy alias](../deps.edn)
- [release dependency review](../doc/release-dependency-review.md)
