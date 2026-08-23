# Team CI starter

This example uses `com.kirahowe/secrets` from the repository root via
`{:local/root "../.."}`. It demonstrates the team mode: a committed list of
age public recipients, an encrypted fixture, and a value-free manifest that a
CI job can verify without installing age or receiving a private identity.

From this checkout, the fixture gate needs Babashka (`bb`) and `java` because
this example's `bb.edn` uses `{:local/root "../.."}` and Babashka `1.13.219`
resolves that through Java-backed deps tooling. It does not need `age`, a
private identity, or secret values. The Alice/Bob demo additionally needs the
`age` CLI. From this directory, the committed fixture can be checked without
any key:

```sh
bb secrets verify fixture
# or, through the convenience task:
bb verify
```

The fixture's `recipients.txt`, ciphertext, and manifest are safe repository
artifacts. The fixture identity used to generate them was disposable and is
not present here. The ciphertext contains only fake values. The manifest
records paths and types plus the ciphertext SHA; it never records values.

## Local Alice/Bob walkthrough

The separate `demo` environment is disposable and lives entirely under the
ignored `.local/` directory. It generates local demo identities, stores fake
values through stdin, creates Bob's identity, adds Bob's public key, re-encrypts,
then uses Bob's identity to verify and decrypt. Decrypted comparison files are
removed automatically on exit (including failure) without printing them; the
keys, ciphertext, and manifest remain until explicit cleanup so the run can be
inspected:

```sh
bb demo
bb cleanup
```

The script passes only Bob's public key as a command argument. Values are
provided to `bb secrets set` on stdin, so they do not enter shell history or
process arguments. No identity or plaintext is committed. Cleanup removes only
the exact named files in `.local/demo`; inspect or adapt the script if you add
your own local artifacts.

For a real project, each teammate generates a durable age identity locally,
backs up its private half in an approved secure store, and gives the maintainer
only the public half:

```sh
bb secrets keygen demo
bb secrets add-recipient demo age1...their-public-key...
bb secrets reencrypt demo
```

After every recipient addition or removal, re-encrypt. `reencrypt` updates both
the age ciphertext and its manifest atomically. `bb secrets recipients demo`
lists the current public recipients.

## Onboarding, offboarding, and deployment

Onboarding is: add the new person's public key to the committed recipients
file, then run `reencrypt`. Offboarding removes their public-key line and
re-encrypts, which prevents access to future ciphertext. It cannot revoke an
old clone, backup, or ciphertext that they already downloaded. Rotating the
recipient set or age key also cannot revoke values from an old ciphertext if
the old private key leaked; for real revocation, rotate the underlying secret
values (and any affected credentials), then re-encrypt the artifacts with the
new recipient identities. Keep a deployment recipient separate from human
keys, and inject only that recipient's private identity into the deploy job
(for example via `SECRETS_AGE_IDENTITY`); do not use a developer's identity for
production deployment.

Commit the encrypted `*.age` file, its value-free `*.manifest`, public-only
`recipients.txt`, safe templates, CLI configuration, and CI workflow. Never
commit age identities, plaintext decrypts, or real values. The `.gitignore`
keeps this example's `.local/` demo artifacts out of git.

## Reading manifest changes

The ciphertext is intentionally opaque. A manifest diff makes reviewable
changes visible without values. For example:

```diff
 :keys
 {[:service/url] {:type :string}
- [:service/timeout] {:type :string}
- [:service/old-token] {:type :string}}
+ [:service/timeout] {:type :integer}
+ [:service/retries] {:type :integer}
+ [:service/new-token] {:type :string}}
```

Here `:service/timeout` was retyped, `:service/old-token` was removed,
`:service/retries` was added, and `:service/new-token` was added. In
single-recipient mode, a value-only change appears as a changed `:vhash`:

```diff
# Single-recipient mini-diff: the key and type stayed the same; the value changed.
- [:service/api-key] {:type :string, :vhash "old-hash"}
+ [:service/api-key] {:type :string, :vhash "new-hash"}
```

The hashes expose no value. Multi-recipient manifests intentionally remain
structure-only, so they cannot expose that value-only signal.

The nested `.github/workflows/verify-secrets.yml` is a copyable CI gate for this
starter. GitHub only loads workflows from a repository's root `.github/workflows`
directory, so this nested file is inert while the example remains inside this
monorepo. To use it here, copy the workflow unchanged into this repository's
top-level `.github/workflows`; its `examples/team-ci/**` path filters and
`examples/team-ci` working directory are already configured for this layout.
If adapting the example into a standalone repository, remove or update those
path prefixes and the working directory. It has no private-material step and
runs the same keyless freshness check as a pull request reviewer.
