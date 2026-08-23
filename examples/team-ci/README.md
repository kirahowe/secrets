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

## Disposable Alice/Bob and first-owner workflow

The separate `demo` environment lives entirely under ignored `.local/`. The
script starts from an empty store, generates Alice's disposable identity, adds
Alice's public recipient, and silently proves that there is still no
ciphertext and that the command did not recommend `reencrypt`. It creates the
first store from fake stdin values, adds Bob's public recipient, confirms that
`reencrypt` is now recommended, re-encrypts, and asserts the exact two-recipient
set. Finally, both private identities decrypt the resulting ciphertext to
temporary comparison files and Bob runs `verify`.

No secret value or private identity is printed. The comparison plaintext files
are removed automatically on exit, including failure. Disposable identities,
ciphertext, and manifest remain under `.local/demo` until explicit cleanup so
the state can be inspected:

```sh
bb demo
bb cleanup
```

Values enter `bb secrets set` only on stdin, never as command arguments. Only
Bob's public recipient is passed as an argument. Nothing under `.local/` is
committed, and cleanup removes only the script's exact named artifacts.

For a real team's first store, the first owner follows the same state
transition with a durable, securely backed-up private identity:

```sh
bb secrets keygen demo
bb secrets add-recipient demo
printf %s "$FIRST_SECRET_VALUE" | bb secrets set demo :service/token
# Or use `bb secrets new demo` instead of `set`.
```

There is no `reencrypt` step before the first `set` or `new`: no ciphertext
exists yet, and store creation encrypts directly to the current public
recipients.

## Onboarding, offboarding, deployment, and repository boundaries

When ciphertext already exists, a teammate creates and retains their private
identity, gives a maintainer only its public `age1…` recipient, and is onboarded
with:

```sh
bb secrets add-recipient demo age1...teammate-public-key...
bb secrets reencrypt demo
bb secrets recipients demo
```

The maintainer must be a current recipient able to decrypt the existing store.
Adding the public key changes only `recipients.txt`; re-encryption writes the
new ciphertext and value-free manifest. The teammate gains access to that new
and future ciphertext, not by changing any private identity.

To offboard someone, remove their public-key line from the committed recipients
file and re-encrypt. This blocks their identity from future ciphertext only. An
old clone, backup, downloaded ciphertext, or plaintext cannot be revoked. If a
private identity or old ciphertext is compromised, changing recipients is
insufficient: rotate the underlying secret values and affected credentials,
then write new ciphertext for the remaining recipients.

Use a dedicated, non-human deployment recipient and never a developer's
identity. Commit the deployment public recipient and inject only its private
identity into the job through one supported mechanism:
`SECRETS_AGE_IDENTITY_FILE` for a secret-provided file path,
`SECRETS_AGE_IDENTITY` for raw identity contents, or
`SECRETS_AGE_IDENTITY_B64` for base64 identity contents.

Commit only the public recipient list, encrypted `*.age` ciphertext, its
value-free `*.manifest`, safe templates containing fake placeholders, CLI
configuration, and the CI workflow. Never commit private identities, decrypted
plaintext, or real secret values. The fixture's committed ciphertext contains
explicitly fake values; its discarded generation identity is not present.

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
