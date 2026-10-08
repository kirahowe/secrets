# Team CI starter

This example uses `com.kirahowe/secrets` from the repository root via
`{:local/root "../.."}`. It demonstrates team mode: a committed list of age
public recipients, an encrypted fixture, and a manifest that a CI job can
verify without installing age or receiving a private identity.

The fixture gate needs Babashka (`bb`) and `java`, because Babashka resolves
the `:local/root` dependency through Java. It does not need `age`, a private
identity, or secret values. The Alice and Bob demo also needs the `age` CLI.
From this directory, check the committed fixture without any key:

```sh
bb secrets verify fixture
# or, through the convenience task:
bb verify
```

The fixture's `recipients.txt`, ciphertext, and manifest are safe to commit.
The identity used to generate them was disposable and is not present here.
The ciphertext contains only fake values. The manifest records key paths,
types, a keyed hash of each value, and the ciphertext's SHA-256. It never
records a value.

The check runs without a key because the job names no identity and the
runner has no key file. An identity that is named, by `:identity-file` or an
identity variable, has to exist.

## Disposable Alice and Bob workflow

The separate `demo` environment lives entirely under ignored `.local/`. The
script starts from an empty store, generates Alice's disposable identity, and
adds her public recipient. It checks that there is still no ciphertext and
that the command did not recommend `reencrypt`. It creates the store from fake
values on stdin, adds Bob's public recipient, confirms that `reencrypt` is now
recommended, re-encrypts, and asserts the exact two-recipient set. Finally Bob
runs `verify` with his own identity, and both identities decrypt the
ciphertext with `age` to temporary files that are compared byte for byte.

No secret value or private identity is printed. The comparison files are
removed on exit, including on failure. The disposable identities, ciphertext,
and manifest remain under `.local/demo` until you clean up, so you can inspect
them:

```sh
bb demo
bb cleanup
```

Values enter `bb secrets set` only on stdin. Only Bob's public recipient is
passed as an argument. Nothing under `.local/` is committed, and cleanup
removes only the script's own named files.

For a real team's first store, the first owner follows the same steps with a
durable private identity that is backed up:

```sh
bb secrets keygen demo
bb secrets add-recipient demo
printf %s "$FIRST_SECRET_VALUE" | bb secrets set demo :service/token
# Or use `bb secrets new demo` instead of `set`.
```

There is no `reencrypt` step before the first `set` or `new`: no ciphertext
exists yet, and creating the store encrypts to the current public recipients.

## Adding and removing people

When ciphertext already exists, a teammate creates and keeps their own private
identity and gives a maintainer only its public `age1…` recipient. The
maintainer, who must be a current recipient, runs:

```sh
bb secrets add-recipient demo age1...teammate-public-key...
bb secrets reencrypt demo
bb secrets recipients demo
```

Adding the public key changes only `recipients.txt`. Re-encryption writes the
new ciphertext and manifest, and the teammate can read from then on.

To remove someone, delete their public-key line from the committed recipients
file and re-encrypt. Their identity cannot decrypt ciphertext written after
that. It still decrypts every earlier version in git history, and nothing
takes back a value they already read, so rotate the affected credentials at
their providers.

`reencrypt` also gives the store a new manifest key, so every `:vhash` in the
manifest changes in that commit. The removed person held the old key, and
with it they could have tested guesses against later manifests. `edit`, `set`,
and `rm` renew the key the same way when they find that the recipients file
has changed since the store was last encrypted.

Use a dedicated deployment recipient instead of a developer's identity. Commit
its public recipient and give the job its private identity through one of
`SECRETS_AGE_IDENTITY_FILE` (a path to a mounted file), `SECRETS_AGE_IDENTITY`
(the identity's contents), or `SECRETS_AGE_IDENTITY_B64` (the contents in
base64).

Commit the recipient list, the `*.age` ciphertext, its `*.manifest`, templates
that contain only placeholders, the CLI configuration, and the CI workflow.
Never commit private identities, decrypted plaintext, or real secret values.

## Reading manifest changes

The ciphertext diff is opaque. The manifest diff shows what changed without
the values:

```diff
 :keys
 {[:service/url] {:type :string, :vhash "6e9027b4e13dd2e0"}
- [:service/timeout] {:type :string, :vhash "4a4fc93ef568f4b1"}
- [:service/token] {:type :string, :vhash "fc994298c8dbd774"}}
+ [:service/timeout] {:type :integer, :vhash "2f0df714792f03c7"}
+ [:service/retries] {:type :integer, :vhash "d32adde248640142"}
+ [:service/token] {:type :string, :vhash "89ae7df577fa8bb8"}}
```

Here `:service/timeout` was retyped, `:service/retries` was added, and
`:service/token` kept its type and changed its value. `:service/url` did not
change. The hash values in this example are illustrative.

Team stores have value hashes like any other store. The hashes are keyed by a
random key held inside the encrypted file, so every recipient computes the
same ones and someone with only the repository cannot test guesses against
them. They do disclose equality and change: equal values in one store have
equal hashes at any path, and a value that returns to an earlier one repeats
its earlier hash while the store keeps the same key. Key paths, types, and
collection sizes are public too, so never use a secret value as a map key.

## The CI workflow

The nested `.github/workflows/verify-secrets.yml` is a copyable CI gate for
this starter. GitHub only loads workflows from a repository's root
`.github/workflows` directory, so the nested file is inert while the example
stays inside this repository. To use it here, copy it into the top-level
`.github/workflows`. Its `examples/team-ci/**` path filters and
`examples/team-ci` working directory already fit that layout. In a standalone
repository, remove or update those prefixes. Pin its actions to commit SHAs
before you rely on it. The job holds no private material and runs the keyless
check.
