# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - Unreleased

### Added
- `com.kirahowe.secrets/load-secrets` and `get-secret`, which load an
  age-encrypted EDN map from a local path, a `File`, a `Path`, or a classpath
  resource `URL`, including one inside a jar.
- The `#secret/req` and `#secret/opt` reader literals, through
  `reader-literals` and `merge-readers`.
- `com.kirahowe.secrets.aero/read-config`, which reads an Aero config whose
  secret tags decrypt the store at most once for that read.
- `com.kirahowe.secrets/resolve-identity` and `identity-available?`, which
  resolve the identity an operation uses.
- Identity resolution from an explicit path, `SECRETS_AGE_IDENTITY_FILE`,
  `SECRETS_AGE_IDENTITY`, `SECRETS_AGE_IDENTITY_B64`, a `:key-command`, a
  `:key-file`, or on macOS the login Keychain item for the app. There is no
  default key file.
- `keygen` and the initializer's `--keygen` store a new key in the macOS
  Keychain unless the environment sets a `:key-file`.
- Keys that are not in a file reach `age` on its standard input and are never
  written to disk.
- A `bb secrets` task, `com.kirahowe.secrets.cli/run!`, with the commands
  `keygen`, `new`, `edit`, `set`, `rm`, `verify`, `doctor`, `show-key`,
  `add-recipient`, `recipients`, `reencrypt`, and `help`.
- Team stores, encrypted to every public key in a committed recipients file.
- A committed manifest beside each store that lists key paths, value types,
  and keyed value hashes, and holds no values. `verify` checks it against the
  ciphertext, with or without an identity.
- A project initializer, `com.kirahowe.secrets.init`, that previews by default
  and creates files only with `--apply`.
- A `:reason` keyword in the data of every `ex-info` the library throws.
- Fixed bounds on the size and nesting depth of the inputs the library reads.
- Owner-only temporary files for plaintext, deleted when the operation ends,
  including on Ctrl-C, a closed terminal, or `SIGTERM`.

[0.1.0]: https://github.com/kirahowe/secrets/tree/v0.1.0
