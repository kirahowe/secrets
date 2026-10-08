# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

Changes since `v0.1.0`. A project on `v0.1.0` has to act on the "Changed" and
"Removed" entries.

### Added
- A project initializer, `com.kirahowe.secrets.init`. It previews by default
  and, with `--apply`, creates a `bb.edn` with the `secrets` task, a template,
  and with `--keygen` an identity. It never edits a file that exists: for an
  existing `bb.edn` or `deps.edn` it prints the entries to add.
- `bb secrets doctor`, which reports the state of `age`, the configured files,
  the resolved identity and where it came from, and the recipients, without
  printing any contents.
- Value hashes in every manifest, team stores included. Each store holds a
  random 256-bit manifest key inside its encrypted EDN, and every manifest
  entry carries a `:vhash` keyed by it.
- Manifest key renewal. `reencrypt` always generates a new key, and `edit`,
  `set`, and `rm` do when the recipients file no longer matches the set the
  store was last encrypted to, so a removed recipient's copy of the old key
  says nothing about values published afterwards.
- `com.kirahowe.secrets/with-identity`, which resolves an identity for one
  operation and deletes a temporary identity file when the operation ends.
- `com.kirahowe.secrets.aero/read-config`, which reads an Aero config whose
  secret tags decrypt the store at most once for that read.
- A hidden prompt for `bb secrets set` when it runs from a terminal.
- `-h`, `--help`, and `bb secrets help <command>` for every command, and `--`
  to end the options.
- Fixed bounds that catch an accidental huge or deeply nested input: 16 MiB of
  ciphertext, 8 MiB of plaintext, EDN depth 100, 256 KiB of recipients file,
  and 1 MiB of manifest.

### Changed
- The manifest format is `:version 3`. `verify` reports a `v0.1.0` manifest as
  unsupported, and a store written by `v0.1.0` has no manifest key, so `edit`,
  `set`, and `rm` fail on it. Run `bb secrets reencrypt <env>` once per
  environment to fix both.
- A store's plaintext must be one EDN map. The library keeps its own metadata
  in it as reserved top-level data in the `:com.kirahowe.secrets` namespace.
- An identity named by a path argument, `:identity-file`, or
  `SECRETS_AGE_IDENTITY_FILE` has to exist. A missing one is a `:no-identity`
  error where `verify` used to fall back to a keyless check and `#secret/opt`
  used to return `nil`.
- Identity paths are local paths. A URI-shaped value, a bare `name:rest`, and
  key contents in a path setting are refused with `:disallowed-identity`
  without being echoed. A leading `~` is expanded for every identity path.
- `load-secrets` and the reader literals accept only local sources: a path, a
  `File` or `Path`, or a classpath resource, including one inside a jar. HTTP
  and other remote URLs, and input streams, are refused with
  `:disallowed-source`.
- `get-secret` with a vector path walks maps and vectors only. A path that
  continues into a string, set, or list is not found.
- Aero configs with secret tags have to be read with
  `com.kirahowe.secrets.aero/read-config`, passing the options under
  `:secrets`. `aero.core/read-config` alone throws on a secret tag.
- The CLI config rejects a key it does not know, at the top level and in an
  environment.
- With no environment argument, `verify` reports an environment it cannot
  check and continues with the others. It exits 1 for drift and 2 for an
  environment it could not check.
- A manifest has to be complete before `verify` compares anything, with or
  without an identity: `:version 3`, this project's `:app`, a
  `:ciphertext-sha`, and a `:type` and `:vhash` on every entry.
- A write replaces the ciphertext and then the manifest, each atomically, and
  rolls nothing back. A failure between the two is reported as a stale
  manifest, which `reencrypt` regenerates.
- The ciphertext, manifest, and recipients file are written with ordinary file
  permissions instead of 0600.
- Temporary plaintext and identity files are deleted with an ordinary delete,
  and a delete that fails is reported with the path.

### Removed
- The `bb secrets encrypt` and `bb secrets decrypt` commands, and
  `cli/encrypt!` and `cli/decrypt!`. Use `age` for arbitrary files.
- `com.kirahowe.secrets.age/decrypt-to-file!`.
- `com.kirahowe.secrets/identity-from-env`, `resolve-identity-file`, and
  `identity-available?`. Use `with-identity`.
- `com.kirahowe.secrets/owner-only-temp-file!`.
- `com.kirahowe.secrets.aero/register!` and `reset-cache!`.

## [0.1.0] - 2026-08-21

### Added
- Initial release of `com.kirahowe/secrets`.
- `com.kirahowe.secrets.age` — thin, binary-safe wrapper over the `age` CLI,
  usable from JVM Clojure and babashka: `keygen!`, `public-key`,
  `valid-recipient?`, `decrypt-bytes` (plaintext as a byte array), `decrypt`
  (UTF-8 string), `decrypt-to-file!` (byte-for-byte). `encrypt-file!` encrypts
  to an identity file, a `:recipients-file`, or a `:recipients` list — and
  throws if given a bare `age1…` public key where an identity-file path is
  expected.
- `com.kirahowe.secrets` — runtime loading of age-encrypted EDN secrets:
  `load-secrets` (from a path, File, or URL/resource — including `jar:`
  resource URLs inside an uberjar; identity via a path or an
  `{:identity-file … :app …}` opts map), `get-secret`, and namespaced
  `#secret/req` / `#secret/opt` EDN reader literals (`reader-literals`,
  `merge-readers`) as the EDN spec requires. `#secret/req` throws when the
  secrets file, the identity, or the key is missing; `#secret/opt` returns nil
  in those cases; a genuine decryption failure throws for both tags.
- **Identity resolution** from `SECRETS_AGE_IDENTITY_FILE` (a path), `SECRETS_AGE_IDENTITY`
  (raw key contents, used verbatim), or `SECRETS_AGE_IDENTITY_B64` (base64-encoded
  contents; invalid base64 throws), checked in that order (`identity-from-env`),
  then `~/.config/<app>/key.txt` when an app name is known
  (`resolve-identity-file`). There is deliberately no default key path: loading
  with no resolvable identity throws and lists the options. A variable that is
  set but empty throws, naming itself, instead of resolving to an unusable
  identity — CI runners expand a missing secret to the empty string, and
  falling back to the local key path would mask the broken deployment.
- **Owner-only temp files.** Everything sensitive the library materializes
  (injected identities, plaintext during edit) is created 0600 atomically via
  NIO (`owner-only-temp-file!`), with a create-then-restrict fallback on
  non-POSIX filesystems.
- `com.kirahowe.secrets.cli` — config-driven `bb secrets` management task
  (`keygen`, `new`, `edit`, `set`, `rm`, `verify`, `show-key`,
  `add-recipient`, `recipients`, `reencrypt`, `encrypt`, `decrypt`, `help`). Command fns are a
  REPL-safe API: they return data (paths, result maps, `:aborted` from a
  declined overwrite prompt) and throw `ex-info` on failure; only `run!` prints
  error details (`:hint` / `:install` / `:error` / `:docs`) and exits. Config
  is validated up front (`:app` is required — it names the default key path,
  and a default would let unrelated projects share a key by accident;
  `:secrets-file` is required and must end in `.age` unless both `:template`
  and `:manifest` are set explicitly; no artifact path may be a blank string,
  which would otherwise resolve to the working directory), every command
  takes the environment first (`bb secrets decrypt [env] <file>`), and each
  environment's decrypt-side `:identity-file` resolves from the
  `SECRETS_AGE_IDENTITY*` variables before its configured `:key-file` — so CI holding
  only `SECRETS_AGE_IDENTITY` can encrypt, decrypt, and verify.
- **Multi-recipient encryption.** An environment may set `:recipients-file` (a
  committed list of age public keys); it then encrypts to all of them (`age -R`)
  so each teammate decrypts with their own key, via the `add-recipient`,
  `recipients`, and `reencrypt` commands.
- **Committed manifest.** `com.kirahowe.secrets.manifest` and a `verify`
  command. Every `new` / `edit` / `reencrypt` writes a value-free `*.manifest`
  beside the ciphertext: key paths + value types, a key-derived `:vhash` in
  single-key mode (keyed only by the `AGE-SECRET-KEY` material, so identity-file
  comments and whitespace don't change it), and the `:ciphertext-sha` of the
  encrypted file. `bb secrets verify` checks every environment and exits 0
  (ok) / 1 (drift) / 2 (missing artifacts or key); with no key available it
  still verifies freshness against `:ciphertext-sha`, with one it also flags
  out-of-band re-encryption, and an unsupported manifest `:version` counts as
  drift. Disable per-environment with `:manifest false`.
- **Transactional CLI saves.** `new`, `edit`, and `reencrypt` validate the
  complete plaintext as EDN before encrypting, stage ciphertext and manifest in
  sibling temporary files, and atomically replace the live pair with rollback
  if either commit fails. Invalid editor contents therefore leave existing
  secrets untouched.
- `com.kirahowe.secrets.aero` — optional `aero.core` integration:
  `(:require [com.kirahowe.secrets.aero])` registers the `#secret/req` /
  `#secret/opt` reader methods on `aero.core/reader`; there is nothing else to
  call. Configure with `register!` for a process-wide default, or a per-read
  `:secrets` key in the opts map passed to `aero.core/read-config` (the same
  opts map `reader-literals` takes) — the per-read key always wins, which is
  also how a caller varies the config per `:profile`. `reset-cache!` drops the
  cached decrypted store, for a long-running REPL that needs to pick up a
  `bb secrets edit` made after the process started. `aero` stays out of
  `deps.edn`; the namespace only loads for consumers who already depend on it
  themselves.
- `identity-available?` — true when an age identity actually resolves *and*
  its file exists on disk; the "do I have a key, or should I tell the user to
  run `keygen`?" check that `resolve-identity-file` alone can't answer, since
  it returns the conventional path whether or not anything is there.
- **`load-secrets` error contract.** Every failure now throws `ex-info` with a
  `:reason` — `:no-identity` or `:no-file` — the same vocabulary `#secret/req`
  / `#secret/opt` use internally, so a consumer can branch on the failure the
  same way regardless of which API reached the store.
- `bb secrets set` / `bb secrets rm` — non-interactive key set/remove, reading
  the value from **stdin** so it never lands in shell history or `ps`.
  `set [env] <key> [--edn]` stores the value as a string unless `--edn` parses
  stdin as EDN (sets, numbers, nested maps), and creates the environment's
  secrets file when it doesn't exist yet, so bootstrap is scriptable; a blank
  value is refused (an unset CI variable expanding to nothing), with `--edn`
  plus `""` as the deliberate escape hatch. `rm [env] <key>` fails when the
  key or the store is absent rather than silently doing nothing. `<key>` is a
  keyword or a vector path for both, and both refresh the manifest like every
  other write command.
- **`keygen` reports who its key serves.** `:key-file` defaults to one path
  per app, not one per environment, so `bb secrets keygen dev` reads as making
  a dev-specific key when it makes the one key every environment without its
  own `:key-file` shares. It now names the environments that use the file it
  wrote, and says when that file is the app-wide default. The environment
  argument is also optional when every environment shares one key file, since
  naming one cannot change the outcome.
