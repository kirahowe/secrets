# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Development tasks for formatting (`bb format`), non-mutating format checks
  (`bb format:check`), and linting (`bb lint`), enforcing the project's
  100-column Clojure style consistently.

### Changed
- `add-recipient` now distinguishes first-store bootstrap from recipient
  changes to existing ciphertext: it recommends `set` or `new` before a store
  exists, and `reencrypt` only when ciphertext already needs updating.
- Core, CLI, and Aero internals were simplified and reorganized for readability
  while preserving public APIs, command behavior, and returned diagnostic
  schemas.
- Source style and behavior-oriented test names are now consistent, and example
  task entrypoints use qualified function calls so static analysis is reliable
  without changing how the examples run.

### Fixed
- Environment-injected identities are materialized through a race-safe,
  SHA-256-digest-keyed cache. Concurrent callers with identical identity
  contents now share one owner-only temporary-file write, and realized cache
  entries retain only the digest and resulting path rather than the raw
  identity contents.
- Every `age` invocation that takes an input pathname now ends its options with
  an explicit `--` terminator, and every path-valued argument — the positional
  input, `-o`, `-i`, and `-R` — is normalized (a leading `-` is prefixed with
  `./`) so a pathname can never be parsed as an option or as standard
  input/output. Files whose names begin with a dash, including names identical
  to age options, now encrypt and decrypt as data: previously an existing file
  named `--armor` made encryption succeed against empty stdin, writing a
  ciphertext of nothing while the real plaintext went unencrypted, and
  decrypting a file named `--version` or `--help` exited 0 with age's own
  version or help output standing in for plaintext. A blank or nil path now
  fails closed with `ex-info` before any subprocess starts, instead of silently
  resolving to standard input. `-r` recipient strings are values rather than
  paths and are untouched. The CLI's best-effort plaintext secure delete passes
  `--` plus an absolute operand to `rm` / `shred`, because exact `-` remains a
  special operand after option parsing ends. The editor operand is likewise
  made absolute before it reaches the shell/editor, because a relative
  `java.io.tmpdir` can otherwise produce a dash-leading temporary pathname.
- `age/decrypt-to-file!` no longer writes plaintext through the destination
  pathname it was handed. Previously a newly created output inherited process
  defaults — confirmed as mode `0644` under umask `022` — and an existing
  destination symlink was followed, so the public API could disclose plaintext
  through permissions or write through a link outside the selected directory.
  Plaintext now reaches the filesystem only through a sibling staging file that
  `createTempFile` opens `CREATE_NEW` with owner-only (`0600`) permissions as a
  creation attribute, so the mode never depends on umask and a guessed staging
  name can never be the file written; the permissions are read back and
  verified before any bytes are written. The destination's final component is
  validated without following links (a symlinked *parent* stays legitimate) and
  a symlink, directory, or other non-regular destination is refused. Success
  publishes by atomic rename in the same directory, so the destination is 0600
  whatever mode it had before and is never observable as permissive or partial
  plaintext; decryption runs before any staging file exists, and a write,
  permission, or move failure removes the staging plaintext and leaves the
  previous destination intact. A filesystem without POSIX permissions fails
  closed rather than downgrading to default permissions — use `decrypt-bytes`
  or `decrypt`, which never write plaintext to disk.

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
