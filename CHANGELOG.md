# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
