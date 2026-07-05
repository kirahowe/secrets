# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Initial release of `com.kirahowe/secrets`.
- `com.kirahowe.secrets.age` — thin wrapper over the `age` CLI (keygen, encrypt,
  decrypt, public-key), usable from JVM Clojure and babashka.
- `com.kirahowe.secrets` — runtime loading of age-encrypted EDN secrets:
  `load-secrets`, `get-secret`, identity resolution from
  `AGE_IDENTITY_FILE` / `AGE_IDENTITY` / `~/.config/<app>/key.txt`, and
  `#secret` / `#secret/opt` EDN reader literals (`reader-literals`,
  `merge-readers`).
- `com.kirahowe.secrets.cli` — config-driven `bb secrets` management task
  (`keygen`, `new`, `edit`, `show-key`, `encrypt`, `decrypt`, `help`).
- **Multi-recipient encryption.** An environment may set `:recipients-file` (a
  committed list of age public keys); it then encrypts to all of them (`age -R`)
  so each teammate decrypts with their own key. New commands `add-recipient`,
  `recipients`, and `reencrypt`; `encrypt-file!` now accepts a recipients spec
  (`:identity-file` / `:recipients-file` / `:recipients`); `age/valid-recipient?`.
- **Committed manifest.** `com.kirahowe.secrets.manifest` and a `verify` command.
  Every `new` / `edit` / `reencrypt` writes a value-free `*.manifest` beside the
  ciphertext (key paths + value types, plus a key-derived `:vhash` in single-key
  mode) so `git diff` shows which keys changed. `bb secrets verify` regenerates
  it from the ciphertext and exits non-zero on drift; disable per-env with
  `:manifest false`.
