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
