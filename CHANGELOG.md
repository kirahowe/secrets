# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Development tasks for formatting (`bb format`), non-mutating format checks
  (`bb format:check`), and linting (`bb lint`), enforcing the project's
  100-column Clojure style consistently.
- An optional top-level `:limits` config key bounding untrusted inputs before
  any `age` subprocess starts: `:max-recipients` (256), `:max-recipient-chars`
  (1024), and `:max-recipients-bytes` (262144). Supplied values are merged over
  those defaults and resolved onto every environment; each must be a positive
  integer, and an unknown key inside `:limits` is rejected rather than ignored,
  because a typo in a security limit must not read as "leave it at the
  default".
- Runtime loading takes a `:limits` map — `secrets/default-limits`, overridable
  through the opts of `load-secrets`, `reader-literals`, and `merge-readers` —
  bounding the ciphertext copied from a URL or InputStream
  (`:max-source-bytes`, 16 MiB), the plaintext `age` may produce
  (`:max-plaintext-bytes`, 8 MiB), and the nesting depth of the decrypted EDN
  (`:max-edn-depth`, 100). Each bound is enforced while the bytes move rather
  than after they are all allocated: sources are counted chunk by chunk as they
  are copied, so a misleading, absent, or chunked `Content-Length` cannot raise
  or lower the effective bound, and decryption now streams through
  `ProcessBuilder` instead of `clojure.java.shell/sh`, which materializes the
  whole plaintext before any caller can look at its size. Passing a bound kills
  the `age` process, drops the partial plaintext, deletes the partial temp copy
  or staging file at once, and throws with `:source-too-large`,
  `:plaintext-too-large`, or `:edn-too-deep` carrying the byte count and the
  limit but no content; a malformed `:limits` throws `:invalid-limits` rather
  than reading as the defaults. Previously an attacker-influenced source could
  exhaust disk or heap (CWE-400). The EDN policy is documented where it is
  enforced: `:max-plaintext-bytes` bounds graph size because EDN cannot expand,
  a linear depth pre-scan bounds parser recursion (a `StackOverflowError` no
  `catch` should be relying on), and `clojure.edn` with no custom readers
  evaluates nothing. `age/decrypt-bytes`, `age/decrypt`, and
  `age/decrypt-to-file!` take the same limits through an optional trailing opts
  map; their existing arities are unchanged, as is the `--`/`path-arg` option
  boundary the argv keeps. `bb secrets decrypt`, the general-purpose counterpart
  to `bb secrets encrypt` for an arbitrary file, carries its own 1 GiB bound
  instead of the store's 8 MiB: a store past that is hostile or broken, an
  arbitrary file past it is ordinary.

### Changed
- Publishing is now a guarded, receipted, two-step flow. `clojure -T:build
  release` (`bb release`) refuses a working tree holding modified or untracked
  files, a `HEAD` that is not exactly the tag naming the declared version — a
  descendant of the tag is a refusal, not a pass — and a version `CHANGELOG.md`
  does not document. It then exports that tag with `git worktree` and builds the
  jar from the snapshot rather than from live files that can diverge after
  validation, checks the jar's name, both embedded Maven descriptors, and the
  `<scm><tag>` the pom claims it was built from against the version — a release
  that records no tag claims no provenance and is refused — and records the jar,
  the pom that is published beside it, the commit, and the jar's SHA-256 in
  `target/release.edn`. `clojure -T:build deploy` no longer builds anything: it
  re-reads that receipt, re-verifies the version, tag, commit, embedded
  metadata, and digest, confirms the pom it is about to upload is byte-identical
  to the one inside that jar — the pom, not the jar, is what defines the
  coordinate and dependency list a consumer resolves, and it is served beside
  the artifact rather than inside it — and hands the publisher exactly those two
  files, so a jar or pom changed after inspection, a missing receipt, or a
  `HEAD` that has moved off the tag each fail before any credential is used
  (CWE-345). Previously the version was hardcoded beside the tag it claimed,
  `jar` copied the live `src` tree while stamping it with tag metadata, and
  `deploy` rebuilt and uploaded whatever that produced, with the published pom
  taken from a path nothing had checked. The version now has one authoritative
  source, `com.kirahowe.secrets.release/version`, on a new `build/` path that is
  tested under both runtimes but never shipped in the jar. `clojure -T:build
  jar` remains an unguarded development build from the live tree and now says
  so: its pom records the repository URL without an `<scm><tag>`, because a
  development build is not the tag.
- A new `release` GitHub workflow publishes on a `v*` tag push (or an explicit
  dispatch) from the protected `release` environment, whose protection rules —
  required reviewers and the deployment tag restriction — are the enforcement a
  build cannot perform on its own. It builds once from the tag, inspects those
  exact bytes, uploads the jar and its receipt as a workflow artifact, and
  exposes the Clojars credentials to nothing but its final deploy step. Every
  action it uses is pinned to a full commit SHA, and it resolves dependencies
  without a cache any earlier run could have written.
- The project initializer now proves the project root untamperable before it
  mutates anything, and refuses otherwise. It previously validated a pathname —
  rejecting escapes and symlinked segments — and then wrote through that same
  pathname, so another principal able to write an ancestor directory could
  replace a validated directory with a symlink between the check and the write
  and redirect the writes outside the project (CWE-367, CWE-59).
  `SecureDirectoryStream` and openat-style anchored operations are unreachable
  from Babashka, the initializer's own runtime, so instead of re-walking
  ancestors an attacker might have swapped, `trusted-ancestry!` establishes that
  nobody can swap them: every directory from the filesystem root down to and
  including the project root must be a real directory under `NOFOLLOW_LINKS`,
  owned by the current user or by `root`, and writable by nobody else.
  Other-write needs the sticky bit, which restores the rename guarantee a write
  bit takes away and keeps a root under `/tmp` usable; group write needs sticky
  or a group whose name is the owner's, since the user-private group of Fedora,
  RHEL, and Debian holds nobody but the owner and a `umask 002` checkout at mode
  0775 is therefore exactly as safe as one at 0755. The path as written is
  walked as well as the resolved one, because a symbolic link on the way in can
  be repointed by whoever writes the link's own parent and the resolved path
  never names that parent. A filesystem that cannot report the `posix` and
  `unix` attributes the proof depends on fails closed rather than writing while
  implying a race safety it never established.
- Every initializer mutation re-verifies at the operation point. Directories are
  created with an explicit `rwxr-xr-x` a umask can only narrow, and checked one
  segment at a time below the verified root; each file is staged under an
  unguessable name with `O_CREAT|O_EXCL`, which refuses any existing entry
  including a symlink, and published with `ATOMIC_MOVE`, whose `renameat`
  replaces an entry at the destination instead of following it. The non-atomic
  copy-and-delete fallback is gone, because it would follow exactly the symlink
  the atomic rename refuses. Rollback after a failed apply runs through those
  same checked operations and reports any path it declined to touch rather than
  claiming a restore it did not perform. Preview still needs none of this, since
  it writes nothing, but it now reports whether applying would be refused — and
  `init!`'s status map carries that `:trust` report — so a refusal is visible
  before apply is chosen rather than after.
- **BREAKING** — the manifest format is now `:version 2`, and committed
  manifests must be regenerated with `bb secrets reencrypt <env>`. Value hashes
  were derived from a rendered string that joined entries with `=` and `;` — the
  same characters values may contain — and that flattened nested collections, so
  two different secret graphs could receive the same `:vhash` and a party
  holding only the public recipient could replace ciphertext, refresh
  `:ciphertext-sha`, and still pass full verification. Version 2 encodes a value
  recursively as `<type-tag>:<code-unit-count>:<payload>`, framing every scalar,
  collection, map key, and map value with its own type and length, and hashes
  the result as raw UTF-16 code units rather than through a charset encoder that
  would substitute for unpaired surrogates: `=` and `;` inside a value can no
  longer be read as structure, `[[1]]`, `[(1)]`, and `#{[1]}` all encode
  differently, and no two distinct values share a hash. Manifest entry paths are
  ordered by the same encoding instead of by rendered text, so two distinct
  paths can no longer compare equal and drop a manifest line. The encoding
  version is mixed into the HMAC key derivation, so a v1 and a v2 hash of the
  same value can never coincide, and `verify` and `doctor` reject `:version 1`
  as an unsupported version rather than diffing it as if it were v2.
- `add-recipient` now distinguishes first-store bootstrap from recipient
  changes to existing ciphertext: it recommends `set` or `new` before a store
  exists, and `reencrypt` only when ciphertext already needs updating.
- Core, CLI, and Aero internals were simplified and reorganized for readability
  while preserving public APIs, command behavior, and returned diagnostic
  schemas.
- Source style and behavior-oriented test names are now consistent, and example
  task entrypoints use qualified function calls so static analysis is reliable
  without changing how the examples run.
- The CI workflow now pins every executable dependency it runs. Each `uses:`
  reference is a full commit SHA with the version that commit is recorded
  alongside it, and the Babashka container is a `@sha256:` digest with its
  release tag kept only as a comment, so an upstream tag or registry reference
  that moves no longer changes what a build executes — including the Pages
  deployment, the one job holding `pages: write` and `id-token: write`
  (CWE-829, CWE-494). No version was upgraded in the process, no trigger or
  permission was widened, and Pages deployment keeps its main-only condition and
  its protected `github-pages` environment. A new
  `com.kirahowe.secrets.workflow-policy` namespace under `build/` decides whether
  workflow text pins its references, and names which problem each finding is: a
  mutable reference, a SHA with no version comment to review it against, a
  reference form the policy has no pinning rule for, or an undigested image. A
  test runs it over every discovered `.github/workflows/*.yml`, so a workflow
  added later is covered without anyone extending the test, and Dependabot is
  enabled for `github-actions` weekly — it bumps a pinned SHA and rewrites the
  comment beside it, keeping the pins maintainable as reviewable diffs rather
  than silent tag drift.

### Fixed
- The CI examples in the production chapter and the README no longer grant a
  private age identity to a whole job. `SECRETS_AGE_IDENTITY` is declared on the
  `bb secrets verify` step alone, so checkout, the `age` install, and the
  third-party Babashka setup action stop inheriting a key none of them needs
  (CWE-522). Each keyed job also declares `permissions: contents: read` and
  gates itself to trusted events — a fork pull request receives no secrets
  anyway, but a workflow that looks like it grants one invites the edit to
  `pull_request_target` that would hand the key to unreviewed code — and every
  `uses:` in the chapter is pinned to a full commit SHA with the version beside
  it (CWE-829), the keyless job included, since a job holding no secret still
  runs third-party code. The workflow policy grew the matching rule: it reports
  an identity declared anywhere wider than the step that consumes it, in all
  three spellings (`SECRETS_AGE_IDENTITY`, `_FILE`, `_B64` — a path is not key
  material, but a job-wide pointer to the identity grants the same decryption),
  and a new extractor reads the fenced YAML out of a chapter's `;;` prose so the
  documented examples are checked by the same rules as
  `.github/workflows/*.yml`.
- The optional `aero` integration's registration and its decrypted-reader cache
  are now one piece of state with one lifecycle, so `register!` retires the
  cache it replaces: every decrypted store and every cached decryption failure
  held under the previous registration is dropped, including when the new
  config map compares equal to the retired one, and `(register! nil)` is the
  same operation with no config. Previously the default config and the cache
  were independent atoms, so clearing or replacing a registration left matching
  plaintext — and cached failures — reachable, and a later registration whose
  config merely compared equal to a retired one inherited the retired
  lifecycle's secrets (CWE-672, CWE-668). Cache entries are now installed by
  the same compare-and-set that reads them back, so a registration committing
  first makes the installing swap retry against the new state rather than write
  into a retired cache; readers already holding a reader map keep using it, and
  once-per-lifecycle decryption, the cache key (the secrets config map alone,
  so a distinguishing key is a distinct entry), and `reset-cache!`'s contract
  are unchanged.
- Every command that encrypts now reads, bounds, and validates the configured
  recipients file exactly once — before an editor opens, before stdin is read,
  before anything is decrypted — and encrypts to the resulting immutable list
  of validated recipients, which `age` receives as repeated `-r` values. The
  recipients pathname is no longer passed to `age` at all. Previously the file
  was read once to check it was non-empty and then handed to `age` as `-R` to
  be read again, so anyone able to write the worktree could substitute the list
  during the interval between the two reads — an editor session, minutes long —
  and choose the recipients of the resulting ciphertext, then restore the
  original file (CWE-367). Recipient count, per-entry length, and total file
  size are bounded by the new `:limits` before the file is read into memory,
  and an entry that is not an age recipient, or an empty list, fails the
  command with a diagnostic naming the file line number and quoting only a
  truncated prefix of the offending line. `bb secrets recipients` remains an
  unvalidated read-only listing, but now marks any line encryption would
  refuse instead of presenting it as a recipient.
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
- Configuration validation now builds one global table of canonical artifact
  paths and semantic roles — ciphertext, manifest, template, key file,
  recipients file, and the *resolved* identity each environment reads — and
  rejects incompatible reuse of a path across the whole configuration before
  any command performs I/O (CWE-73). Previously each environment was checked
  independently and the resolved identity was left out of the model entirely,
  so an identity path equal to a manifest path, or `dev`'s ciphertext path
  equal to `prod`'s key path, was accepted and a destructive command could
  overwrite private identity material or ciphertext — or encrypt private
  identity material as input. Compatible sharing is now an explicit allow-list
  rather than an inference from matching path strings: one identity/key
  artifact (`:identity-file` defaults to `:key-file`, `:key-file` to one
  app-wide path), one recipients list shared by several environments, and one
  shared template. Everything else is rejected, including two environments
  writing one ciphertext or one manifest, so a configuration that relied on any
  other shared path now fails at startup with a diagnostic naming every
  environment and role involved and the shared canonical path — never file
  contents. A configured path that cannot be canonicalized is likewise a
  configuration error rather than an unattributed failure later.

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
