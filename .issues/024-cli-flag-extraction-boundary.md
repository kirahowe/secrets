# 024 — CLI flag extraction boundary

Status: `resolved`
Priority: P2
Review classification: Low

## Problem

The CLI removes `--edn` from the argument vector for every command, not only
for the one command that defines it. A filename can therefore still change how
arguments are parsed — this time in the project's own parser rather than in
age's. A file literally named `--edn` cannot be passed to `encrypt` or
`decrypt`: the operand is stripped before positional dispatch, so the command
runs against a missing or shifted file (CWE-88). This is the last remaining
place in the codebase where a filename influences argument parsing.

## Evidence

- [`extract-flag`](../src/com/kirahowe/secrets/cli.clj) at lines 1398–1404
  removes *every* occurrence of the flag from the argument sequence, and
  [`run!`](../src/com/kirahowe/secrets/cli.clj) applies it at line 1453 before
  the `case` dispatch, so it runs for all commands. The comment there says
  `--edn` only means anything to `set`; extracting it early is what keeps
  `[env]` positional and optional.
- Confirmed against the extraction expression: with `args` `["dev" "--edn"]`
  the flag is reported present and the remaining arguments are `("dev")`.
  `bb secrets encrypt --edn` therefore reaches `encrypt!` with `file` nil, and
  `bb secrets encrypt dev --edn` reaches it with the environment name `"dev"`
  standing in for the file (dispatch at lines 1474–1479 treats a lone
  remaining argument as the file).
- It fails closed. `encrypt!` and `decrypt!` reject the resulting operand at
  their existence guards ([lines 883–884 and
  897–898](../src/com/kirahowe/secrets/cli.clj)) with `No such file:` before
  age is invoked at lines 886 and 899. No wrong file is read or written and no
  ciphertext or plaintext is produced.
- Only a path *relative* to the process working directory yields the literal
  `--edn` argv element; `./--edn` and any absolute path are not matched by the
  extraction and already work. The exposure and any fixture are therefore
  cwd-relative, the same constraint 006 hit.
- Found by the security review of the 006 argument-boundary fix, not by the
  original audit.

## Desired outcome

Extract `--edn` only for the command that defines it, or stop flag extraction
at a `--` operand terminator so `bb secrets encrypt dev -- --edn` addresses the
file. Either way `[env]` stays positional and optional.

## Acceptance criteria

- [x] A file named `--edn` round-trips through `encrypt` and `decrypt` with the
      environment given explicitly and with it omitted.
- [x] `--edn` is no longer removed from the arguments of any command that does
      not define it, and no command's operand can be consumed as a flag it
      does not accept.
- [x] `set --edn` keeps working in every argument position it accepts today,
      including with `[env]` omitted.
- [x] Every other command's argument interpretation is unchanged: `[env]` stays
      positional and optional and an omitted `[env]` still selects the default
      environment.
- [x] A regression test drives the real dispatch path for the `--edn`-named
      file and for `set`, and fails against the current extraction behavior.
- [x] Any cwd-relative fixture is removed in a `finally` and covered by a
      `.gitignore` safety-net entry, as in 006.

## Resolution

Both routes the issue offered, because they close different halves. `--edn` is
extracted only for `set`, the command that defines it, and `split-operands` stops
flag recognition at a `--` terminator, consuming it rather than passing it on.
Every other command now receives its arguments untouched apart from the
terminator, and `doctor` takes the same no-flag path so the grammar is uniform.

The interesting part is *why* the original extracted early, because that reason
is real and had to be preserved rather than deleted. `set` is
`[env] <key> [--edn]` with an optional `[env]`, and the dispatch decides which of
the two the first argument is with `(second more)`. With `--edn` still in the
sequence, `set --edn :n` makes `(second more)` truthy, so `--edn` would be read
as the environment and `:n` as the key. The flag genuinely must leave the
sequence before that arity decision — but only for `set`, so that is now the only
place it happens, with the reasoning recorded at the binding and in
`extract-flag`'s docstring.

A second `--` after the terminator is data, so a file named `--` is addressable
too.

Regression tests: `a-file-named-like-a-flag-round-trips-test` (real `age`, real
`cli/run!`, a cwd file named exactly `--edn`, environment given and omitted,
recovered bytes compared), `operand-terminator-addresses-a-flag-named-file-test`
(including an assertion that no `--.age` was produced, proving the terminator was
consumed rather than taken as the file), `set-edn-still-works-everywhere-it-did-test`
(all five positions the dispatch accepts, enumerated from the dispatch rather than
guessed, plus `set dev -- :past-terminator`),
`other-commands-do-not-consume-a-flag-they-do-not-define-test` (a 23-row table
asserting the exact arguments dispatch hands each command, including the two
cases the issue confirmed), and
`default-environment-still-resolves-without-env-test`.

Verified independently against the real binary: a file named `--edn` encrypts and
decrypts through `bb secrets` both as `encrypt dev -- --edn` and as bare
`encrypt --edn` with the environment omitted, recovering identical bytes. The
cwd-relative fixtures are cleaned in a `finally` and `.gitignore` gained `/--edn`
and `/--edn.age`, extending 006's safety net; its comment now covers the CLI's own
flags as well as age's options.

This was a parsing-correctness fix, not a disclosure fix — the defect failed
closed, rejecting the shifted operand at the existence guard before `age` ran.
It was the last place in the codebase where a filename influenced argument
parsing.

## Non-goals

- Replacing positional dispatch with a general option parser.
- Rejecting or rewriting filenames that look like flags.
- Changing what `--edn` means to `set`.

## Verification

With a supported real age binary, create a file named `--edn` in the working
directory, encrypt and decrypt it through the CLI, and assert the recovered
bytes match. Run `set` with `--edn` in each position it accepts and assert the
value is stored as EDN. Dispatch every other command with an operand that
looks like a flag and assert the interpretation is unchanged.

## Dependencies / related files

- [CLI flag extraction and dispatch](../src/com/kirahowe/secrets/cli.clj)
- [CLI tests](../test/com/kirahowe/secrets/cli_test.clj)
- [006 — Age option boundary](006-age-option-boundary.md)
- [CLI documentation](../README.md)
