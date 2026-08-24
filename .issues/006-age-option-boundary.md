# 006 — Age option boundary

Status: `resolved`
Priority: P0
Review classification: Confirmed Medium — alpha release blocker

## Problem

The age subprocess commands place caller-controlled input paths after options
without an option terminator. A path beginning with `-` is therefore parsed by
age as an option rather than as a positional file. This crosses a command-line
argument boundary (CWE-88) and can make encryption consume the wrong input or
make decryption return unauthenticated program output.
The exposed surfaces include both the public age API and CLI commands that
accept arbitrary input files.

## Evidence

- Before the fix, [`encrypt-file!` and
  `decrypt-bytes`](../src/com/kirahowe/secrets/age.clj) built age arguments
  without `--` before the positional input.
- Confirmed with age 1.3.1: an existing file named `--armor` made encryption
  succeed on empty stdin, and `decrypt-bytes` with input `"--version"`
  returned age version bytes with exit status 0 instead of authenticated
  plaintext.
- Exploitation requires an attacker or unsafe configuration to control the
  input filename. It does not imply shell execution because arguments are not
  passed through a shell, but it can bypass the expected decryption operation
  and its authenticity check.

## Desired outcome

Treat every caller-controlled age input as positional data by establishing an
explicit option boundary in both encryption and decryption paths.

## Acceptance criteria

- [x] Every age invocation that accepts an input pathname inserts `--` after
      all intended options and before positional inputs.
- [x] Encryption and decryption work for existing filenames beginning with one
      or more dashes, including names equal to valid age options.
- [x] A dash-prefixed decrypt input is read as ciphertext and cannot return
      age help, version, or other option-generated output as plaintext.
- [x] Focused regression coverage uses the real subprocess argument path and
      failed against the pre-fix missing-boundary behavior.
- [x] Ordinary files and non-dash identity-file and recipients-file paths
      behave unchanged; exact `-` intentionally names the filesystem entry
      `./-` rather than standard input or output.

## Resolution

The fix has two parts, and only both together close the boundary. Every age
invocation that accepts an input pathname now places `--` after all options and
immediately before the positional input, and every *path-valued* argument — the
positional input, `-o`, `-i`, and `-R` — is normalized so it can only mean a
file: a string form beginning with `-` is prefixed with `./`. The terminator
alone is not sufficient. age still reads a positional `-`, and an `-i` / `-R`
`-`, from standard input, and still writes `-o -` to standard output, after an
option terminator; the `./` prefix is what removes that reading. Go's `flag`
package never re-parses option *values*, so `-i -key` and `-o -x` were already
literal — the normalization there is defence in depth for the exact-`-` case,
not a parse fix. `-r` recipient *strings* are values, not paths, and are not
normalized.

A blank (`""`, `"   "`) or nil path now fails closed with `ex-info` whose
message contains `blank`, before any subprocess runs. Previously age resolved
such an argument to standard input and exited 0, producing a ciphertext of
empty stdin while the intended plaintext was never encrypted. The `ex-info`
`:data` carries the original, un-normalized path strings; `./` prefixing is a
subprocess-argument concern only and never appears in messages or return
values.

A later review pass tightened three edges of that guarantee. Argument
validation now runs before `ensure-installed!`, whose `age --version` probe is
itself a subprocess: "fails closed before any subprocess" is now literally
true, not merely true of the subprocesses that touch caller data. A bare
(non-map) recipients value is documented as a mandatory identity-file *path*,
so nil there now fails closed with the same blank error as `""` — previously
the truthiness `cond->` omitted `-i` entirely and age reported "missing
recipients", naming a configuration mistake instead of the nil path that
caused it. And `keygen!` gained the same guard: it was the one age path
argument without one, and it is the function that can replace an existing key.

A final review established the complete implementation contract. Absent
optional `:identity-file` and `:recipients-file` map keys remain absent;
explicitly present nil or blank values are invalid paths and fail before
`age --version`, with regression coverage recording zero shell calls for every
invalid role. As related boundary hardening, `run-editor!` itself makes its
internally-created plaintext operand absolute before it reaches the
shell/editor: `Files/createTempFile` can return a relative path when
`java.io.tmpdir` is relative (`-Djava.io.tmpdir=-tmp` was observed to produce
`-tmp/probe...` with `Path.isAbsolute` false). Blank editor selection remains
separate issue 025.

Scope grew by one adjacent instance rather than a new issue: the CLI's
best-effort plaintext secure delete invoked `rm -P` / `shred -u` with the same
missing terminator (`/bin/rm -P -foo` exits 64 `illegal option`, while
`/bin/rm -P -- -foo` succeeds). That is the same defect at a different binary,
so it was folded in here instead of filed separately. The terminator alone is
not enough there either, for exactly the reason `path-arg` normalizes rather
than only terminating: measured with GNU shred, `shred -u -- -` exits 1
`invalid file type` and leaves the plaintext in place, after which the trailing
`(when (.exists f) (.delete f))` fallback unlinks it without ever overwriting —
a silent downgrade from a secure delete to a plain one. `shred -u -- ./-` exits
0 and removes the file. Both commands now receive `(.getAbsolutePath f)`, which
can neither begin with a dash nor be the bare `-`.

Regression tests: `encrypt-input-named-like-an-age-option-test`,
`decrypt-input-named-like-an-age-option-test`,
`dash-only-filename-is-a-path-not-stdin-test`,
`dash-leading-relative-paths-work-for-every-path-argument-test`,
`a-file-named-dash-is-a-path-for-every-age-path-role-test`,
`age-argv-shape-test`, `blank-and-nil-age-paths-fail-closed-test`,
`invalid-age-paths-run-no-subprocesses-test`, `age-path-handling-control-test`
(the no-regression control),
`encrypt-decrypt-a-dash-leading-relative-path-test`,
`run-editor-receives-an-absolute-path-test`,
`secure-delete-option-boundary-test`, and
`secure-delete-platform-argv-shape-test`.

`a-file-named-dash-is-a-path-for-every-age-path-role-test` and
`age-argv-shape-test` came from the review pass, and they exist because
behaviour cannot see the whole fix. Once `path-arg` rewrites `--armor` to
`./--armor`, deleting both `--` arguments leaves every behavioural test
green; and a dash-*leading* `-i` / `-R` / `-o` value is something age accepts
as an option value anyway, so those cases never protected the normalization
either. Only an exact `-` distinguishes a normalized path from standard
input/output. Hence exact-`-` cases for the `-i`, `-R` and `-o` roles against
the real binary, plus one deliberate argv-shape test pinning the terminator's
position, the `./-` rendering, and `-r` pass-through.

One non-obvious testing constraint, for whoever touches these next: a
dash-leading argv element can only be produced by a path *relative* to the
process working directory — an absolute path always starts with `/`, and a
temp-directory path never starts with `-`. The dash-leading fixtures are
therefore created in the repository root and removed in a `finally`, with
`.gitignore` entries as the safety net for an interrupted run.

Sequencing finding: 007 (secure plaintext file output) and 016 (bounded source
and plaintext sizes) both rewrite the same two functions. 006 was deliberately
done first because it is argv-local — it changes how arguments are assembled
and nothing about how bytes move. 016 should come last, since it replaces
`decrypt-bytes`' whole output-capture model.

## Non-goals

- Replacing the age subprocess integration or invoking it through a shell.
- Validating filenames by rejecting legitimate dash-prefixed names.
- Changing age's cryptographic or recipient semantics.

## Verification

With a supported real age binary, encrypt and decrypt a valid store whose
input filename starts with `-`; then attempt to decrypt files named like
`--version` and `--help` and assert that option output is never accepted as
plaintext. Run the focused age integration and CLI regression cases.

## Dependencies / related files

- [age subprocess integration](../src/com/kirahowe/secrets/age.clj)
- [CLI tests](../test/com/kirahowe/secrets/cli_test.clj)
