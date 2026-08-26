# 025 — Blank editor variable

Status: `resolved`
Priority: P2
Review classification: Low

## Problem

A set-but-blank `VISUAL` or `EDITOR` is treated as a usable editor, because the
empty string is truthy. `VISUAL=""` therefore shadows a correctly set `EDITOR`
and the built-in default. The resulting shell command word is the decrypted
plaintext temp file, so `edit` asks the shell to execute the secrets file
instead of opening it in an editor.

## Evidence

- [`editor`](../src/com/kirahowe/secrets/cli.clj) at line 273 is
  `(or (System/getenv "VISUAL") (System/getenv "EDITOR") "vim")`. `or` selects
  the first *set* variable, blank or not.
- [`run-editor!`](../src/com/kirahowe/secrets/cli.clj) at lines 275–289 builds
  `["sh" "-c" (str (editor) " \"$1\"") "editor" path]` at line 284. With a
  blank editor the command string is ` "$1"`, whose only word is `path` — the
  0600 plaintext temp file.
- Confirmed with `/bin/sh`: `sh -c "$v \"\$1\"" editor <plaintext>` with `v`
  empty *and* with `v` whitespace-only both exit 126 `Permission denied` on the
  plaintext path, so the plaintext is the command word in either case and
  emptiness alone is not the whole test.
- It fails closed. The temp file is owner-only and not executable, so the shell
  exits non-zero and `fail!` at line 289 leaves secrets unchanged. The operator
  sees only "Editor exited with an error; leaving secrets unchanged." and no
  indication that the editor variable, not the editor, was the problem.
- It contradicts the project's own explicit set-but-blank policy for identity
  variables: [`identity-env-value`](../src/com/kirahowe/secrets.clj) at lines
  147–165 throws on a set-but-blank variable precisely because CI expands a
  missing or misnamed secret to the empty string, and reasons through why
  neither using the blank value nor silently skipping to the next source is
  safe there. The editor lookup makes the opposite, unexamined choice.
- Predates the 006 boundary work; found by the security review of that change.

## Desired outcome

A set-but-blank editor variable must not win over the next source. The
recommended shape is to reject `str/blank?` values before the `or`, treating
empty and whitespace-only strings as unset — falling through is safe here,
unlike an identity variable, because the fallback editor cannot silently
produce a wrong-but-plausible result. Taking the values as arguments, as
`identity-env-value` does, makes the rule testable without setting the process
environment. This also preserves editor values such as `"code --wait"` that
contain meaningful non-blank whitespace.

## Acceptance criteria

- [x] A blank `VISUAL` with `EDITOR` set resolves to `EDITOR`.
- [x] Both variables blank resolves to the default editor.
- [x] A whitespace-only value behaves the same as an empty one, since the shell
      drops it identically.
- [x] An editor value carrying arguments (`"code --wait"`, `"emacsclient -t"`)
      still works, and the path is still a separate positional argument.
- [x] Blank and whitespace-only `VISUAL` or `EDITOR` values never make the
      plaintext path the command word of the shell invocation.
- [x] `edit` still leaves both the ciphertext and the manifest unchanged when a
      real editor exits non-zero.

## Resolution

`editor-value` takes the two values as arguments and returns
`(or (first (remove str/blank? [visual editor])) "vim")`, with `editor` as a thin
caller over the namespace's existing `getenv` indirection. Taking the values as
arguments is what makes the rule testable without mutating the process
environment, exactly as `identity-env-value` does. `str/blank?` covers empty and
whitespace-only identically — which matters, because the measurement in the issue
showed both produce the same exit 126 on the plaintext path, so emptiness alone
was never the right test. Internal whitespace is untouched, so `"code --wait"`
survives; a naive trim-and-compare would have broken it.

The docstring records the asymmetry with `identity-env-value`, because it will
otherwise read as an inconsistency: a blank *identity* variable means a missing
secret, where both using the value and skipping to the next source produce a
wrong result silently, so that one throws. A blank *editor* variable has a
fallback that cannot produce a wrong-but-plausible outcome — the operator either
sees their editor open or the command fails without touching the store — so
falling through is safe here.

Command construction moved into its own `editor-argv`, so the resulting argv is
assertable without running an editor. That is what let the regression test assert
on the *command word* rather than merely on the resolved value, which is the
actual defect: the test resolves the built command through real `/bin/sh` word
splitting and proves the plaintext path is never the first word. Its first
assertion deliberately shows `editor-argv ""` *does* report the plaintext path as
the command word, so the probe cannot pass vacuously. Issue 006's absolute-path
operand is preserved.

The failure message now names the editor command:
"Editor exited with an error; leaving secrets unchanged. Editor: <command>". A
blank variable can no longer cause that message, but a genuinely failing editor
still can, and the issue's complaint that it gave no indication of the cause
applies either way. The editor command string is not a secret; the plaintext path
is still not printed.

Regression tests: `editor-resolution-table-test`,
`blank-editor-never-makes-the-plaintext-the-command-word-test`,
`editor-with-arguments-still-receives-the-path-positionally-test` (a recording
stub as the editor, asserting its argv), and
`edit-leaves-the-store-untouched-when-the-editor-fails-test`. Against the pre-fix
resolver the table test fails 8 of 11 assertions and the command-word test fails
on every blank pair.

Demonstrated end to end against a real store with `VISUAL=""` and a working
`EDITOR`: pre-fix, `sh` was handed `[" \"$1\"" "editor" <plaintext>]` and exited
126 `Permission denied` on the secrets file; post-fix the blank `VISUAL` falls
through and the edit completes, re-encrypting and updating the manifest.
Identical under babashka and JVM Clojure. Verified independently during review
across empty, whitespace-only, both-blank, unset, argument-carrying, and ordinary
values.

It failed closed before: the temp file is owner-only and not executable, so the
shell refused it and `fail!` left the store untouched. This is an attribution and
correctness fix, not a disclosure fix.

## Non-goals

- Validating that the editor value names an existing executable.
- Removing the shell from `run-editor!` — it is there so the value may carry
  arguments.
- Changing the throw-on-blank policy for identity variables.

## Verification

Resolve the editor over a table of variable states (blank `VISUAL` with a set
`EDITOR`, both blank, whitespace-only, a value with arguments, a plain value,
none set) and assert both the selected value and the resulting command word.
Then run `edit` with a failing editor and assert the store is untouched.

## Dependencies / related files

- [CLI editor lookup and invocation](../src/com/kirahowe/secrets/cli.clj)
- [identity variable blank policy](../src/com/kirahowe/secrets.clj)
- [CLI tests](../test/com/kirahowe/secrets/cli_test.clj)
- [editor documentation](../README.md)
