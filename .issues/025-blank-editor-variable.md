# 025 — Blank editor variable

Status: `open`
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

- [ ] A blank `VISUAL` with `EDITOR` set resolves to `EDITOR`.
- [ ] Both variables blank resolves to the default editor.
- [ ] A whitespace-only value behaves the same as an empty one, since the shell
      drops it identically.
- [ ] An editor value carrying arguments (`"code --wait"`, `"emacsclient -t"`)
      still works, and the path is still a separate positional argument.
- [ ] Blank and whitespace-only `VISUAL` or `EDITOR` values never make the
      plaintext path the command word of the shell invocation.
- [ ] `edit` still leaves both the ciphertext and the manifest unchanged when a
      real editor exits non-zero.

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
