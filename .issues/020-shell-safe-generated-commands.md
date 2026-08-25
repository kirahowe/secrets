# 020 — Shell-safe generated commands

Status: `resolved`
Priority: P2
Review classification: Low

## Problem

The CLI prints copy/paste shell commands containing unquoted configuration
values. A key path or environment name containing shell metacharacters can
execute unintended commands when an operator pastes the suggestion (CWE-78).
The CLI does not itself execute these strings.

## Evidence

- [CLI guidance output](../src/com/kirahowe/secrets/cli.clj) at lines 660–678
  interpolates key paths and environment names into `flyctl` and `bb` commands
  without POSIX argument quoting.
- Exploitation requires attacker-influenced configuration plus an operator
  pasting the generated text into a compatible shell; this is a hazardous
  instruction, not direct command execution by the process.

## Desired outcome

Render every generated shell argument with tested POSIX quoting and explicit
option boundaries, or replace executable snippets with non-executable
structured instructions.

## Acceptance criteria

- [x] Every dynamic argument in emitted commands uses one shared, tested POSIX
      argument-quoting routine; no value is concatenated as shell syntax.
- [x] File-reading snippets use an option boundary such as `cat --` and quote
      the pathname as a separate argument.
- [x] Values containing spaces, single quotes, newlines, leading dashes,
      substitutions, separators, redirects, and glob characters round-trip as
      one literal argument when the command is pasted.
- [x] Focused tests parse/execute suggestions in an isolated POSIX shell with
      inert fixtures and prove no sentinel side effect occurs.
- [x] Ordinary generated guidance remains readable and documents its expected
      shell, or executable shell output is removed entirely.

## Resolution

One private `shell-quote` renders any value as a single POSIX `sh` word by the
single-quote rule: wrap in `'`, splice each embedded `'` as `'\''`, and the empty
string becomes `''`. Single quotes rather than backslash-escaping because inside
`'…'` every character except `'` is literal — there is no metacharacter set to
keep correct across shells and positions, and no interaction with `$`, backticks,
`\`, newlines, or globs. Seventeen call sites now pass every dynamic argument
through it.

The `flyctl` site needed more than quoting, and this is the part worth
remembering. `SECRETS_AGE_IDENTITY="$(cat <key-file>)"` has two defects, and
quoting closes one: the path must be a single word, *and* `cat` must not read it
as an option, since a key file named `-n` or `--help` changes what the operator's
shell does. It now emits `cat -- '<key-file>'`. That is the same defect issue 006
fixed for `age` and for `rm`/`shred`, at a third binary. The surrounding
`"$(…)"` stays: it is the shell's own construct rather than interpolated data,
and it is what makes the file contents one argument to `flyctl`.

Scope grew from the five sites the issue named to seventeen. The extra twelve are
the `bb secrets …` hints inside `fail!` messages and `verify` output —
`require-identity!`, `recipient-snapshot`, `new!`, `edit!`, `remove-secret!`
(twice), `reencrypt!`, `add-recipient!`, `read-supported-manifest` (twice),
`verify-keyless`, `verify-keyed-diff`, and `verify-one`. They interpolate the
same environment name for the same reason, and a partially quoted surface is the
one that rots. Message wording is otherwise unchanged; only argument rendering
moved. `set-secret!`'s `printf %s "$VALUE" | bb secrets set …` needed nothing —
the `…` is a literal placeholder with no interpolated value — and is byte
identical.

Ordinary values are quoted too. There is deliberately no "looks safe, skip the
quotes" branch, because that branch is exactly what rots; `bb secrets
add-recipient 'dev'` is the cost. The help footer now states that printed
suggestions are POSIX `sh`, single-quoted per argument, which is the criterion's
"documents its expected shell".

The pre-fix behaviour was measured, not reasoned about. With a legal environment
name `(keyword "dev; touch PWNED-ENVNAME; #")` and a legal key path
`key.txt; touch PWNED-KEYFILE`, the old code emitted
`flyctl secrets set SECRETS_AGE_IDENTITY="$(cat key.txt; touch PWNED-KEYFILE)"`
and `bb secrets add-recipient dev; touch PWNED-ENVNAME; #`. Executed against
recording stubs, *both* sentinels were created — one from the `;` inside the
command substitution, one from the `;` splitting the line — and `flyctl` received
an empty value because `touch` had consumed the substitution's output. After the
fix neither sentinel appears and each binary receives the whole value as one argv
element.

Regression tests: `shell-quote-round-trips-adversarial-values-test` (executes
each quoted value through a real shell and compares bytes, because inspecting the
quoted string proves nothing about how a shell reads it),
`generated-commands-execute-as-one-argument-test` (real guidance executed against
stub `bb`/`flyctl`/`cat` on a temp `PATH`, asserting recorded argv and that no
sentinel file appeared), `key-file-named-like-an-option-is-read-as-a-path-test`,
and `ordinary-guidance-is-unchanged-in-substance-test`. Independently re-verified
during review: twenty adversarial values including the empty string, a newline, a
single quote, `$(id)`, backticks, and a backslash all round-trip as exactly one
literal argument.

Unrelated finding, not fixed here: `bb format:check` dies with
`FileNotFoundException` on `src/com/kirahowe/.#secrets.clj` when a source file is
open in Emacs, because cljfmt's directory walk follows the dangling lock symlink.
Nothing to do with this issue, but it makes the format gate fail for a reason
that has no relation to formatting.

## Non-goals

- Supporting every shell dialect with one quoting syntax.
- Automatically executing deployment commands.
- Validating away legitimate paths or environment names solely to simplify
  rendering.

## Verification

Generate suggestions for a table of adversarial values, execute only against
stub `bb`, `flyctl`, and `cat` commands in a temporary POSIX environment, and
assert exact argv capture with no created sentinel files or extra commands.

## Dependencies / related files

- [CLI generated guidance](../src/com/kirahowe/secrets/cli.clj)
- [CLI output tests](../test/com/kirahowe/secrets/cli_test.clj)
- [deployment documentation](../README.md)
