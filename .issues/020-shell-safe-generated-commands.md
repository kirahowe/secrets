# 020 — Shell-safe generated commands

Status: `open`
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

- [ ] Every dynamic argument in emitted commands uses one shared, tested POSIX
      argument-quoting routine; no value is concatenated as shell syntax.
- [ ] File-reading snippets use an option boundary such as `cat --` and quote
      the pathname as a separate argument.
- [ ] Values containing spaces, single quotes, newlines, leading dashes,
      substitutions, separators, redirects, and glob characters round-trip as
      one literal argument when the command is pasted.
- [ ] Focused tests parse/execute suggestions in an isolated POSIX shell with
      inert fixtures and prove no sentinel side effect occurs.
- [ ] Ordinary generated guidance remains readable and documents its expected
      shell, or executable shell output is removed entirely.

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
