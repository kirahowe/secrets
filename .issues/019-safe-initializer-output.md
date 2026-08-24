# 019 — Safe initializer output

Status: `open`
Priority: P2
Review classification: Low

## Problem

The initializer retains and prints complete old/new file contents while
previewing changes. In noninteractive apply mode, credentials already present
in a target file can therefore be copied to logs or captured stdout.

## Evidence

- [Initializer planning](../src/com/kirahowe/secrets/init.clj) at lines 217–221
  and 262–291 retains full old/new files.
- [Initializer preview](../src/com/kirahowe/secrets/init.clj) at lines 359–364
  prints previews before apply selection.
- Confirmed: a sentinel credential in an existing file appeared in stdout with
  apply enabled. Disclosure requires sensitive content in a touched file and
  captured/observed command output.

## Desired outcome

Default to path/action summaries for noninteractive or apply runs, limit
interactive previews to safe escaped hunks, and require explicit opt-in before
printing complete content.

## Acceptance criteria

- [ ] Noninteractive and apply output reports paths and actions without old or
      new file bodies.
- [ ] Interactive default previews show only minimal changed hunks, redact
      sensitive values, and visibly escape control/terminal sequences.
- [ ] Full-content output requires an explicit warning-bearing opt-in and is
      never enabled merely by `--apply` or noninteractive mode.
- [ ] Planning state does not retain complete old/new sensitive contents longer
      than required to apply safely.
- [ ] Sentinel regressions cover existing credentials, generated private data,
      newlines, ANSI escapes, and apply true; default stdout/stderr contain none.
- [ ] Normal summaries still make every proposed and completed file action
      auditable.

## Non-goals

- Printing secrets to make previews more informative.
- Building a general secret scanner or terminal sanitizer.
- Removing the preview-first initializer workflow.

## Verification

Initialize over files containing unique secret and control-character sentinels
in interactive, noninteractive, preview, and apply modes. Assert safe defaults
never emit them, opt-in behavior is explicit, and resulting files remain
correct.

## Dependencies / related files

- [initializer planning and output](../src/com/kirahowe/secrets/init.clj)
- [initializer tests](../test/com/kirahowe/secrets/init_test.clj)
- [initializer documentation](../README.md)
