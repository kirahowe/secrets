# 019 — Safe initializer output

Status: `resolved`
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

- [x] Noninteractive and apply output reports paths and actions without old or
      new file bodies.
- [x] Interactive default previews show only minimal changed hunks, redact
      sensitive values, and visibly escape control/terminal sequences.
- [x] Full-content output requires an explicit warning-bearing opt-in and is
      never enabled merely by `--apply` or noninteractive mode.
- [x] Planning state does not retain complete old/new sensitive contents longer
      than required to apply safely.
- [x] Sentinel regressions cover existing credentials, generated private data,
      newlines, ANSI escapes, and apply true; default stdout/stderr contain none.
- [x] Normal summaries still make every proposed and completed file action
      auditable.

## Resolution

Three output modes, with the safe one as the default. Noninteractive or `--apply`
prints paths, actions (`create` / `merge into the existing file` /
`leave as is`) and honest counts, plus an `Applied:` block naming each completed
path — no bodies. Interactive adds the changed region only, three lines of
context, every line rendered. `--show-contents` prints complete bodies and is
implied by nothing; the precedence is deliberately `show-contents? → :full`,
`(or apply? (not tty?)) → :summary`, else `:hunks`, so an interactive `--apply`
run prints no bodies: the safe mode wins.

The implementer found the flaw in the issue's own framing, and it changed the
design. Withholding `:old` fixes nothing on its own, because `merge-bb-edn`
*preserves* the existing `bb.edn` text — so a credential already in that file is
in the **new** body too. Suppressing only the old side would have left the
disclosure intact by another name. `:old` is dropped from the plan entirely
(its only consumers were change detection and the diff; `apply-changes!` re-reads
its own rollback bytes and never touched it), planning now derives an `:action`
instead, and `init!` returns `:actions` rather than `:changes` — a programmatic
caller printing the status map was the same leak by a third route. `:content`
necessarily stays on the internal plan, because it is what gets written.

Rendering is three guards, each with a reason. Control characters and ANSI
sequences are escaped visibly (`\x1b`, `\r`), because a previewed file is
untrusted input to the terminal and a crafted `bb.edn` could otherwise rewrite
what the operator sees. Credential-looking values are replaced with
`[redacted N characters]` — a value under a key matching
`secret|token|password|key|credential`, an `AGE-SECRET-KEY-1…` string, or a long
mixed-case-and-digit opaque token — documented as a targeted guard for obvious
cases and explicitly not a secret scanner, which is a stated non-goal. Long lines
truncate with a count. Paths are escaped and truncated but *not* redacted, since
redaction would mangle `secrets/key.txt`. Verified directly:
`:my/password "SENTINEL…"` renders as `:my/password [redacted 36 characters]`,
and `\u001b[31mRED` renders as `\x1b[31mRED`.

Regression tests: `apply-output-contains-no-file-bodies-test` (the confirmed
defect, asserting *both* streams — a preview that moved the leak to stderr is not
a fix), `interactive-preview-redacts-and-escapes-test`,
`full-contents-require-explicit-opt-in-test` (including that the warning precedes
the first body line and that `--apply` alone does not enable it),
`summaries-remain-auditable-test`, and `status-map-carries-no-file-bodies-test`.
Measured against the pre-fix file, the sentinel appeared twice across
stdout+stderr; after, zero. Confirmed independently with a real run over a
`bb.edn` holding a password, an age secret key, an ANSI sequence and a bare CR.

`preview-shows-before-and-after-content-test` was removed rather than updated: it
asserted the leaking output shape itself, so it was a test *of* the defect. Its
preview coverage moved into `full-contents-require-explicit-opt-in-test`. Issue
011's `preview-reports-whether-apply-would-be-refused-test` had one assertion on
the old `--- /dev/null` diff header and now asserts the action line instead; its
trust assertions are untouched.

One incidental finding: a bare `\r` never survives the merge, because
`rewrite-clj` rewrites a lone carriage return inside an existing `bb.edn` string
to `\n` on re-emit. The sentinel therefore only appears on the old side, where
the escape does catch it. Pre-existing `merge-bb-edn` behaviour, left alone.

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
