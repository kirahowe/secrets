# 009 — Snapshot recipients before encryption

Status: `open`
Priority: P0
Review classification: Confirmed Medium — alpha release blocker

## Problem

The CLI validates a recipients file early but retains its mutable pathname and
later asks age to read it again with `-R`. In workflows containing an editor or
other delay, a shared-worktree attacker can swap the file after validation and
control the actual encryption recipients (CWE-367).

## Evidence

- [CLI configuration and recipient validation](../src/com/kirahowe/secrets/cli.clj)
  at lines 354–387 retains the resolved recipients path.
- [CLI write and edit flows](../src/com/kirahowe/secrets/cli.clj) at lines
  562–579 and 721–738 later encrypt through that path.
- [age encryption](../src/com/kirahowe/secrets/age.clj) at lines 133–146 passes
  the mutable path to age with `-R`.
- In a shared writable worktree, an attacker can replace the list during the
  editor interval, copy ciphertext readable by the substituted recipient, and
  restore the original list. The race follows directly from separate pathname
  reads; a timed exploit has not been claimed as a separate confirmed
  reproduction.
- A successful swap can disclose the complete store to the substituted
  recipient and may exclude legitimate recipients from the resulting
  ciphertext.

## Desired outcome

Read, bound, parse, and validate the recipient set exactly once before the
sensitive workflow, then encrypt from that immutable validated snapshot.

## Acceptance criteria

- [ ] The CLI snapshots the complete recipients file once, before opening an
      editor or beginning a write, and validates exactly the values used for
      encryption.
- [ ] Encryption receives repeated validated `-r` values or an owner-only,
      no-follow snapshot that cannot be redirected or changed by the worktree.
- [ ] Recipient count, per-line size, and total input size are bounded before
      starting age; empty and malformed entries fail closed.
- [ ] Swapping, truncating, or restoring the configured recipients pathname
      after validation cannot change the ciphertext's actual recipient set.
- [ ] A deterministic race regression mutates the source between validation
      and encryption and proves only the original validated recipients decrypt.
- [ ] Single-key mode and ordinary multi-recipient `new`, `set`, `edit`, and
      `reencrypt` behavior remain intact.

## Non-goals

- Preventing an authorized repository writer from changing recipients before a
  command starts or from replacing ciphertext after it completes.
- Building a general recipient-management service.
- Keeping an unlinked plaintext recipient snapshot longer than one operation.

## Verification

Use distinct real age identities and a synchronization hook around an
editor-backed operation. Replace the recipients file after validation, then
prove the original identity can decrypt and the substituted identity cannot.
Also exercise the configured size/count boundaries and snapshot cleanup.

## Dependencies / related files

- [CLI recipient resolution and write flows](../src/com/kirahowe/secrets/cli.clj)
- [age encryption integration](../src/com/kirahowe/secrets/age.clj)
- [CLI recipient tests](../test/com/kirahowe/secrets/cli_test.clj)
