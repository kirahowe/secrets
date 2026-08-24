# 009 — Snapshot recipients before encryption

Status: `resolved`
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

- [x] The CLI snapshots the complete recipients file once, before opening an
      editor or beginning a write, and validates exactly the values used for
      encryption.
- [x] Encryption receives repeated validated `-r` values or an owner-only,
      no-follow snapshot that cannot be redirected or changed by the worktree.
- [x] Recipient count, per-line size, and total input size are bounded before
      starting age; empty and malformed entries fail closed.
- [x] Swapping, truncating, or restoring the configured recipients pathname
      after validation cannot change the ciphertext's actual recipient set.
- [x] A deterministic race regression mutates the source between validation
      and encryption and proves only the original validated recipients decrypt.
- [x] Single-key mode and ordinary multi-recipient `new`, `set`, `edit`, and
      `reencrypt` behavior remain intact.

## Resolution

The recipients *pathname* no longer reaches age. `recipient-snapshot` in
[cli.clj](../src/com/kirahowe/secrets/cli.clj) reads the file exactly once,
bounds and validates it, and returns an immutable vector of recipient strings;
`encrypt-target!` wraps that as `{:recipients [...]}`, which `age.clj` already
renders as one `-r` per value. Single-key mode returns `{:identity-file …}`
after `require-identity!` and has no second file to race. `encrypt-recipients`
and `require-encrypt-target!` are gone, and `write-secrets!` takes the resolved
spec as an argument instead of deriving it, so there is no longer any code path
between validation and encryption that can consult the filesystem.

Repeated `-r` was chosen over the acceptance criteria's other option — an
owner-only no-follow snapshot file — because it removes the second read
entirely rather than making it safer. There is no snapshot to create, permission,
or clean up, and the non-goal about not retaining an unlinked recipient snapshot
is satisfied by construction. The recipient values become visible in the process
table where `-R <path>` was not; age recipients are public keys, so this
discloses only the count and identity of recipients to local users, which the
committed recipients file already discloses to anyone with the repository.

Each of the six encrypting commands calls `encrypt-target!` exactly once, and
placement matters more than it looks: `new!` and `edit!` resolve it before the
editor opens, `set-secret!` before `(slurp *in*)`, and `edit!`,
`remove-secret!` and `reencrypt!` before `age/decrypt-to-file!`.
`reencrypt!` exists to pick up a changed list, so it snapshots at command start
— which naturally includes a recipient a preceding `add-recipient` appended.
`add-recipient!` gained no snapshot call because it does not encrypt: it appends
and then prints the `reencrypt` advice. Its membership check deliberately keeps
using the unvalidated reader, since validating there would make the command
that fixes a malformed recipients file refuse to run on one.

Bounds arrived as a new optional top-level `:limits` config key —
`:max-recipients` 256, `:max-recipient-chars` 1024, `:max-recipients-bytes`
262144 — merged over `default-limits` and resolved onto every environment. The
key is deliberately general rather than recipient-specific: issue 016 extends
the same map with source and plaintext sizes. `resolve-limits` rejects a
non-map, an unknown key, and any non-positive-integer value, because a typo in
a security limit must not read as "leave it at the default". The total-size
bound is checked against `(.length f)` *before* the slurp, so an enormous file
is refused rather than read. A rejected line's diagnostic names its 1-based
file line number and quotes only a 16-character prefix; a hand-edited line may
hold anything, and an error message is not the place to echo it.

`recipients!` and `doctor` keep the unvalidated reader on purpose — their
contract is to report, not to throw — but listing a line that encryption would
refuse as though it were a recipient reads as an assurance the write path does
not give, so such lines are now marked in the listing.

Regression tests: `recipients-are-snapshotted-before-the-editor-test` (two real
identities; `run-editor!` replaces the recipients file with B's key mid-edit for
both `new` and `edit`; asserts the file on disk really changed, that A still
decrypts, and that B cannot), `recipient-limits-fail-closed-test` (each bound
over-limit plus an exactly-at-limit success with two real keys),
`malformed-recipients-fail-closed-test` (garbage line named by file line number,
truncated key, comments-only file, prefix-only diagnostic, and a recording
`shell/sh` proving the only age argv is the `age --version` install probe),
`invalid-limits-config-fails-closed-test`, and
`age-receives-repeated-r-arguments-test` — an argv-shape test, because no
behavioural test can see a regression back to handing age the path.

With `encrypt-target!` reverted to validate-then-pass-the-pathname, the race
test fails with B decrypting the ciphertext.

One ordering change fell out: `require-encrypt-target!` used to run before the
"No secrets file at …" existence check in `edit!`, `remove-secret!` and
`reencrypt!`, and now runs after it, so a missing store is reported before an
empty or invalid recipient list. Both are fail-closed configuration errors,
`require-identity!` still runs first, and single-key mode is unaffected.

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
