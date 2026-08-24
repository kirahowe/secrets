# 007 — Secure plaintext file output

Status: `resolved`
Priority: P0
Review classification: Confirmed Medium — alpha release blocker

## Problem

`decrypt-to-file!` opens its destination pathname directly. A newly created
plaintext file inherits permissive process defaults, and an existing symlink is
followed (CWE-732, CWE-59). Although current CLI temporary files happen to be
pre-created with mode `0600`, the public age API itself can disclose plaintext
or overwrite a symlink target.

## Evidence

- [`decrypt-to-file!`](../src/com/kirahowe/secrets/age.clj) at lines 177–182
  passes the requested output directly to an output stream.
- Confirmed under umask `022`: a new output was created with mode `0644`.
  A destination symlink was followed.
- The attack requires control of the destination directory or pathname, or a
  caller selecting an unsafe path. The confirmed impact is plaintext exposure
  through file permissions and writes through a symlink; the CLI's currently
  pre-created `0600` temporaries do not prove every public caller exploitable.

## Desired outcome

Publish decrypted plaintext only through an exclusive, owner-only sibling
staging file, refuse link traversal, and atomically replace the intended
regular-file destination after successful decryption.

## Acceptance criteria

- [x] Decryption creates a sibling staging file exclusively with owner-only
      permissions (`0600`) independent of umask before writing plaintext.
- [x] If owner-only permissions cannot be established or verified, decryption
      fails closed before any plaintext is written.
- [x] Destination and staging operations fail closed on symlinks and other
      unsupported file types; an attacker cannot redirect the write outside
      the selected directory.
- [x] Successful decryption atomically replaces the intended destination on
      the same filesystem without a window containing a permissive plaintext
      file.
- [x] Decryption, close, permission, and move failures remove partial staging
      plaintext and leave the prior destination intact.
- [x] Focused tests cover umask `022`, pre-existing destination, destination
      symlink, staging-name collision, and failed authentication/decryption.
- [x] Public API and CLI callers retain successful behavior for ordinary safe
      destinations.

## Resolution

`decrypt-to-file!` no longer writes through the pathname it is handed. It
validates the destination, decrypts, stages the plaintext in a sibling file that
is owner-only from the instant it exists, and publishes by rename(2). Four
private helpers in [`age.clj`](../src/com/kirahowe/secrets/age.clj) carry the
parts: `plaintext-destination`, `owner-only-staging-file!`,
`publish-plaintext!`, and the `catch` in `decrypt-to-file!` itself.

Measured pre-fix behaviour, all against age 1.3.1 with the old one-line
`io/copy` body restored: a fresh destination was created `0644` under umask
`022`; a destination symlink was followed and its target overwritten with
plaintext; a directory destination raised `FileNotFoundException (Is a
directory)`; `""` and nil raised `FileNotFoundException`; and `"   "` did not
fail at all — it silently created a file literally named `   ` in the process
working directory, which is the same unset-CI-variable shape issue 006 closed
for age's own arguments. Post-fix the published file is `0600` whatever the
umask and whatever mode the destination had before (verified `0644` → `0600` on
a pre-existing destination), and every one of those cases throws `ex-info`
without creating a file.

Three design points are load-bearing and easy to get wrong later.

Only the *final* path component is checked, and only without following links.
A symlinked parent must stay legitimate: macOS temp directories live under
`/var`, itself a link to `/private/var`, so rejecting parent links would reject
every CLI caller. For the same reason the destination is never canonicalized —
`getCanonicalPath` and `toRealPath` resolve a final link *away*, which would
defeat exactly the check being made. `Files/exists` with `NOFOLLOW_LINKS` is
true of a dangling link, so those fail closed too.

The validation is for explicit fail-closed semantics, not for the safety of the
write. `Files/move` replaces a symbolic link *itself* rather than following it,
so a destination that becomes a link between validation and publication still
cannot receive plaintext through the link; the race is benign by construction.
What the check buys is refusing a caller mistake or an attack loudly instead of
quietly replacing someone's link. Likewise `createTempFile` opens `CREATE_NEW`
with a random infix and applies the mode as a *creation* attribute, so a
pre-planted file or link sharing the staging prefix and suffix can never be the
file written, and there is no window at default permissions. The mode is then
read back with `NOFOLLOW_LINKS` and compared, because "established" and
"verified" are different claims.

Decryption deliberately runs *before* the staging file is created, so a wrong
key never creates one. That satisfies the decryption half of the
partial-plaintext criterion structurally rather than by cleanup — and it is the
part issue 016 will invalidate. Once 016 replaces `decrypt-bytes`' whole
output-capture model with streaming, plaintext will flow *into* the staging
file, the `catch` becomes the primary defence rather than a backstop, and
`decrypt-to-file-cleans-up-staging-when-publishing-fails-test` becomes the test
that matters most. That test forces the failure by redefining the private
`publish-plaintext!` var, so the real staging file is really created and really
holds plaintext; deleting the `catch` body makes it, and only it, fail (verified:
1 failure out of 546 assertions).

One deliberate policy change: a filesystem without POSIX permissions now fails
closed instead of writing plaintext with platform defaults, pointing the caller
at `decrypt-bytes` / `decrypt`, which never touch the filesystem. Nothing is
actually lost — `load-secrets` decrypts in memory — and it makes the book's
"treat Windows as unsupported for anything beyond reading" literal rather than
aspirational.

CLI callers are unchanged and needed no edits. Their destinations are
pre-created `0600` temp files in `java.io.tmpdir`, so the staging sibling is
always on the same filesystem and the atomic move always applies; `deleteOnExit`
and `secure-delete!` are path-based and indifferent to the inode swap. The
atomic-move helper is deliberately duplicated rather than shared with
`cli.clj`'s `atomic-replace!`: `secrets` requires `age`, so `age` cannot require
either of the higher layers, and a new namespace for eight lines would cost more
than it saves. Both copies identify `AtomicMoveNotSupportedException` by class
name because Babashka does not expose it as a resolvable class, and neither
falls back to a non-atomic copy — copying is what would reopen the window.

Regression tests, all in
[`secrets_test.clj`](../test/com/kirahowe/secrets_test.clj):
`decrypt-to-file-publishes-owner-only-plaintext-test` (which first proves the
ambient umask is permissive by checking that a plain `spit` is world-readable,
so a `0600` result can only come from the creation attribute),
`decrypt-to-file-replaces-an-existing-destination-test`,
`decrypt-to-file-refuses-link-and-non-regular-destinations-test`,
`decrypt-to-file-ignores-planted-staging-names-test`,
`decrypt-to-file-leaves-the-destination-intact-when-decryption-fails-test`,
`decrypt-to-file-fails-closed-when-staging-cannot-be-created-test`,
`decrypt-to-file-rejects-unusable-destination-paths-test`, and
`decrypt-to-file-cleans-up-staging-when-publishing-fails-test`.
`binary-roundtrip-test` and the `decrypt-to-file!` assertions inside
`dash-leading-relative-paths-work-for-every-path-argument-test` are the
no-regression controls for ordinary and dash-leading destinations.

Two of those tests do not falsify the old code and are honest controls rather
than proofs: the wrong-key case passed pre-fix because `decrypt-bytes` was an
*argument* to `io/copy` and threw before the destination was opened, and the
unwritable-directory case passed because a mode `0500` directory also defeated
the old `FileOutputStream`. The latter also carries a root guard: it probes
whether this process can create a file in a `0500` directory and skips if it
can, since root can. Testing note for whoever adds link fixtures next:
Babashka does not pack Java varargs, so `Files/createSymbolicLink` needs an
explicit empty `FileAttribute` array — hence the `symlink!` test helper.

## Non-goals

- Secure deletion guarantees on journaling or copy-on-write filesystems.
- Changing ciphertext file permissions or the format of decrypted data.
- Treating the CLI's current temporary-file behavior as a substitute for
  fixing the public API.

## Verification

Exercise the public function in a private temporary directory with a real age
ciphertext. Inspect the published mode, verify atomic replacement preserves an
old destination until success, and prove symlink and forced-decryption failure
cases neither alter their targets nor leave plaintext staging files.

## Dependencies / related files

- [age file decryption](../src/com/kirahowe/secrets/age.clj)
- [CLI plaintext temporary-file callers](../src/com/kirahowe/secrets/cli.clj)
