# 011 — Race-safe initializer writes

Status: `resolved`
Priority: P1
Review classification: Confirmed Medium — alpha release blocker

## Problem

The initializer validates target paths and symlinks, then later re-resolves and
writes those pathnames. In a shared writable parent, an attacker can swap a
validated directory for a symlink between those operations and redirect writes
outside the project (CWE-367, CWE-59).

## Evidence

- [Initializer path checks](../src/com/kirahowe/secrets/init.clj) at lines
  164–179 inspect resolved paths and symlinks.
- [Initializer writes](../src/com/kirahowe/secrets/init.clj) at lines 295–338
  later operate through re-resolved pathnames rather than an anchored directory
  handle.
- The vulnerable shape is a check/use pathname race under an attacker-writable
  project root. Confidence is medium: the separate operations are present, but
  a timing exploit was not executed during review.
- The risk requires another principal able to rename directories or create
  symlinks in the relevant root while initialization runs.

## Desired outcome

Anchor validation and writes to the same trusted directory handle with
no-follow semantics, or fail closed where the platform cannot provide that
guarantee for an untrusted/shared root.

## Acceptance criteria

- [x] Initializer mutations use `SecureDirectoryStream`, openat-style anchored
      operations, or an equivalently reviewed primitive that does not re-walk
      attacker-controlled ancestors after validation.
- [x] Every created/replaced file and traversed child rejects symlinks and
      unexpected non-directory/non-regular types at the operation point.
- [x] Platform capability is detected explicitly; unsupported platforms or
      filesystems fail closed for shared/untrusted roots with actionable output.
- [x] Private single-owner roots retain a documented safe path where the
      stronger primitive is unavailable, without silently claiming race safety.
- [x] Focused coverage includes capability branches and a deterministic
      directory-swap/symlink attempt proving no outside file is changed.
- [x] Preview/apply semantics and normal initialization outputs remain intact.

## Resolution

The first acceptance criterion names `SecureDirectoryStream` and openat-style
anchored operations, and neither is reachable from the runtime this code exists
for. Measured against babashka 1.13.219: `(import [java.nio.file
SecureDirectoryStream])` fails with "Unable to resolve classname", and calling
`.newDirectoryStream` with two arguments on the object `Files/newDirectoryStream`
returns fails with "No matching method newDirectoryStream found taking 2 args
for interface java.io.Closeable" — babashka types the return as
`java.io.Closeable` and cannot reach the interface at all. The initializer is a
`bb -Sdeps … -m com.kirahowe.secrets.init` one-liner, so that runtime is the
whole point of the namespace.

So the fix takes the criterion's own escape clause — "an equivalently reviewed
primitive that does not re-walk attacker-controlled ancestors" — and removes the
*attacker-controlled* half rather than the re-walking. `trusted-ancestry!`
proves, before any mutation, that no other principal can rename or symlink any
ancestor: every directory from the filesystem root down to and including the
project root must be a real directory under `NOFOLLOW_LINKS`, owned by the
current user or by `root`, and writable by nobody else. The threat the issue
describes requires "another principal able to rename directories or create
symlinks in the relevant root"; proving no such principal exists closes it
outright rather than narrowing the window.

Three parts of the rule are load-bearing and non-obvious.

Other-write is accepted when the sticky bit is set. Sticky means only an entry's
own owner may rename or delete it, so another user with write access to `/tmp`
can create entries beside ours but cannot swap ours — which is the entire attack.
Refusing sticky world-writable directories would reject every root under a system
temp directory without removing any attacker capability.

Group-write is accepted when the directory's group name equals its owner's. That
is the user-private group of Fedora, RHEL and Debian: a group holding nobody but
the owner is not another principal, so a `umask 002` checkout at mode 0775 is
exactly as safe as one at 0755. This came out of review — the first
implementation refused group-write outright, which would have made the
initializer unusable on those distributions for no security gain. A shared group
and a non-sticky world-writable directory carry distinct refusal reasons.

Both the resolved path and the path *as written* are walked, and a link component
is judged on its owner alone, since the kernel ignores a symlink's own mode bits.
That is stronger than checking `toRealPath` alone, and it was the implementer's
correction to the design handed over: `/shared-0777/link -> /private/proj`
resolves to a wholly private ancestry, yet anyone who can write `/shared-0777`
can repoint the link mid-run, and the resolved path never names that parent.
Refusing symlinked ancestors outright was not an option either — `/var` and
`/tmp` are symlinks on macOS.

Capability is explicit: `filesystem-capability` requires the default filesystem
to support the `posix` and `unix` attribute views the proof reads, and a
filesystem without them fails closed with actionable output rather than writing
while implying a race safety it never established — the same posture issue 007's
fix takes for a non-POSIX filesystem. The trust basis is printed, so a run states
on what grounds it considered the root safe.

Every mutation re-verifies at the operation point rather than trusting the plan.
`Files/createDirectories` became a segment-by-segment `ensure-directories!` that
verifies each segment after creating it — a directory the initializer just made
is not exempt, because the window between creating and using it is the same
window — and creates with an explicit `rwxr-xr-x`, which a umask can only narrow,
so the check immediately following creation cannot fail on the caller's umask.
Staging moved from `createTempFile` + `Files/write` to `Files/newByteChannel`
with `CREATE_NEW`: `O_CREAT|O_EXCL` fails on any existing entry including a
symlink, so the leaf is no-follow by construction, and the staging name is
generated locally so it cannot be aimed at. Publication stays `ATOMIC_MOVE`,
whose `renameat` replaces an entry at the destination rather than following it —
the leaf was never the exposure, the ancestors were.

Two pre-existing holes were found on the way and had to be closed for the claim
to be true. The non-atomic copy-and-delete fallback after
`AtomicMoveNotSupportedException` *would* follow a symlink planted at the
destination, so it is now a named refusal instead. And the rollback loop could
itself throw through `target-path!`, masking the real cause behind "previous
project files were restored" — precisely what happens in the swap scenario. It
now distinguishes "never written through, nothing to undo" from "restore failed",
reports the paths it declined to touch, and carries the original cause.

Regression tests: `trusted-ancestry-accepts-a-private-root-test` (including a
root under sticky world-writable `/tmp`, with its premises asserted rather than
assumed), `trusted-ancestry-refuses-an-untrusted-ancestor-test` (0777 without
sticky refused, the same directory with `chmod +t` accepted, group-write with
group equal to owner accepted, a shared group refused, and a repointable link
under a shared ancestor refused),
`directory-swap-between-plan-and-apply-changes-nothing-outside-test` (the swap
happens inside the injected input function, between plan and apply, with no
timer; the outside sentinel's bytes are unchanged and `bb.edn` was never
written), `unsupported-filesystem-capability-fails-closed-test`,
`staging-write-refuses-an-existing-entry-test`, and
`preview-reports-whether-apply-would-be-refused-test`. No existing initializer
test needed weakening.

## Non-goals

- Claiming protection from an attacker who controls the process account or an
  already-open trusted directory.
- Reimplementing a complete cross-platform filesystem abstraction.
- Replacing permissions and ownership controls for project roots.

## Verification

Use a temporary root with an outside sentinel and coordinate a directory swap
between plan creation and apply. Assert initialization either completes only
inside the anchored tree or fails before mutation, the sentinel is unchanged,
and the unsupported-capability branch emits the documented refusal.

## Dependencies / related files

- [initializer path validation and writes](../src/com/kirahowe/secrets/init.clj)
- [initializer tests](../test/com/kirahowe/secrets/init_test.clj)
- [initializer documentation](../README.md)
