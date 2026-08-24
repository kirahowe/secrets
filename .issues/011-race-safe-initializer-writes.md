# 011 — Race-safe initializer writes

Status: `open`
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

- [ ] Initializer mutations use `SecureDirectoryStream`, openat-style anchored
      operations, or an equivalently reviewed primitive that does not re-walk
      attacker-controlled ancestors after validation.
- [ ] Every created/replaced file and traversed child rejects symlinks and
      unexpected non-directory/non-regular types at the operation point.
- [ ] Platform capability is detected explicitly; unsupported platforms or
      filesystems fail closed for shared/untrusted roots with actionable output.
- [ ] Private single-owner roots retain a documented safe path where the
      stronger primitive is unavailable, without silently claiming race safety.
- [ ] Focused coverage includes capability branches and a deterministic
      directory-swap/symlink attempt proving no outside file is changed.
- [ ] Preview/apply semantics and normal initialization outputs remain intact.

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
