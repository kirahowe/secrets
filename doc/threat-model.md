# Threat model and design boundaries

This is the decision rule for what belongs in this library. It records the
requirements, trust boundaries, and lessons from the September 2026 architecture
review. It is a design target, not a claim that the implementation already meets
every requirement below.

The library is unreleased and has no users. Compatibility with existing commands,
formats, options, and identity resolution rules is not a constraint. Ergonomics,
security, simplicity, maintainability, and correctness are goals. We want useful
protection against plausible mistakes and named threats, without building a
subsystem for every hypothetical adversary.

This document owns the threat and design rationale. `SECURITY.md` still owns
vulnerability reporting and response; it is not replaced by this document.

## The essential problem

- Keep structured application secrets encrypted in version control.
- Decrypt them into application data using an authorized identity.
- Let an operator create and update them without exposing plaintext or damaging
  the usable store.
- Make changes meaningfully reviewable without decrypting. The committed manifest
  is a valuable part of the product, not an optional convenience to discard just
  to reduce code. The intended experience includes added and removed paths, type
  changes, and value-change indicators for both solo and team use.

Those are requirements. Global caches, arbitrary-file encryption commands,
automatic editing of existing project configuration, and a particular manifest
format are implementation or product choices that must justify their cost.

## What this protects

- Private age identities, which can decrypt ciphertext addressed to them,
  including historical versions.
- Plaintext secret values and any confidential manifest hashing key.
- The correctness and availability of the stored configuration. A wrong endpoint
  can leak data or break an application; losing the only usable store is also a
  failure worth preventing.

The application remains responsible for validating the meaning of its own
configuration. The library cannot decide whether a database URL is the right one.

## Trust assumptions

The deployment process selects an approved configuration artifact and protects
the route from review to the running application. A repository contribution is
not automatically an approved deployment. The library provides no sender
authentication or protection against replay of an older valid artifact.

The operator chooses a trusted working/output directory. The decrypting host,
application process, and installed `age` binary are trusted. These assumptions
do not make accidental malformed or oversized input impossible.

## Threats and mistakes in scope

### A1. A repository reader without an identity

They can read ciphertext, manifests, public recipients, source, and git history.
For a public repository, this is everyone. They must not obtain secret values or
enough public information to cheaply test guesses of low-entropy values.

Reviewability deliberately discloses metadata: key paths, value types, collection
sizes, and value equality/change indicators where hashes are present. Ciphertext
size and committed change history are also visible. Manifest key paths must be
treated as public metadata; secret values do not belong in map keys.

Age provides encryption. If public value-change indicators use hashes, those
hashes need a confidential, unpredictable key. Unkeyed hashes of passwords are
not an acceptable substitute. Deterministic, unambiguous value encoding avoids
false equality caused by serialization, but a finite hash is not collision-free.
The current 64-bit truncated HMAC must not be described as an injective hash.

The manifest exists for reviewability. Confidentiality constrains how we build
it; confidentiality alone does not justify the manifest's entire design.

### A2. Operator mistakes and ordinary failures

Prefer small checks for failures that would otherwise be silent or destructive:

- A missing CI secret expands to a blank identity setting, and fallback silently
  selects a different identity.
- Blank or dash-leading path arguments are interpreted as subprocess options or
  standard input instead of the intended file.
- Derived artifact names collide, or environments assign incompatible roles to
  the same file.
- An interrupted write damages the only ciphertext, or leaves its manifest stale.
- A URI is supplied where a local path was expected.
- A parser ignores trailing input or exposes secret text in its errors.
- An accidental large file or deeply nested EDN exhausts resources.
- Invalid manifest metadata silently disables value-change reporting.

Modest byte and nesting bounds remain useful for mistakes. Share their
implementation and avoid unnecessary configuration modes. A check is not worth
keeping in its current form just because it can be called a security defense.

### A3. A reader of logs or diagnostics

Secret values, private identities, and manifest hashing keys must not appear in
errors, exception causes, logs, or generated public examples. This applies to
ordinary failures as well as malicious inputs. Parser errors should report a
reason and useful location without reproducing the rejected text.

Caller-supplied filesystem paths are permitted diagnostic metadata, including
identity paths. We do not need a provenance subsystem solely to hide temporary
pathnames. This is a disclosure policy, not a claim that every possible path is
non-sensitive. Credentials embedded in locators and arbitrary source objects
must not be rendered wholesale.

### A4. Another local user on a shared machine

Create private files with owner-only permissions from the moment they exist.
Use exclusive temporary-file creation, cleanup scoped to the operation, and
replacement operations that do not write through a substituted destination link.
If private creation is unavailable, do not silently write sensitive bytes with
default permissions.

These are local guarantees about operations the library performs. We do not
attempt to prove every ancestor of a project directory untamperable or defend
against an attacker controlling the selected working directory. Such control
also does not necessarily imply control of the application's source; that
equivalence is not a reason to remove ordinary safe filesystem operations.

### A5. A former recipient observing future changes

Revocation cannot make someone forget values or keys they already read. But new
values published after revocation should not become guessable through the public
manifest using a hashing key that former recipient retained.

A shared manifest key inside the encrypted store creates this obligation.
Re-encrypting to fewer recipients alone does not revoke knowledge of that key.
Any replacement design must address its renewal before publishing future values,
or explicitly revisit the product's revocation guarantee. The operator still
rotates credentials at their provider; manifest-key handling cannot revoke an
already disclosed provider credential.

## Threats out of scope

### B1. An attacker who can replace the deployed configuration artifact

Public recipients allow anyone to encrypt chosen contents. Age does not identify
the sender. Someone who can replace both deployed ciphertext and its manifest
can make those artifacts agree with each other. Agreement does not establish
approval or authorship.

Protecting the repository, build, and deployment channel is the deployment
system's responsibility. We will not add an authorship infrastructure to this
library. This exclusion does not eliminate the usefulness of bounded input,
safe parsing, or local-only source contracts against operator mistakes.

### B2. A former recipient's access to previously disclosed values

Git history can retain ciphertext that their identity still decrypts. Removing a
recipient and re-encrypting the current store cannot revoke historical access or
make an old credential unusable. Rotate the credential at its provider. A5
separately covers new values and retained manifest hashing keys.

### B3. A compromised decrypting host or application process

The application holds plaintext in memory. Root, a heap dump, an attached
debugger, or compromised code in the same process may read it. A library cannot
defend its own address space. This does not justify retaining temporary private
files longer than their operation needs them.

### B4. A hostile `age` binary

The installed `age` executable is part of the trusted system. We do not attempt
to contain a hostile encryption implementation.

## Manifest guarantees and recovery

| Property | Responsibility or limit |
| --- | --- |
| Confidentiality of encrypted values | age, plus confidential hashing material for public value indicators |
| Ciphertext integrity against corruption | age |
| Reviewable paths, types, and value changes | the committed manifest; desired consistently for solo and team use |
| Keyless digest check | detects disagreement with the recorded ciphertext digest; cannot prove the manifest describes the plaintext |
| Verification with an identity | compares the decrypted store with the manifest; does not establish authorship |
| Sender authenticity or replay prevention | outside this library |

Ciphertext is the authoritative artifact. A manifest is derived metadata that an
authorized recipient can regenerate. Losing a temporary plaintext file does not
prevent regeneration when valid ciphertext and a usable identity remain.

Atomic replacement protects a single ciphertext from partial writes. Two atomic
renames do not make a ciphertext/manifest pair one atomic transaction. Rollback
can help with caught I/O failures but cannot run after process termination.
A simpler recovery contract can permit detectable manifest staleness after
interruption. The exact write/recovery behavior remains a separate implementation
task; do not claim that pairwise atomicity or power-loss durability follows from
rename alone.

## Lessons from the manifest experiment

The session reviewed commits `4f4467e`, `c8ede1d`, and `6d4c838`. These findings
describe that experiment, not a claim that it is the current implementation or
that its proposed remedies have been accepted as a complete design.

Moving from identity-derived hashes to a random per-store key inside the
encrypted payload is a promising direction. It lets different recipients compute
the same value hashes and removes private-identity parsing. Keep reviewability
while evaluating this design; do not expand it into another key-management
subsystem by default.

The review found the following issues to resolve individually:

1. **Revocation:** a two-recipient reproduction removed one recipient,
   re-encrypted, and changed a synthetic PIN. The removed identity could no longer
   decrypt, but its retained manifest key identified the new PIN from candidate
   hashes. See A5. Calling this key "not itself a secret" is incorrect.
2. **Silent downgrade:** setting the reserved metadata key to `nil` produced no
   value hashes and still passed verification. Arbitrary short or non-string key
   values were also accepted. Generated metadata needs a clear validity contract;
   no compatibility requirement mandates a structure-only fallback.
3. **Cleanup:** the additional keyed plaintext temporary file was populated
   before entering its cleanup scope. An injected later staging failure left it
   on disk until process exit. Every acquired private resource needs cleanup even
   when the next acquisition fails.
4. **Ownership and ergonomics:** the editor and `set`/`rm` exposed reserved
   hashing metadata to ordinary editing. A copied or shared template containing
   that key could also give different stores the same key. Library-owned metadata,
   creation semantics, and template handling should be considered together.
5. **Validation:** tests should exercise actual store creation, edits by different
   recipients, and loading through the public API. A test helper that strips the
   reserved key itself does not verify that `load-secrets` hides it. Comparing
   manifest entries should account for the ciphertext digest changing on
   re-encryption.

Fresh random keys distinguish independently initialized stores; copying a keyed
store does not generate a fresh key. Documentation must state the actual behavior
and distinguish approved requirements, design proposals, and verified guarantees.

## Architecture questions for separate sessions

The review also identified candidates beyond the manifest. These are bounded
work items to evaluate individually, not instructions to implement them all:

- Replace global identity caching, generations, and leases with operation-owned
  temporary identities where possible.
- Scope Aero loading to a configuration read or application-owned lifecycle,
  instead of a global cache keyed by configuration equality.
- Make normalization pure and use one identity precedence rule. The reviewed
  runtime favored explicit identity options while the CLI favored environment
  variables; normalization could also materialize a private file.
- Evaluate a common recipient-based encryption path for solo and team use.
- Keep setup ergonomic while reducing the initializer's responsibility for
  modifying existing projects and proving filesystem ancestry.
- Narrow overlapping source/argument forms and general-purpose file commands;
  put store operations beneath prompts and CLI rendering.
- Reduce duplicated build/documentation policy and verification. Moving code to
  another package does not by itself remove maintenance cost.

## How to decide what to change

1. Name the required behavior and the plausible failure or in-scope threat.
2. Ask whether simpler ownership, a narrower interface, or removing an optional
   behavior eliminates the need for the defense.
3. Retain the smallest mechanism that establishes the needed invariant. Safety
   errors still follow the disclosure policy, and ordinary failures still need
   cleanup.
4. Share a surviving primitive where that makes its contract clearer. Avoid
   replacing a few straightforward functions with a general framework.
5. Verify the observable behavior and relevant failure path. Do not preserve
   tests of obsolete internal machinery as requirements in their own right.

Work on one concern at a time in a fresh session. Record the chosen contract and
its tradeoffs before extending the implementation. An identified risk belongs
here even when its remedy is still undecided; recording it is not authorization
to implement every proposed fix at once.
