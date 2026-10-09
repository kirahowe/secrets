# Threat model and design boundaries

This is the decision rule for what belongs in this library. It records the
requirements, trust boundaries, and lessons from the September 2026 architecture
review, and the contracts chosen since. The requirement sections are the design
target. The sections titled "Chosen ... contract" and "Other chosen contracts"
describe what the implementation does. No requirement below is known to be
unmet. The design questions that are still undecided are listed under
"Architecture questions still open".

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
- Plaintext secret values and each store's manifest key.
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
sizes, and a value equality/change indicator for every leaf. Ciphertext
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
Re-encrypting to fewer recipients alone does not revoke knowledge of that key,
so the key is renewed whenever the recipient set changes, before any later value
is published. The chosen manifest contract below states the rule. The operator
still rotates credentials at their provider; manifest-key handling cannot revoke
an already disclosed provider credential.

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
| Confidentiality of encrypted values | age, plus the per-store manifest key for public value indicators |
| Ciphertext integrity against corruption | age |
| Reviewable paths, types, and value changes | the committed manifest, the same for solo and team stores |
| Keyless digest check | requires a complete manifest and detects disagreement with the recorded ciphertext digest; cannot prove the manifest describes the plaintext |
| Verification with an identity | the keyless check, plus a comparison of the decrypted store with the manifest; does not establish authorship |
| Sender authenticity or replay prevention | outside this library |

Ciphertext is the authoritative artifact. A manifest is derived metadata that an
authorized recipient can regenerate. Losing a temporary plaintext file does not
prevent regeneration when valid ciphertext and a usable identity remain.

Atomic replacement protects a single ciphertext from partial writes. Two atomic
renames do not make a ciphertext/manifest pair one atomic transaction, and a
rollback cannot run after process termination, so the library does not attempt
one. A write validates the plaintext, encrypts it, and renders the manifest
before it replaces anything. It then replaces the ciphertext, and then the
manifest. If the manifest is not replaced after the ciphertext was, the manifest
is stale: the command reports that when it is still running, `verify` detects
it either way, and `reencrypt` regenerates the manifest. Do not claim that
pairwise atomicity or power-loss durability follows from rename alone.

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

The design that answers these five findings is recorded under "Chosen manifest
contract" below.

## Architecture questions still open

The review also identified candidates beyond the manifest. Four of them are
decided and recorded under "Other chosen contracts": the initializer, Aero
loading, the general-purpose file commands, and the input bounds. These remain
bounded work items to evaluate individually, not instructions to implement
them all:

- Evaluate a common recipient-based encryption path for solo and team use.
- Narrow overlapping source/argument forms, and put store operations beneath
  prompts and CLI rendering.
- Make normalization pure. Canonical path checks still use the filesystem, so
  this remains a separate simplification from the identity contract.
- Reduce duplicated build/documentation policy and verification. Moving code to
  another package does not by itself remove maintenance cost.

## Chosen identity contract

Identity resolution is scoped to one operation. `with-identity` accepts an
identity path or options and calls its function with
`{:identity-file path :identity-source source}`. Resolution uses an explicit
path or `:identity-file` first, then `SECRETS_AGE_IDENTITY_FILE`,
`SECRETS_AGE_IDENTITY`, and `SECRETS_AGE_IDENTITY_B64`, then the CLI's
configured `:key-file` or its app default.

An explicit path and `SECRETS_AGE_IDENTITY_FILE` each designate a file, and a
designated file that does not exist is an error. When nothing is designated
and no key file is present, no identity is available, which is what leaves
keyless verification and a `nil` optional secret possible. A missing
designated file used to mean
"no identity", so a typo in a deployment passed a keyless check. Every identity
path has a leading `~` expanded. A URI-shaped path, and key contents in a path
setting, are refused without being echoed (A2, A3).

Raw and base64 identities are materialized for each operation in an exclusive
0600 temporary file. The operation deletes it with an ordinary delete and
checks the deletion on both success and failure. It does not try to overwrite
the file first: that protects nothing on a copy-on-write or flash filesystem.
Caller-owned paths are never deleted. A cleanup failure carries structured
error data with the temporary path so an operator can remove the remaining file.
Paths are permitted diagnostic metadata; identity contents are never included. A process
crash can leave a temporary file behind, and deletion is not secure erasure on
every filesystem. The extra temporary-file write per operation is the accepted
cost of removing shared identity state. The plaintext temporary file that
`new`, `edit`, `set`, `rm`, and `reencrypt` use follows the same rule.

`load-secrets` owns this scope automatically. CLI normalization validates and
canonicalizes configured paths without selecting an environment identity or
materializing one. A CLI command selects its environment, resolves its
identity, validates that resolved path against the configured artifact roles,
and then owns the operation scope. There is no identity cache or reset
lifecycle.

## Chosen manifest contract

Every store holds the library's metadata inside its encrypted EDN, under the one
reserved top-level key `:com.kirahowe.secrets/store`. The metadata is a map,
`{:version 1 :manifest-key "<64 hex>" :recipients "<record>"}`. `:version` is
the version of the store format, separate from the manifest's. `:manifest-key`
is a random 256-bit key, written as 64 lowercase hex characters drawn from
`SecureRandom`. `:recipients` records the recipient set the store was last
encrypted to. Each manifest entry carries a `:vhash`: the first 64 bits of
HMAC-SHA-256 over the value's unambiguous encoding, keyed by the manifest key. Nothing is derived from an age identity. A solo
store and a team store produce the same kind of manifest, and every recipient
of a store computes the same hashes.

A `:vhash` marks change. At 64 bits it can collide, so an unchanged hash is
strong evidence of an unchanged value and not proof. The hash is keyed by the
store key alone, so equal values at different paths in one store have equal
hashes, and a reader of the manifest can see that.

Lifecycle. Creating a store generates its key: `new`, or `set` when no store
exists yet. `edit`, `set`, and `rm` keep the key. `reencrypt` always generates
a new one, so every `:vhash` changes once. The metadata's `:recipients` is a
digest of the recipient set the store was last encrypted to. `edit`, `set`,
and `rm` encrypt to the
recipients file as it reads when they run, so when that set differs from the
recorded one they generate a new key as `reencrypt` does. Removing a recipient
therefore renews the key on the next write of any kind, and a removed
recipient's retained key says nothing about values published after it (A5).
It still tests guesses against every manifest published before, as B2 says of
old ciphertext. One function in `cli.clj` holds this rule.

Validity. A store's plaintext is one EDN map, because the metadata lives in
it. Version 1 metadata is a map with exactly the three fields above: `:version
1`, a manifest key of 64 lowercase hex characters, and a `:recipients` string.
A store whose metadata is missing, malformed, or of another `:version` is an
error on every command that writes the store, and drift on a `verify` that has
an identity. The message says which of those it is and that `reencrypt` writes
a current store, and `reencrypt` repairs each of them without reading the old
metadata. An existing store that is not a map gets a message that says so and
names `new`, the command that replaces it. There is no manifest without value
hashes. A manifest is valid only if it is a map with `:version
3`, the project's `:app`, a `:ciphertext-sha`, and a `:keys` map in which every
entry has a `:type` and a `:vhash`. Anything else is a manifest problem: drift,
exit 1, with or without an identity. Keyless verification checks that
structure and the ciphertext digest. Verification with an identity also
compares the decrypted store's entries. Every other `:version` is unsupported
and the report says to run `reencrypt`.

Ownership. The reserved key is library metadata and never user data.
`load-secrets`, the reader literals, and `get-secret` on a loaded store never
return it. `edit` shows the plaintext without it and puts it back on save, and
refuses a plaintext in which the user typed it. `set` and `rm` refuse a path
at or under it. `new` drops the metadata line its template holds and generates
a fresh key, so two stores created from one template never share a key. The
manifest lists no entry for it.

Tradeoffs accepted:

- Copying an encrypted store file copies its key. Two copies then publish
  comparable hashes until one of them is re-encrypted.
- Everyone who can decrypt a store holds its manifest key, and can test guesses
  against every manifest published while that key was in use.
- A recipient change makes every `:vhash` change in one commit, so that commit's
  manifest diff shows which paths exist and not which values changed.
- The library writes its metadata as the first line of the store's map, which
  must be the first form in the plaintext after whitespace and comments, and
  takes only that line back out. The reserved key anywhere else was put there
  by hand. Such a store still loads and verifies, but `edit`, `reencrypt`, and
  `new` from such a template refuse the key as they refuse one typed in the
  editor.
- Solo mode records the fixed word `identity` as its recipient set, because the
  identity that decrypts a solo store is the one it is encrypted to. Moving a
  store between solo and team mode renews the key.

## Other chosen contracts

Initializer. It creates the files a new setup needs and never modifies a file
that exists. For an existing `bb.edn` or `deps.edn` it prints the entries to
add. It previews by default and writes only with `--apply`. Because it does not
edit or replace anything, it carries no merge logic, no diff preview, and no
proof about the project directory's ancestry. Each file is created
exclusively, so a file that appears after the plan was made stops the run
instead of being replaced. There is one layout: a project that wants another
describes it in its own config.

Aero. `com.kirahowe.secrets.aero/read-config` is the one entry point. A read
decrypts the store at most once and keeps nothing afterwards. There is no
process-wide registration and no cache to reset, so two reads never share a
decrypted store and a second read sees an edited one. The reader literals
outside Aero keep their first load for the life of the readers map the caller
built, which is a value the application owns.

General-purpose commands. The CLI manages one configured store per
environment. It has no commands that encrypt or decrypt an arbitrary file:
that is what `age` does, and those commands needed their own bounds, streaming,
and plaintext publication. `decrypt-bytes` is the one decryption primitive,
and plaintext reaches disk only in the private temporary file a command owns.

Bounds. Each size and depth bound is a constant in the namespace that enforces
it: 16 MiB of ciphertext, 8 MiB of plaintext, EDN depth 100, 256 KiB of
recipients file, 1 MiB of manifest. They exist to stop an accidental input
(A2), nobody needs to tune that, and so there is no `:limits` configuration.
The CLI refuses to write a plaintext that decryption would refuse to read.

File permissions. The ciphertext, manifest, and recipients file are committed
and shipped, so they get the permissions any new file gets. Only identities
and temporary plaintext are private (A4).

Configuration. A key the config or an environment does not define is an error
that names the key and not its value, so a misspelled key cannot silently
configure nothing.

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
