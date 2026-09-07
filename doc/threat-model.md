# Threat model

This is the decision rule for what belongs in this library. Every defense in the
code should trace to a named adversary below, or to a named operator mistake. A
defense that traces to neither gets deleted, however careful it is.

It replaces the reasoning previously spread across the README's "Authenticity
contract and threat model" section, `SECURITY.md`, and the resolved issues in
`.issues/`. Those documents described individual defenses well. What they never
did was say which attacks are out of scope, so nothing ever got removed.

## What this protects

Three assets, in order of how much damage their loss does:

1. The private age identity. It decrypts every ciphertext encrypted to it,
   including every version in git history.
2. The plaintext secret values.
3. The correctness of what the application loads. A wrong `:database/url` is a
   breach even though no secret leaked.

## Adversaries in scope

### A1. A reader of the repository who holds no identity

They have the ciphertext, the manifest, `recipients.txt`, the full source, and
all of git history. For a public repository this is everyone.

This is the adversary the library exists to stop, and the only one it stops by
cryptography rather than by convention. They must learn nothing beyond the
manifest's declared shape: key paths, value types, collection sizes.

What this justifies:

- age encryption, and never committing plaintext.
- A manifest that records shape and no values.
- `:vhash` as an HMAC keyed on private key material. An unkeyed hash of a
  six-character password is brute-forceable from the repository alone, so the
  key is what makes the hash safe to commit.
- The injective encoding in `manifest.clj`. If two different values can produce
  one `vhash`, the manifest reports "no change" when a value changed, and the
  review that the manifest exists to enable silently fails.
- Owner-only permissions on any plaintext the CLI writes to disk.

### A2. Operator mistake

Not an adversary, and the source of nearly every real incident this tool will
ever see. It earns first-class standing because it justifies more code than any
attacker does.

The mistakes worth writing code against are the ones that fail *quietly*:

- A CI runner expands a missing or misnamed secret to the empty string, so
  `SECRETS_AGE_IDENTITY` is set but blank. Falling through to the next source
  would use the developer's local key and pass on a laptop while the deployment
  it was meant to configure is broken. Using the value encrypts to nothing and
  exits zero.
- A path argument that starts with `-`, or is blank, reaching `age`. age reads a
  bare `-` as stdin and a blank path as stdin, so the command succeeds and
  produces a ciphertext of nothing.
- A `:secrets-file` that does not end in `.age`, so the derived `.manifest` and
  `.example` names collide with the ciphertext and overwrite it.
- Two environments configured to write one ciphertext or one manifest.
- A crash between writing the ciphertext and writing the manifest, leaving the
  two disagreeing with no plaintext left to rebuild from.
- A URI where a filesystem path was expected, resolving somewhere the operator
  did not intend.
- Trailing junk after the EDN value, silently ignored by a plain reader.

Each of these is worth a check that fails loudly. None is worth a subsystem.

### A3. Whoever reads the logs

Exception messages, stack traces, and CI output travel further than the
repository does, into log aggregators and error trackers with wider read access.

In scope: a secret value must never appear in a message, and neither must the
private key. A parser that echoes the malformed text it rejected can print a
secret, so failures carry a reason and a location rather than the input.

Out of scope: file paths. A path is not a secret. The identity temp file is 0600
and short-lived, and anyone who can read it can read the process heap, which
holds the same key already. Naming a path in a diagnostic costs nothing and is
most of a good error message's value.

### A4. Another local user on a shared machine

If another account can read `~/.config/<app>/key.txt`, or a plaintext temp file
while `bb secrets edit` is open, they have everything.

In scope: create files with owner-only permissions, from the instant they exist
rather than by chmod afterwards. This is cheap, standard, and correct.

Out of scope: proving that no other user could have raced or redirected a write.
That is an unbounded claim about the entire filesystem, and an attacker who can
swap a directory on the way to your project root can also edit the source that
project is about to run.

The line: restrict permissions on files we create. Do not attempt to prove the
filesystem was untampered with.

## Adversaries out of scope

### B1. Anyone who can write the repository, the build, or the deploy channel

age encrypts to recipients and does not sign. Every recipient is public by
design and committed in the clear. So anyone holding a public recipient can
author a ciphertext that decrypts cleanly for every reader, and if they can also
replace the file the application reads, they choose the configuration.

No check this library performs can distinguish their file from a legitimate one,
because there is no authorship signal to check. Adding one means a second key
that is separately provisioned, distributed, rotated, and trusted, which is the
infrastructure "no GPG keyrings, no KMS, no vault" exists to avoid.

**This is the concession most of the current code has not absorbed.** Its
consequence: any input arriving through the ciphertext is exactly as trusted as
the repository. If it is not, the deployment is already compromised in ways the
library cannot see, let alone fix.

So the following buy no security:

- Byte limits on the ciphertext or the plaintext. Someone who can hand you a
  two-gigabyte file can hand you a two-kilobyte file that points your database
  at their host, which is worse and invisible.
- A nesting-depth limit on the decrypted EDN. Deep nesting crashes the process.
  Attacker-chosen configuration does not.
- Rejecting remote source locators as an attack surface. The source comes from
  the operator's own config, so this is a mistake-catcher (A2), not a defense.

Denial of service against a process that is about to load attacker-chosen
configuration is not a threat worth ranking.

### B2. A former recipient, for values they could already read

Anyone who was ever in `recipients.txt` holds a key that decrypts every
ciphertext they had access to, and git history keeps those forever. `reencrypt`
protects values written after their removal and nothing before it.

The answer is rotating the underlying credential at the provider. There is no
code change that helps, and pretending otherwise would be worse than saying so.

### B3. The host that decrypts

The application holds the plaintext map in memory. Root on that box, a heap
dump, an attached debugger, or any compromised dependency in the same process
reads it. A library cannot defend its own address space.

### B4. The `age` binary itself

We shell out to whatever `age` is on `PATH`. If that is hostile, so is
everything downstream of it.

## Properties, and who provides each

| Property | Provided by |
| --- | --- |
| Confidentiality of values against a repository reader | age |
| Integrity of the ciphertext against corruption and splicing | age |
| Reviewability of what changed | the committed manifest |
| Detection of a value change by a party without the key | `:vhash`, single-key mode only |
| Sender authenticity | nobody. Out of scope, see B1 |
| Freshness of the manifest against the ciphertext, without a key | `:ciphertext-sha` |

Team mode has no shared private key, so team manifests carry no `:vhash` and
detect shape changes only. A same-shape value change is invisible to `verify`
there. That is a documented boundary, not a defect.

## Safety is not security

Several checks in this codebase are worth keeping for reasons that have nothing
to do with an attacker. Framing them as security is what made them elaborate.

A safety check answers "will this fail loudly when someone makes a mistake?" It
needs to be correct and small. It does not need to be adversary-proof, it does
not need a content-free failure mode, and it does not need to hold under
concurrent modification by a hostile local process.

Atomic replacement is the clearest case. A crash mid-write leaving a corrupt
ciphertext is a real way to lose secrets, and rename-into-place fixes it in a
few lines. It does not need a two-phase commit with rollback, because the
failure being prevented is a crash, not an adversary.

## How to validate a change

For each defense currently in the code:

1. Name the in-scope adversary it stops (A1, A3, A4). If there is one, keep it.
2. If not, name the operator mistake it catches loudly (A2). If there is one,
   keep the check and shrink it to the smallest thing that catches the mistake.
3. If neither, delete it.
4. Whatever survives: is it implemented once, or four times?

Step 4 is where most of the remaining volume is. Bounded reading exists in four
places, atomic owner-only writing in four, limit resolution in two, EDN failure
rendering in two.

## What this model does not change

The library keeps every user-facing behavior it has today: the same commands,
the same reader literals, the same manifest format and `verify` exit codes, the
same identity resolution order. The plan is to remove machinery, not features.
Where a defense is removed, this document is where the reasoning lives, so the
decision stays reviewable rather than becoming folklore.
