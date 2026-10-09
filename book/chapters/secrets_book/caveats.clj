;; # Caveats and threat model

^:kindly/hide-code
(ns secrets-book.caveats)

;; Encryption solves one particular problem: it keeps the values in the
;; repository from being readable without a private identity. It doesn't make
;; the rest of the system secure by itself, so this chapter explains what the
;; library does and does not protect. The repository's
;; [threat model](https://github.com/kirahowe/secrets/blob/main/doc/threat-model.md)
;; is the full statement, and the rule the design is held to.

;; ## What the encryption actually protects

;; As long as the private identities are kept somewhere else, access to the
;; repository alone does not reveal the encrypted values. The manifest still
;; reveals key names, types, and collection sizes, and it reveals which values
;; in a store are equal and when a value changes.

;; This doesn't protect a running process. Once decrypted, the map sits in
;; memory like any other config, and code running in your app can read it as
;; easily as it can read environment variables. A client-side secrets scheme
;; can't avoid that.

;; You also still have to trust the production deployment platform. The
;; identity arrives through a mounted file or environment variable, and anyone
;; who can read both that identity and the ciphertext can decrypt the whole
;; file.

;; ## A leaked key exposes history

;; Git history keeps old ciphertexts, and age does not provide forward secrecy
;; across versions of a file. If a key leaks today, it can decrypt every
;; retained version that was encrypted to its recipient.

;; Replacing the key is not enough after a leak. You also have to rotate the
;; secret values at their upstream services, because anyone with the old key
;; can still read the old ciphertexts.

;; Similarly, removing a teammate's line from the recipients file and running
;; `reencrypt` only stops access to new ciphertexts. Until `reencrypt` runs,
;; removing the line stops nothing. They can still read everything committed
;; while they were a recipient. If their past access is a concern, rotate the
;; secret values as well.

;; Rotating those values is a manual process. This library can't rotate a
;; database password or expire an API key for you. If you need scheduled
;; rotation and proof that it happened, use a server-based secrets manager.

;; ## Rotation goes through a deploy

;; Changing a secret normally requires a commit, a CI run, and a deploy. You
;; get a git history in return, but during an incident this may be slower than
;; changing a value directly in the deployment platform. Make sure you have a
;; fast deployment path and know how to revoke credentials at their source.

;; ## Access is whole-file

;; One matching identity decrypts an environment's entire file. There is no
;; per-secret access policy, and in team mode every recipient can read
;; everything. If people need different levels of access, use separate
;; environments, files, and keys.

;; ## Plaintext touches disk during edits

;; `bb secrets edit` decrypts to an owner-only (0600) temporary file, opens
;; your editor, re-encrypts the result, and then deletes the temporary file.
;; `new`, `set`, `rm`, and `reencrypt` use a temporary file the same way. The
;; file is plaintext for as long as the editor is open. Your editor may write
;; its own swap or backup files, which the library cannot control. The delete
;; is an ordinary delete and not secure erasure: the blocks can remain on the
;; disk. If the delete fails, the command reports the path so you can remove
;; the file yourself.

;; An identity injected as contents, through `SECRETS_AGE_IDENTITY` or
;; `SECRETS_AGE_IDENTITY_B64`, is written to a temporary file in the same way
;; for each operation. A process that crashes during the operation can leave
;; it behind.

;; ## The manifest discloses structure and change

;; The committed manifest lists key names, types, and collection sizes. For
;; example, someone reading it can see that you have a `:stripe/api-key` and
;; that `:auth/admins` has three members, although they cannot see the values.
;; Key paths through nested maps are public at every depth, so never use a
;; secret value as a map key.

;; The manifest also carries a keyed `:vhash` for each entry, in solo and team
;; stores alike. The hash does not reveal the value, but it does reveal
;; equality and change. Equal values at different paths in one store have
;; equal hashes. A value that returns to an earlier one repeats its earlier
;; hash, for as long as the store keeps the same manifest key. The size of the
;; ciphertext and the history of both files are visible too.

;; The hash key lives inside the encrypted store, so everyone who can decrypt
;; the store has it and can test guesses of a value against the manifests
;; published while that key was in use. A removed recipient keeps the key they
;; had. The library replaces the key on the next write after the recipients
;; change, so values published later can't be tested with the old key. The
;; manifests from before stay testable.

;; If even a key name is sensitive, set `:manifest false` for that environment.
;; Its changes will then not be reviewable.

;; ## No signatures: the repository is the boundary

;; age encrypts to recipients, but it does not sign. Here is what that means
;; for confidentiality, integrity, sender authenticity, and repository trust.

;; age provides confidentiality: only a private identity matching one of the
;; file's recipients can decrypt it. It also provides ciphertext integrity. A
;; modified, truncated, or spliced ciphertext fails to decrypt instead of
;; producing altered plaintext. This protects the payload from corruption and
;; splicing, but it doesn't tell you who created it.

;; age does not provide sender authenticity. A public recipient is meant to be
;; shared and committed: it permits encryption, but it is not a signing key.
;; Anyone who has one can create a file that decrypts cleanly. Successful
;; decryption therefore tells you that the file is readable, not who wrote it.
;; Nothing stops an older valid file from being put back in place of a newer
;; one, either.

;; This project relies on the reviewed repository and the deployment channel
;; for both. It doesn't provision a second signing key or store a signature
;; beside every ciphertext. In practice, this means using reviewed and
;; protected refs, transferring an immutable artifact from that commit to the
;; running process, and limiting write access to whatever serves the
;; ciphertext.

;; `verify` reports drift between a manifest and its ciphertext. It doesn't
;; identify the author of either file. A run with an identity compares the
;; decrypted store with the manifest, so it catches a manifest that no longer
;; matches the ciphertext. Anyone who can replace both files can make them
;; agree, and anyone who can decrypt the store holds the key the hashes are
;; made with. The
;; [threat model](https://github.com/kirahowe/secrets/blob/main/doc/threat-model.md)
;; describes this in full.

;; ## Writes are two renames

;; A write replaces the ciphertext and then the manifest, each with an atomic
;; rename. A single file is never left half written, but the pair is not one
;; transaction and nothing is rolled back. An interruption between the two
;; leaves a new ciphertext beside an old manifest. `verify` reports that, and
;; `bb secrets reencrypt` regenerates the manifest. It can also leave a
;; staging file named `.<target>.<uuid>.tmp` beside the target, which is safe
;; to delete. The library makes no claim about what survives a power loss.

;; ## Operational dependencies

;; Decryption shells out to the `age` binary, so every environment that
;; decrypts secrets, from a laptop to the production image, needs it on
;; `PATH`. Keyless `verify` is the exception: it only compares hashes, so it
;; needs neither an identity nor the binary.

;; Runtime loading only reads local sources. It accepts local files and
;; classpath resources, including one inside a jar, and it never fetches a
;; ciphertext over HTTP. Fixed bounds apply to the ciphertext a load reads,
;; the plaintext the CLI writes, EDN nesting, the recipients file, and the
;; manifest. They are far above the size of a real secrets map and are not
;; configurable.

;; The library assumes POSIX file permissions. Private temporary files are
;; created owner-only, and where the filesystem can't do that the operation
;; fails instead of writing with default permissions. That affects every CLI
;; command that writes a store, key generation, and identities injected as
;; contents. Loading with an identity file you named needs no private file
;; unless the ciphertext is inside a jar. Treat Windows as unsupported.

;; If you find a vulnerability in the library itself, follow the project's
;; [security policy](https://github.com/kirahowe/secrets/blob/main/SECURITY.md)
;; and use the private reporting route there. Do not put real credentials,
;; unpatched exploit details, or other sensitive material in a public issue.

;; ## When to use something else

;; This library is a good fit when a small team manages application secrets
;; that change infrequently and wants to track their encrypted form with the
;; code.

;; Use [SOPS](https://github.com/getsops/sops) when you want field-level
;; encrypted diffs or KMS integration.

;; Use Vault or a cloud secrets manager when you need dynamic credentials,
;; per-secret access policies, automatic rotation, or a central audit log.
;; Those features require a service, which a file-encryption wrapper is not.
