;; # Caveats and threat model

^:kindly/hide-code
(ns secrets-book.caveats)

;; Encryption solves one particular problem: it keeps the values in the
;; repository from being readable without a private identity. It doesn't make
;; the rest of the system secure by itself, so this chapter explains what the
;; library does and does not protect.

;; ## What the encryption actually protects

;; As long as the private identities are kept somewhere else, access to the
;; repository alone does not reveal the encrypted values. The manifest still
;; reveals key names, types, and collection sizes, and in single-key mode it
;; also reveals which values are equal and when a value changes.

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

;; Rotating the key is not enough after a leak. You also have to rotate the
;; secret values at their upstream services, because anyone with the old key
;; can still read the old ciphertexts.

;; Similarly, removing a teammate's recipient and re-encrypting only stops
;; access to new ciphertexts. They can still read everything committed while
;; they were a recipient. If their past access is a concern, rotate the secret
;; values as well.

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
;; your editor, re-encrypts the result, and then deletes the temporary file on
;; a best-effort basis. This is not secure erasure. Your editor may write its
;; own swap or undo files, which the library cannot control. On a copy-on-write
;; filesystem such as APFS, overwriting before deletion is mostly symbolic
;; because old blocks may remain below the filesystem's view. The temporary file also remains as plaintext
;; for as long as the editor is open.

;; ## The manifest leaks structure

;; The committed manifest lists key names, types, and collection sizes. For
;; example, someone reading it can see that you have a `:stripe/api-key` and
;; that `:auth/admins` has three members, although they cannot see the values.
;; Key paths through nested maps are public at every depth, so never use a secret value as
;; a map key.

;; In single-key mode the manifest also carries a keyed `:vhash` for each leaf.
;; The hash does not reveal the value, but it does reveal equality and change.
;; Equal values at different paths, or in different environments that share a
;; key, have equal hashes, and a value that returns to an earlier one is visible
;; in the file's history. Team manifests carry no hashes.

;; If even a key name is sensitive, set `:manifest false` for that environment.
;; Its ciphertext diffs will then be opaque.

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

;; This project relies on the reviewed repository and the deployment channel
;; for sender authenticity. It doesn't provision a second signing key or
;; store a signature beside every ciphertext. In practice, this means using
;; reviewed and protected refs, transferring an immutable artifact from that
;; commit to the running process, and limiting write access to whatever serves
;; the ciphertext.

;; `verify` reports drift between a manifest and its ciphertext, but it doesn't
;; authenticate the author of either file. A keyed run compares the decrypted
;; store with the manifest, so it catches a manifest that no longer matches the
;; ciphertext. Anyone who can replace both files can make them agree. Team
;; manifests carry no `:vhash`es, so a keyed run there compares structure only.
;; The
;; [threat model](https://github.com/kirahowe/secrets/blob/main/doc/threat-model.md)
;; describes this in full, including why sender authenticity and replay
;; prevention are left to the deployment channel.

;; ## Operational dependencies

;; Decryption shells out to the `age` binary, so every environment that
;; decrypts secrets, from a laptop to the production image, needs it on
;; `PATH`. Keyless `verify` is the exception: it only compares hashes, so it
;; needs neither an identity nor the binary.

;; Runtime loading only reads local sources. It accepts files, local `file:`
;; locators, and `jar:file:` classpath resources, and it never fetches a
;; ciphertext over HTTP. The library applies limits while reading ciphertext,
;; plaintext, nested EDN, recipient lists, and manifests. The defaults are
;; deliberately generous for a secrets map, but an unusually large store may
;; need explicit `:limits`.

;; The library assumes POSIX file permissions. Writing decrypted plaintext to
;; a file *requires* them: `decrypt-to-file!` stages the plaintext in an
;; owner-only sibling file and fails if it cannot establish and verify that
;; mode. It will not fall back to the platform's default permissions. In-memory
;; decryption with a caller-owned identity file does not need private temporary
;; file creation. Raw or base64 injected identities do need it, so those
;; operations fail closed when owner-only permissions cannot be established.
;; Secure deletion is not available on every filesystem. The library targets
;; POSIX systems, so treat Windows as unsupported for anything beyond reading.

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
;; Those features require a service rather than a file-encryption wrapper.
