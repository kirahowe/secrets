;; # Caveats and threat model

^:kindly/hide-code
(ns secrets-book.caveats)

;; This chapter describes what the library protects and what remains the
;; operator's responsibility.

;; ## What the encryption actually protects

;; If the private identities remain separate, repository access alone does not
;; reveal the encrypted values. The manifest may still reveal key names, types,
;; and collection sizes.

;; It does not protect a running process. The decrypted map sits in memory
;; like any other config, and code execution in your app reads it as
;; easily as it reads env vars. No client-side secrets scheme changes this.

;; It also does not reduce production's trust in the deployment platform. The
;; identity arrives through a mounted file or environment variable, so anyone
;; who can read that identity and the ciphertext can decrypt the complete file.

;; ## A leaked key exposes history

;; Git history retains old ciphertexts, and age does not provide forward
;; secrecy across versions of a file. A key that leaks today decrypts every
;; retained version that was encrypted to its recipient. Three consequences
;; follow.

;; Rotating the key is not enough after a leak. You must rotate the secret
;; values, at the upstream services, because the old ciphertexts remain
;; readable to whoever holds the old key.

;; Removing a teammate's recipient and re-encrypting stops access to new
;; ciphertexts only. Everything committed while they were a recipient stays
;; readable to them. Rotate the secret values when past access is a concern.

;; Value rotation is manual. Nothing in this library rotates a database
;; password or expires an API key. If your compliance regime requires
;; scheduled rotation with proof, you want a secrets manager with a server,
;; not this.

;; ## Rotation goes through a deploy

;; Changing a secret normally means commit, CI, and deploy. This provides a git
;; history but may be slower than changing a value directly in a deployment
;; platform during an incident. Maintain a fast deployment path and know how
;; to revoke credentials at their source.

;; ## Access is whole-file

;; One matching identity opens an environment's entire file. There is no
;; per-secret policy, and in team mode every recipient reads everything. Use
;; separate environments, files, and keys when users need different access.

;; ## Plaintext touches disk during edits

;; `bb secrets edit` decrypts to an owner-only (0600) temp file, opens your
;; editor, re-encrypts, and then deletes the temp file with best-effort
;; secure deletion. Your editor may write its own swap or undo files, which
;; the library cannot control. On copy-on-write filesystems like APFS, secure
;; deletion is mostly symbolic,
;; since old blocks may persist beneath the filesystem's view. The temp file
;; also remains plaintext for as long as the editor is open.

;; ## The manifest leaks structure

;; The committed manifest lists key names, types, and collection sizes. A
;; reader learns you hold a `:stripe/api-key` and that `:auth/admins` has
;; three members, but no values. If even a name is sensitive, set
;; `:manifest false` for that environment; its ciphertext diffs will then be
;; opaque.

;; Value-change hashes (`:vhash`) exist only in single-key mode, because they
;; are keyed by the shared private key and teams do not have one. Team
;; manifests still show adds, removals, and type changes; a rotated string
;; without a shape change does not show.

;; ## No signatures: the repository is the boundary

;; age encrypts to recipients; it does not sign. Four properties are easy to
;; run together, so this chapter keeps them apart.

;; Confidentiality is age's. Only a private identity matching one of the file's
;; recipients decrypts it. Ciphertext integrity is age's too: a modified,
;; truncated, or spliced ciphertext fails to decrypt rather than yielding
;; altered plaintext. That is integrity of the payload against corruption and
;; splicing, and it establishes that the bytes came from *someone* holding a
;; recipient — not which someone.

;; Sender authenticity is nobody's. A public recipient is meant to be shared
;; and committed; it permits encryption and is not a signing key. Anyone
;; holding one can author a file that decrypts cleanly, so a successful
;; decryption proves readability, never authorship.

;; Repository trust is yours. This project deliberately accepts the reviewed
;; repository and the deployment channel as the sender-authenticity boundary,
;; rather than provisioning a second, separately trusted signing key and
;; carrying a signature beside every ciphertext. Accepting a boundary means
;; holding it: reviewed and protected refs, immutable artifact transfer from
;; that commit to the running process, and least-privilege write access to
;; whatever serves the ciphertext.

;; `verify` reports drift between a manifest and its ciphertext; it does not
;; authenticate who wrote either. In single-key mode the `:vhash`es make a
;; forged value fail a keyed run, because whoever holds only a public recipient
;; cannot key the HMAC. In team mode there are no `:vhash`es, so a forgery that
;; keeps the same shape passes verification and is visible only as a change to
;; committed files. The README's authenticity contract and threat model states
;; this in full, including who may hold a public recipient and who may replace
;; a deployed artifact.

;; ## Operational dependencies

;; Decryption shells out to the `age` binary, so every decrypting
;; environment, from laptops to the production image, needs it on the PATH.
;; The exception is keyless `verify`, which compares hashes and needs neither
;; an identity nor the binary.

;; POSIX file permissions are assumed. Writing decrypted plaintext to a file
;; now *requires* them: `decrypt-to-file!` stages plaintext in an owner-only
;; sibling file and fails closed if that mode cannot be established and
;; verified, rather than falling back to whatever the platform defaults to.
;; In-memory decryption (`decrypt`, `decrypt-bytes`, `load-secrets`) needs no
;; permissions and still works. On Windows the owner-only guarantees on temp
;; files degrade to best effort and the secure-delete path does not exist. The
;; library targets POSIX systems; treat Windows as unsupported for anything
;; beyond reading — which this makes literal.

;; ## When to use something else

;; Use this library when a small team manages application secrets that change
;; infrequently and wants their encrypted form tracked with the code.

;; Use [SOPS](https://github.com/getsops/sops) when you want field-level
;; encrypted diffs or KMS integration.

;; Use Vault or a cloud secrets manager when you need dynamic credentials,
;; per-secret access policy, automatic rotation, or a central audit log. Those
;; requirements need a service rather than a file-encryption wrapper.
