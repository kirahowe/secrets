;; # Caveats, trade-offs, and the honest threat model

^{:kindly/hide-code true}
(ns secrets-book.caveats)

;; Every secrets tool is a bet about which risks you accept to remove others.
;; This chapter states this library's bet plainly, because a security tool
;; that oversells itself is worse than no tool.

;; ## What the encryption actually protects

;; Encrypting secrets at rest, in git, protects you from repo access being
;; secret access. A cloned laptop, a leaked repo, a contractor with read
;; access, a public fork by mistake: none of these expose values. That is
;; the whole promise, and it is worth having.

;; It does not protect a running process. The decrypted map sits in memory
;; like any other config, and code execution in your app reads it exactly as
;; easily as it reads env vars. No client-side secrets scheme changes this.

;; It also does not reduce production's trust in the deploy platform. The key
;; arrives as `AGE_IDENTITY`, so anyone who can read your platform's secrets
;; still gets everything. What you gain in production is narrower: one secret
;; to manage instead of forty, and a reviewable history of the other
;; thirty-nine.

;; ## A leaked key exposes history

;; This is the sharpest edge, so it gets its own section. Git history is
;; immutable, and age has no forward secrecy within a file's history. A key
;; that leaks today decrypts every version of every file it was ever a
;; recipient of, all the way back. Three consequences follow.

;; Rotating the key is not enough after a leak. You must rotate the secret
;; values, at the upstream services, because the old ciphertexts remain
;; readable to whoever holds the old key.

;; Removing a teammate's recipient line stops future access only. Everything
;; committed while they were a recipient stays readable to them. Offboarding
;; someone you trust is a config change; offboarding someone you do not is a
;; value rotation.

;; And value rotation is manual. Nothing in this library rotates a database
;; password or expires an API key. If your compliance regime requires
;; scheduled rotation with proof, you want a secrets manager with a server,
;; not this.

;; ## Rotation goes through a deploy

;; Changing a secret means commit, CI, deploy. On a calm Tuesday that is a
;; feature: the change is reviewed, attributed, and bisectable. During an
;; incident at 2 a.m. it is slower than flipping an env var in a dashboard.
;; Decide in advance whether that trade sits well with your on-call story,
;; and remember the mitigations are ordinary ones: a fast deploy pipeline,
;; and upstream credentials you can revoke at the provider while the deploy
;; runs.

;; ## Access is whole-file

;; One key opens an environment's entire file. There is no per-secret policy,
;; and in team mode every recipient reads everything. If the intern should
;; see the dev Stripe key but not the prod database password, that boundary
;; must be an environment boundary, with separate files and separate keys.
;; Within one file there are no smaller compartments.

;; ## Plaintext touches disk during edits

;; `bb secrets edit` decrypts to an owner-only (0600) temp file, opens your
;; editor, re-encrypts, and then deletes the temp file with best-effort
;; secure deletion. Honesty requires three admissions. Your editor may write
;; its own swap or undo files, which the library cannot control. On
;; copy-on-write filesystems like APFS, secure deletion is mostly symbolic,
;; since old blocks persist beneath the filesystem's view. And the temp file
;; exists in plaintext for as long as your editor is open. The window is
;; small and local, and it is a window.

;; ## The manifest leaks structure

;; The committed manifest lists key names, types, and collection sizes. A
;; reader learns you hold a `:stripe/api-key` and that `:auth/admins` has
;; three members, but no values. Usually the reviewability is worth far more
;; than the leak. When even a name is sensitive, set `:manifest false` for
;; that environment and accept opaque diffs there.

;; Value-change hashes (`:vhash`) exist only in single-key mode, because they
;; are keyed by the shared private key and teams do not have one. Team
;; manifests still show adds, removals, and type changes; a rotated string
;; without a shape change does not show.

;; ## No signatures

;; age encrypts to recipients; it does not sign. Anyone holding only the
;; public keys can produce a file that decrypts cleanly, so the integrity of
;; your secrets rests on git: review, branch protection, and commit access.
;; `verify` detects drift between manifest and ciphertext; it does not
;; authenticate who wrote either. In practice the repo is already your trust
;; boundary for code, and secrets inherit it. Know that this is the boundary.

;; ## Operational dependencies

;; Decryption shells out to the `age` binary, so every decrypting
;; environment, from laptops to the production image, needs it on the PATH.
;; The single exception is keyless `verify`, which compares hashes and runs
;; happily with neither key nor binary.

;; POSIX file permissions are assumed. On Windows, the owner-only guarantees
;; on temp files degrade to best effort, and the secure-delete path does not
;; exist. The library targets POSIX systems; treat Windows as unsupported for
;; anything beyond reading.

;; ## When to use something else

;; Reasonable rules of thumb, in one place:

;; Use this library when a small team ships a handful of apps, secrets change
;; on the order of weeks, and today's alternative is env vars in a dashboard.

;; Use [SOPS](https://github.com/getsops/sops) when reviewers must see the
;; actual changed values in diffs, or you want per-value encryption with KMS
;; integration and are willing to run a heavier tool for it.

;; Use Vault or a cloud secrets manager when you need dynamic credentials,
;; per-secret access policy, automatic rotation, or a real audit log. At that
;; point you have a secrets infrastructure problem, and a library that
;; wraps a file encryption tool is the wrong shape, this one included.
