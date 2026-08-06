# Introduction to com.kirahowe/secrets

`com.kirahowe/secrets` keeps an application's critical configuration in a single
**version-controlled, age-encrypted EDN file** instead of a pile of environment
variables. One private key (the age identity) decrypts it; everything else —
structure, defaults, even the encrypted ciphertext — lives in git.

## Why

Environment variables for secrets are easy to start with and painful to live
with:

- They sprawl. Every new integration adds another `FLY_SECRET`, and nobody can
  tell from the repo what the app actually needs.
- They are untyped strings. A comma-separated allowlist becomes string-splitting
  code; there are no sets, vectors, or nested maps.
- They are not version-controlled. There is no history, no review, no single
  source of truth — just mutable state in a deploy platform.

Encrypting a plain EDN map fixes all three. The map is real data (sets, nested
maps, numbers), the *encrypted* form is committed and diffable, and the only
out-of-band secret is one age key.

## The model

```
secrets.edn  (plaintext, never committed)
     │  age -e -i key.txt          ← encrypt to your own identity
     ▼
secrets.edn.age  (ciphertext, committed to git)
     │  age -d -i key.txt          ← decrypt at runtime
     ▼
{:database/url "…" :auth/admins #{…}}   (a Clojure map)
```

- **Local dev:** the key lives at `~/.config/<app>/key.txt`.
- **Production:** the same key is injected as one secret — `SECRETS_AGE_IDENTITY`, the
  raw key file contents (or `SECRETS_AGE_IDENTITY_B64`, its base64, for secret stores
  that mangle multi-line values) — which the library materializes to an
  owner-only temp keyfile at startup.

## Beyond the basics

- **Teams.** Point an environment at a committed `recipients.txt` and it
  encrypts to everyone's public key (`age -R`), so each person decrypts with
  their own key — no shared private key.
- **A committed manifest.** Every save writes a value-free `secrets.edn.manifest`
  beside the ciphertext, so `git diff` shows which keys changed. `bb secrets
  verify` checks it still matches (a good CI gate — it can even confirm the
  manifest is fresh without holding any private key).

See the [README](../README.md) for the full API, these workflows, and the
trade-offs of managing secrets this way.
