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
- **Production:** the same key is injected as one secret, `AGE_IDENTITY`, which
  the library materializes to a temp keyfile at startup.

See the [README](../README.md) for the full API and an end-to-end integration.
