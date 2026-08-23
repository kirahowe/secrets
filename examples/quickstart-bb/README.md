# Babashka quickstart

This small consumer project uses `com.kirahowe/secrets` via `{:local/root "../.."}`.
It encrypts a development EDN map with `age`, then reads `config.edn` using
native `clojure.edn` and `secrets/merge-readers`. The sample program prints only
safe configured/presence status; it never prints the endpoint or API key values.

Requirements: `bb` (Babashka) and `age` on `PATH`. From this directory:

```sh
bb bootstrap   # creates .local/age-key.txt and fake encrypted values
bb run         # reads config.edn without revealing values
bb verify      # checks ciphertext against its manifest
bb cleanup     # removes generated .local/ files
```

`secrets.edn.example` is a safe plaintext template. The identity, ciphertext,
and manifest are generated under `.local/`, which is gitignored for this
disposable demo; the CLI is explicitly configured to use the tracked template
at `secrets.edn.example`. In a real downstream app, commit the encrypted
ciphertext and manifest, while keeping the identity and plaintext out of git.
Values are supplied to `bb secrets set` through stdin so they do not become
shell command arguments or shell history.
