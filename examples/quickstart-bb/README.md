# Babashka quickstart

This small consumer project uses `com.kirahowe/secrets` via `{:local/root "../.."}`.
It encrypts a development EDN map with `age`, then reads `config.edn` with
`clojure.edn` and `secrets/merge-readers`. The sample program prints only
whether each value is configured. It never prints the endpoint or the API key.

You need `bb` (Babashka), `age`, and `java` on the `PATH`. Java is there
because Babashka resolves the `:local/root` dependency through it. From this
directory:

```sh
bb bootstrap   # creates .local/age-key.txt and a store of fake values
bb run         # reads config.edn without revealing values
bb verify      # checks the ciphertext against its manifest
bb cleanup     # removes the generated .local/ files
```

`secrets.edn.example` is a plaintext template with placeholder values. The
identity, ciphertext, and manifest are generated under `.local/`, which is
gitignored for this disposable demo. That is why this example's config sets
`:key-file`, `:template`, and `:manifest` explicitly. In a real application,
commit the ciphertext and the manifest, and keep the identity and any
plaintext out of git.

`bb bootstrap` passes each value to `bb secrets set` on stdin, so no value
becomes a command argument or lands in shell history.
