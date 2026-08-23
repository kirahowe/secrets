# Aero profiles consumer starter

This is a small Babashka consumer for `com.kirahowe/secrets` with the optional
Aero integration. It uses a local dependency (`../..`) so it can be tried from
this checkout; replace that entry with a released coordinate in a real app.

The config demonstrates three useful behaviours:

- `:api-key` selects a different required key for `:default` and `:evals`.
- `#secret/opt` makes an absent optional integration resolve to `nil`.
- `reset-cache!` is called by the REPL-friendly `run!` helper when requested.

All setup data is disposable fake data. From this directory:

```sh
bb bootstrap
bb run                  # default profile
bb run evals            # evals profile
bb run default reset    # demonstrate a cache reset before reading
```

Bootstrap writes only `tmp/key.txt`, encrypted `tmp/secrets.edn.age`, and a
temporary plaintext that it removes. `tmp/` is gitignored. The app prints only
profile and configured/presence status, never secret values.

`bb bootstrap` is safe to rerun: it removes and recreates only those exact
disposable files. `bb clean` removes them explicitly. In a real application,
commit the CLI-generated encrypted ciphertext and its value-free manifest;
this starter intentionally keeps its runtime ciphertext under ignored `tmp/`.

For a REPL, load the namespace and call `(aero-profiles.core/run! "evals")`;
call `(aero-profiles.core/reset-cache!)` after editing the encrypted store.
