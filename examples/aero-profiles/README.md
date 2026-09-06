# Aero profiles consumer starter

This is a small Babashka consumer for `com.kirahowe/secrets` with the optional
Aero integration. It uses a local dependency (`../..`) so it can be tried from
this checkout; replace that entry with a released coordinate in a real app.

The config demonstrates three useful behaviours:

- `:api-key` selects a different required key for `:default` and `:evals`.
- `#secret/opt` makes an absent optional integration resolve to `nil`.
- `reset-cache!` is called by the REPL-friendly `run!` helper when requested.

All setup data is disposable fake data. From this checkout you need `bb`,
`age`, and `java` on `PATH`: this example's `bb.edn` uses both Maven
(`aero/aero`) and `:local/root` dependencies, and Babashka `1.13.219`
resolves both through Java-backed deps tooling. From this directory:

```sh
bb bootstrap
export SECRETS_AGE_IDENTITY_FILE=tmp/key.txt
bb run                  # default profile
bb run evals            # evals profile
bb run default reset    # demonstrate a cache reset before reading
```

Bootstrap writes only `tmp/key.txt`, encrypted `tmp/secrets.edn.age`, and a
temporary plaintext that it removes. `tmp/` is gitignored. The app prints only
profile and configured/presence status, never secret values.

The application code names no files. The secrets options, the ciphertext path
and `:app "aero-profiles"`, are passed to `run!` from `bb.edn`, the project's
own configuration. They cannot sit inside `config.edn`, because Aero needs them
before it can read that file. The key is then found the way the library always
finds it: `SECRETS_AGE_IDENTITY_FILE` and the other injection variables first,
then `~/.config/aero-profiles/key.txt`. The `export` above points the demo at
the disposable key instead of a real one under `~/.config`.

`bb bootstrap` is safe to rerun: it removes and recreates only those exact
disposable files. `bb clean` removes them explicitly. In a real application,
commit the CLI-generated encrypted ciphertext and its value-free manifest;
this starter intentionally keeps its runtime ciphertext under ignored `tmp/`.

For a REPL started with the same variable exported, load the namespace and call
`(aero-profiles.core/run! {:file "tmp/secrets.edn.age" :app "aero-profiles"} "evals")`;
call `(aero-profiles.core/reset-cache!)` after editing the encrypted store.
