# Aero profiles consumer starter

This is a small Babashka consumer for `com.kirahowe/secrets` with the optional
Aero integration. It uses a local dependency (`../..`) so it can be tried from
this checkout; replace that entry with a released coordinate in a real app.

The config demonstrates three useful behaviours:

- `:api-key` selects a different required key for `:default` and `:evals`.
- `#secret/opt` makes an absent optional integration resolve to `nil`.
- Each read decrypts the store once, however many secret tags the config has,
  and keeps nothing afterwards.

All setup data is disposable fake data. From this checkout you need `bb`,
`age`, and `java` on `PATH`: this example's `bb.edn` uses both Maven
(`aero/aero`) and `:local/root` dependencies, and Babashka
resolves both through Java. From this directory:

```sh
bb bootstrap
export SECRETS_AGE_IDENTITY_FILE=tmp/key.txt
bb run                  # default profile
bb run evals            # evals profile
```

Bootstrap writes only `tmp/key.txt`, encrypted `tmp/secrets.edn.age`, and a
temporary plaintext that it removes. `tmp/` is gitignored. The app prints only
profile and configured/presence status, never secret values.

The application code names no files. The secrets options, the ciphertext path
and `:app "aero-profiles"`, are passed to `run!` from `bb.edn`, the project's
own configuration. `run!` hands them to
`com.kirahowe.secrets.aero/read-config` under `:secrets`, next to Aero's own
`:profile`. They cannot sit inside `config.edn`, because Aero needs them
before it can read that file. With no explicit identity path, the key is found
through the identity environment variables first. Outside the demo it then
comes from the macOS Keychain item for `aero-profiles`, or from a
`:key-command` that prints it from a password manager. There is no default key
file. The `export` above points the demo at the disposable key instead.

`bb bootstrap` is safe to rerun: it removes and recreates only those exact
disposable files. `bb clean` removes them explicitly. The bootstrap encrypts
with `age` directly, so the demo store has no manifest and no store metadata.
`bb secrets edit`, `set`, and `rm` refuse such a store until `bb secrets
reencrypt` has run once. In a real application, create the store with `bb
secrets` and commit the ciphertext and the manifest it writes. This starter
keeps its ciphertext under ignored `tmp/`.

For a REPL started with the same variable exported, load the namespace and call
`(aero-profiles.core/run! {:file "tmp/secrets.edn.age" :app "aero-profiles"} "evals")`.
After editing the encrypted store, call it again: every read decrypts the
current file.
