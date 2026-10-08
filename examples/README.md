# Examples

Choose the smallest example that matches your application shape. Each README
has runnable commands and keeps demo identities and plaintext out of git.

- [quickstart-bb](quickstart-bb/README.md): a minimal Babashka consumer that
  reads its config with `clojure.edn` and the secret reader tags. Start with
  `bb bootstrap`, then `bb run`.
- [integrant-service](integrant-service/README.md): a JVM Clojure HTTP service
  with secrets as an Integrant component. Start with
  `./scripts/bootstrap-demo.sh`.
- [aero-profiles](aero-profiles/README.md): profile-aware EDN configuration
  with the optional Aero integration. Start with `bb bootstrap`, then `bb run`.
- [team-ci](team-ci/README.md): several age recipients and a CI job that
  verifies the manifest without a key. Start with `bb verify`.

The examples depend on this checkout through `{:local/root "../.."}` so they
run from the repository. In your own application, use a git or Maven
coordinate instead, as the [main README](../README.md#install) describes. The
Babashka examples need Java on the `PATH`, because Babashka resolves `:deps`
entries through Java.
