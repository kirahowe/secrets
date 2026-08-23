# Examples

Choose the smallest example that matches your application shape. Each README
has runnable commands and keeps demo identities/plaintext out of git.

- [quickstart-bb](quickstart-bb/README.md) — Minimal Babashka consumer using
  native `clojure.edn` reader tags. Start with `bb bootstrap`, then `bb run`.
- [integrant-service](integrant-service/README.md) — JVM Clojure HTTP service
  with secrets as an Integrant component. Start with `./scripts/bootstrap-demo.sh`.
- [aero-profiles](aero-profiles/README.md) — Profile-aware EDN configuration
  with optional Aero integration. Start with `bb bootstrap`, then `bb run`.
- [team-ci](team-ci/README.md) — Multiple age recipients and keyless CI
  manifest verification. Start with `bb verify`.

These examples use checkout-specific local coordinates such as
`{:local/root "../.."}` so they run from this repository. In a downstream
application, replace that entry with the released `com.kirahowe/secrets`
coordinate from your dependency management setup. From this checkout, the
Babashka examples also need Java on `PATH` because their `bb.edn` files use
normal dependency entries that Babashka `1.13.219` resolves through Java-backed
deps tooling.
