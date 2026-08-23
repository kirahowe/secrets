# Examples

Choose the smallest example that matches your application shape. Each README
has runnable commands and keeps demo identities/plaintext out of git.

| Example | Choose it for | Start here |
| --- | --- | --- |
| [quickstart-bb](quickstart-bb/README.md) | A minimal Babashka consumer using native `clojure.edn` reader tags | `bb bootstrap`, then `bb run` |
| [integrant-service](integrant-service/README.md) | A JVM Clojure HTTP service with secrets as an Integrant component | `./scripts/bootstrap-demo.sh` |
| [aero-profiles](aero-profiles/README.md) | Profile-aware EDN configuration with optional Aero integration | `bb bootstrap`, then `bb run` |
| [team-ci](team-ci/README.md) | Multiple age recipients and keyless CI manifest verification | `bb verify` |

These examples use checkout-specific local coordinates such as
`{:local/root "../.."}` so they run from this repository. In a downstream
application, replace that entry with the released `com.kirahowe/secrets`
coordinate from your dependency management setup.
