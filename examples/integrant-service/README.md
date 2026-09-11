# Integrant service example

This is a small JVM Clojure service using `com.kirahowe/secrets` as an
Integrant component. The component decrypts `secrets.edn.age` from the active
classpath resource root and returns a map. The only endpoint, `GET /health`,
returns safe derived status (`status`, configured flag, and count); it never
returns or prints secret keys or values.

The `:dev` and `:prod` aliases add separate resource roots. Each contains a
`config.edn` referring to the classpath resource `secrets.edn.age`, which also
works when the resource is inside the uberjar.

`resources/common/secrets.edn.example` is a tracked, plaintext-safe shape
template with placeholders. It is documentation only and is never loaded by
the service. This example repository ignores the disposable ciphertext made
by the bootstrap script so local runs do not dirty the checkout. A real app
should commit its age ciphertext and a value-free manifest (for example, a
checksum and non-sensitive metadata), while never committing an age identity,
private key, or decrypted plaintext.

## Try it locally

From this directory, with `age` and `age-keygen` installed:

```sh
./scripts/bootstrap-demo.sh
SECRETS_AGE_IDENTITY_FILE=.demo/age-key.txt clojure -M:dev -m example.integrant-service.main
curl http://127.0.0.1:8080/health
```

The bootstrap creates fake values, a disposable ignored identity, and ignored
dev/prod ciphertext. It never writes a plaintext secret outside `.demo`, and
removes that plaintext before returning.

Run tests (the map-replacement test does not need `age` or a key):

```sh
clojure -M:test
```

## Build and run the jar

Bootstrap first so the prod classpath has ciphertext, then build and run:

```sh
clojure -T:build uber
SECRETS_AGE_IDENTITY_FILE=.demo/age-key.txt java -jar target/integrant-service-standalone.jar
```

The service reads identity configuration for each load operation. Mount a key as
a read-only container secret and pass its path through
`SECRETS_AGE_IDENTITY_FILE`; never copy a private identity into the image or
put its contents in a shell command's arguments:

```sh
docker build -t integrant-service .
docker run --rm -p 8080:8080 \
  --mount type=bind,src="$PWD/.demo/age-key.txt",dst=/run/secrets/age-key.txt,readonly \
  -e SECRETS_AGE_IDENTITY_FILE=/run/secrets/age-key.txt \
  integrant-service
```

`SECRETS_AGE_IDENTITY` (raw key contents) and `SECRETS_AGE_IDENTITY_B64` are
also supported for orchestrator-managed secret injection; prefer the
orchestrator's secret/environment mechanism rather than expanding them into
`docker run` arguments, where process inspection may reveal them.

For tests or a local substitute, omit the secrets Integrant key and put an
ordinary map directly in the HTTP component's `:secrets` value. See
`test/example/integrant_service/system_test.clj` for that replacement and for
the delegation test around `load-secrets`.
