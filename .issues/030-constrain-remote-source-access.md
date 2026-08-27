# 030 — Constrain remote source access

Status: `resolved`
Priority: P1
Review classification: Conditional Medium

## Problem

The normal runtime API accepts URL-like source values and passes them to
`clojure.java.io/input-stream` without a scheme, host, address, port, or redirect
policy. It also sets no connection or read timeout. If an application lets an
attacker influence the source, the library can be used to make server-side
requests to internal or local services (SSRF), follow redirects outside an
intended host, or wait indefinitely before the first bounded byte arrives.

This is conditional on source provenance: a fixed classpath resource or local
path does not create attacker-selected SSRF. It is an alpha contract blocker if
the supported API continues to permit attacker-influenced remote sources.

## Evidence

- The public [`load-secrets` contract](../src/com/kirahowe/secrets.clj#L815-L852)
  explicitly accepts a path, `File`, URL, classpath resource URL, or any other
  value accepted by `clojure.java.io/input-stream`.
- [`source->file`](../src/com/kirahowe/secrets.clj#L605-L630) hands every
  non-existing-file source directly to `io/input-stream`; it does not inspect or
  restrict scheme, host, resolved address, port, or redirect destination and
  does not configure a connection.
- [`acquire-source!`](../src/com/kirahowe/secrets.clj#L688-L706) wraps open/read
  failures but adds no network policy or timeout.
- The fixed-byte copier begins enforcing `:max-source-bytes` only after the
  stream is open and a read returns
  ([`copy-source!`](../src/com/kirahowe/secrets.clj#L569-L603)). A stalled DNS,
  connection, redirect, or pre-byte response is therefore outside the byte
  bound.
- Controlled inspection of the JVM URL connection used by this path observed
  both defaults as zero: `getConnectTimeout` returned `0` and `getReadTimeout`
  returned `0`. In Java these values mean no finite timeout was configured.
- Existing source diagnostics recognize nested URL schemes and retain safe
  metadata, but that is a redaction measure rather than an access-control policy
  ([source descriptor](../src/com/kirahowe/secrets.clj#L468-L556)).

## Desired outcome

Choose and document one explicit source contract. Prefer restricting the normal
API to local paths/files and local `file:`/`jar:` classpath resources. If remote
HTTP remains supported, expose it as an explicit operation with finite connect
and read timeouts and a caller-supplied access policy that controls schemes,
hosts/addresses, ports, DNS rebinding treatment, and each redirect hop.

## Acceptance criteria

- [x] The public contract clearly distinguishes local/resource loading from any
      remote network operation; arbitrary `io/input-stream` URL dispatch is no
      longer an implicit normal-API behavior.
- [x] Under a local-only contract, nonlocal schemes and remote/nested `jar:`
      sources are rejected before DNS or network I/O while local file and
      classpath-jar resources continue to work.
- [x] If HTTP is retained, it is opt-in and requires finite connect/read
      timeouts plus an explicit caller policy for scheme, host/address, port,
      DNS resolution, and every redirect destination. HTTP was not retained:
      there is no network operation or timeout surface in this API.
- [x] Redirects cannot escape the original allowed policy, including through a
      hostname resolving to loopback, link-local, or private addresses unless
      the caller deliberately permits them. The local-only boundary rejects the
      first HTTP hop, so no redirect destination is reached.
- [x] Source byte limits remain enforced during streaming and timeout/policy
      failures use content-free diagnostics.
- [x] Coverage includes disallowed schemes, loopback/private targets, redirect
      hops, connection stalls, read stalls before the first byte, and accepted
      local file/jar resources.
- [x] Public API and user documentation state the chosen source provenance and
      timeout contract.

## Resolution

The normal runtime contract is local-only. `load-secrets` accepts filesystem
path strings, `File`/`Path`, strict local `file:` locators, and strict
`jar:file:` classpath resources. It rejects HTTP(S), other nonlocal schemes,
remote or multiply nested jars, file authorities, malformed local locators,
InputStreams, and all other arbitrary `io/input-stream` values with
`:reason :disallowed-source`. The decision follows the issue's preferred
contract and avoids inventing a generic DNS/redirect policy that the library
cannot safely guess for callers.

Enforcement lives in `local-source`/`source->file`, immediately before opening
the source. Local file locators become `File` values and jar entries are opened
from a validated local archive with `JarFile`; neither path dispatches through a
caller-provided `URLStreamHandler`. URL metadata is rebuilt from field getters
rather than `URL.toString`/`toURI`, so even descriptor and classification work
does not invoke a custom handler. A validated jar entry is copied under
`:max-source-bytes`; existing filesystem files retain the prior pre-decryption
length check.

Reader `:file`/`:resource` configuration reaches the same runtime boundary.
CLI artifact configuration now rejects URI-like locations in `require-path!`
(while preserving Windows drive paths), making its source/destination contract
filesystem-only. Its failure retains the environment, field, normalized scheme,
and reason — never the raw locator, whose userinfo or query may be a credential.

Policy diagnostics retain only the existing allowlisted source descriptor and
have no transport cause because no transport was opened. README API, provenance,
resource-limit, and diagnostic sections state that no HTTP operation exists,
therefore no connect/read timeout or redirect setting exists; applications that
need a remote ciphertext must fetch it explicitly under their own complete
network policy and pass a trusted local path.

Focused regression coverage:

- `local-source-loading-test` covers path, File, Path, file URL/URI/string, local
  jar URL/URI/string, and allowed-looking URL objects with hostile handlers. The
  JVM-only handler is constructed dynamically so Babashka can analyze and run
  the remaining cross-runtime coverage without resolving `URLStreamHandler`.
- `remote-source-policy-test` covers nonlocal/nested schemes, loopback/private
  targets, redirect, connection-stall, and pre-byte read-stall cases. Controlled
  loopback endpoints assert that direct, redirecting, and nonresponding servers
  receive no request.
- `source-size-boundary-test` preserves exact/over-limit streaming behavior for
  local classpath-jar entries and cleanup of completed or partial copies.
- `source-failures-carry-no-sentinel-test` and
  `diagnostics-remain-actionable-test` pin content-free policy failures and
  actionable local-source failures.
- `artifact-locators-are-rejected-test` covers CLI configuration enforcement for
  every artifact role, the Windows drive-path exception, and full rendered
  exception/ex-data redaction for a credential-bearing locator sentinel.

## Non-goals

- Claiming fixed local/resource sources are currently exploitable.
- Treating response byte limits or URL redaction as SSRF prevention.
- Installing one global hostname allowlist that silently guesses every caller's
  network policy.

## Verification

Drive source loading against controlled local endpoints for direct requests,
redirects, delayed connection/read behavior, and responses over the byte limit.
Confirm the chosen local-only or explicit-HTTP contract rejects network access
before a disallowed request is made, enforces finite timeouts, and preserves
working local path, `file:`, and local classpath `jar:` sources.

## Dependencies / related files

- [runtime source loading](../src/com/kirahowe/secrets.clj)
- [runtime source tests](../test/com/kirahowe/secrets_test.clj)
- [public API documentation](../README.md)
