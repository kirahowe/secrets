# 021 — Self-host documentation scripts

Status: `resolved`
Priority: P2
Review classification: Low

## Problem

Rendered Pages HTML loads jQuery and jQuery UI from `code.jquery.com` without
Subresource Integrity or a restrictive Content Security Policy. Compromise of
the CDN response can rewrite installation commands, links, or clipboard content
presented by the project.

## Evidence

- [Rendered book artifacts](../book/rendered) contain external jQuery/jQuery UI
  script references without SRI.
- [CI](../.github/workflows/ci.yml) uploads `book/rendered` to Pages, so those
  references reach the published documentation.
- Exploitation requires compromise or interception of the third-party asset
  delivery path. No current CDN compromise was observed.

## Desired outcome

Serve exact reviewed documentation assets from the same immutable Pages
artifact and enforce a restrictive script policy.

## Acceptance criteria

- [x] Required JavaScript and CSS dependencies are versioned locally and
      generated into the Pages artifact without runtime third-party fetches.
- [x] Unused script dependencies are removed rather than bundled.
- [x] If any external asset is unavoidable, it has reviewed SRI plus
      `crossorigin`, and the site uses a restrictive CSP compatible with it.
      *(No external asset remains, so SRI is moot; the CSP is in place.)*
- [x] A generated-artifact check rejects unexpected external script/style URLs,
      missing integrity metadata, and unsafe inline/eval script allowances.
- [x] Install commands, code blocks, and clipboard behavior remain correct with
      network access restricted to the site origin.
- [x] Asset update provenance and review are reproducible from source.

## Resolution

jQuery and jQuery UI are **removed**, not self-hosted, because nothing in the
book uses them. Clay injects them unconditionally as part of its
`:html-default`/`:md-default` `special-lib-resources` — a plain `def` in
`scicloj/clay/v2/page.clj` with no config knob — and the book renders prose, code
blocks and printed output, with no vega, datatables or portal widget. The only
`$(` occurrences in the output are shell command substitutions inside
syntax-highlighted code blocks, and `window.jQuery` is `undefined` on the
rendered page; the residual mentions are `if (window.jQuery)` interop branches
inside Quarto's own locally-shipped bundles, which no-op without it. Criterion 2
asks for exactly this: an unused script dependency is removed rather than
bundled. Quarto already self-hosts everything it genuinely needs under
`site_libs/`.

`com.kirahowe.secrets.site-policy` rewrites the rendered artifact and then checks
it, and `bb book:build` runs both and fails on any finding, so a local build
cannot produce a non-compliant artifact; CI asserts it again so the failure is
legible in the job log. External script removal matches the *shape* of an
absolute `src` rather than the jQuery URLs by name, so a future Clay default
adding a third URL is also removed instead of silently shipped.

Three findings the issue did not anticipate, and they are the substance of the
work.

Quarto's cosmo Bootstrap CSS contains
`@import"https://fonts.googleapis.com/css2?family=Source+Sans+Pro…"` — a third
runtime third-party fetch, invisible in the HTML and therefore invisible to the
issue's own evidence, which only looked at script tags. It is now stripped, and
the check reads `@import`/`url()` in every stylesheet rather than only the HTML.
The imported URL contains semicolons, so a naive `[^;]*;` removal corrupts the
file; there is a test for that.

`book/rendered/.quarto` (Quarto's build cache, `idx/*.qmd.json`) and the `.qmd`
sources Clay leaves behind both shipped to Pages carrying their own copies of the
jQuery tags. The sources are now rewritten, the cache is deleted, and both are
covered by the check.

The CSP is hash-based for scripts: `script-src 'self'` plus a `'sha256-…'` per
executable inline script, computed at build time because Quarto's inline script
is generated and a hardcoded hash would rot into a broken page. Verified
independently during review across all nine pages: every executable inline
script is covered by a digest computed outside the implementation, no
`unsafe-inline` appears in `script-src`, and `unsafe-eval` appears nowhere. A
`type="application/json"` block is data, gets no hash, and is left intact.

Two allowances are deliberate and were measured both ways rather than assumed.
`'unsafe-hashes'` is required for two inline event handlers Quarto emits
(`onclick="window.quartoOpenSearch();"` and the collapsed-layout sidebar
toggle): without it both report `handlerRan: false` with "Executing inline event
handler violates…" logged; with it both run and the console is clean. It admits
only those exact handler bodies and is neither `unsafe-inline` nor
`unsafe-eval`. `style-src` keeps `'unsafe-inline'` because `quarto-nav.js` writes
style *attributes* at runtime with values computed from the header height it
measures — no build-time hash can cover a runtime-computed value, and hashes do
not apply to style attributes at all without `'unsafe-hashes'`. A hash-only
variant was built and loaded: four blocked-inline-style violations per page and a
sidebar that loses its positioning. The static `<style>` blocks hash fine; the
runtime writes are what make it unworkable.

`font-src` carries `data:` because Bootstrap's icon font is embedded as a data
URL. `frame-ancestors 'none'` is emitted knowing browsers ignore it in `<meta>`
form; the docstring records that it is inert here and holds only if the artifact
is ever served with real headers.

Regression tests: `external-scripts-are-removed-test`,
`external-stylesheet-imports-are-removed-test`, `whole-artifact-is-rewritten-test`,
`csp-hashes-cover-inline-scripts-test`, `rewriting-is-idempotent-test`,
`policy-rejects-violations-test`, `policy-accepts-a-compliant-page-test`, and a
real-artifact test that skips with a stated reason when `book/rendered` is absent
— the suite must not need `quarto` to run.

Verified after a real `bb book:build`: zero external script or stylesheet URLs
anywhere under `book/rendered`, no `fonts.googleapis` reference, no `.quarto`
cache, and a CSP on all nine pages. The remaining `https://` references are prose
links in `<a href>`, which the rewrite deliberately never touches.

## Non-goals

- Claiming self-hosting protects against a compromised project release or Pages
  deployment account.
- Adding analytics or unrelated frontend dependencies.
- Hand-editing rendered output without updating its source/generator.

## Verification

Regenerate the book, scan the complete Pages artifact for external executable
assets and policy violations, then load it with third-party network requests
blocked. Exercise command rendering and copy behavior from the actual page.

## Dependencies / related files

- [book source](../book/chapters)
- [rendered Pages artifact](../book/rendered)
- [CI Pages deployment](../.github/workflows/ci.yml)
