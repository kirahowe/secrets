# 021 — Self-host documentation scripts

Status: `open`
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

- [ ] Required JavaScript and CSS dependencies are versioned locally and
      generated into the Pages artifact without runtime third-party fetches.
- [ ] Unused script dependencies are removed rather than bundled.
- [ ] If any external asset is unavoidable, it has reviewed SRI plus
      `crossorigin`, and the site uses a restrictive CSP compatible with it.
- [ ] A generated-artifact check rejects unexpected external script/style URLs,
      missing integrity metadata, and unsafe inline/eval script allowances.
- [ ] Install commands, code blocks, and clipboard behavior remain correct with
      network access restricted to the site origin.
- [ ] Asset update provenance and review are reproducible from source.

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
