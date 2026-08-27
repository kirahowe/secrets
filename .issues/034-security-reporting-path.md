# 034 — Publish security reporting path

Status: `resolved`
Priority: P2
Review classification: Low release hygiene

## Problem

The repository has no `SECURITY.md` and no documented private channel for
reporting a vulnerability. A researcher cannot determine which alpha versions
receive security fixes, how to avoid disclosing an unpatched report in a public
issue, when to expect acknowledgement or status updates, or how coordinated
disclosure will be handled.

This is release hygiene rather than evidence of a product vulnerability, but an
alpha that processes encryption identities and decrypted secrets needs an
unambiguous safe reporting route before publication.

## Evidence

- Repository inspection found no `SECURITY.md` at the root or under `.github/`.
- The public [`Security notes`](../README.md#L1360-L1407) document operational
  risks and safe handling but provide no vulnerability-reporting channel,
  supported-version statement, response expectation, or disclosure process.
- The [`Development`](../README.md#L1007-L1047) and
  [`Releasing`](../README.md#L1076-L1148) sections explain contribution checks
  and publication mechanics but do not tell a reporter how to share sensitive
  vulnerability details privately.
- The repository's issue backlog is stored as ordinary Markdown files, including
  this one; that public workflow is not a safe substitute for a confidential
  report containing exploit details or affected secrets.

## Desired outcome

Publish a discoverable security policy that names supported alpha versions, a
working private reporting channel, the information useful for triage, response
and status-update expectations, and a coordinated disclosure process. It must
explicitly direct reporters not to publish sensitive report details, secrets,
proof-of-concept payloads, or unpatched exploit instructions in public issues.

## Acceptance criteria

- [x] A root or GitHub-recognized `.github/SECURITY.md` is present and linked
      from the repository's main documentation or contribution path.
- [x] The policy identifies exactly which released alpha versions/branches are
      supported and how support changes when a new alpha is published.
- [x] It provides at least one working private channel controlled by the
      maintainer, such as GitHub private vulnerability reporting or a dedicated
      security address, with a safe fallback if the primary channel is
      unavailable.
- [x] It tells reporters what non-secret reproduction, impact, affected-version,
      and contact information helps triage while warning them not to include
      real credentials or user data.
- [x] It states acknowledgement, triage/status-update, and remediation/disclosure
      expectations using realistic target windows rather than an unsupported
      guarantee.
- [x] It defines coordinated disclosure: private validation, fix and supported
      release preparation, advisory/CVE handling where appropriate, reporter
      credit preferences, and public disclosure only after coordination or the
      documented deadline/escalation path.
- [x] Public issue templates or nearby reporting guidance direct suspected
      vulnerabilities to the private path without revealing report details.
- [x] The channel and rendered links are checked from an unauthenticated
      repository view without sending a real vulnerability report.

## Resolution

Added a root [`SECURITY.md`](../SECURITY.md), which GitHub recognizes as the
repository security policy. It names `v0.1.0` as the only supported alpha,
states that `main` and every other version or branch are unsupported, and makes
the newest alpha the sole supported release as soon as it is published.

The private route is `contact@kirahowe.com`, linked with a `mailto:` URL and
grounded in the contact address the maintainer already publishes on the
[`kirahowe` GitHub profile](https://github.com/kirahowe), rather than an invented
security mailbox or an assumed GitHub repository setting. If that address is
unavailable, the policy permits only a content-free public request for an
alternate private route; it forbids naming the component, impact, or any report
detail there.

The policy asks for affected versions, sanitized configuration, impact,
synthetic reproduction steps, prerequisites, mitigations, a follow-up address,
and credit preference. It forbids real identities, credentials, decrypted
secrets, production URLs with tokens, user data, and unsanitized proof of
concepts. Good-faith targets are 3 business days for acknowledgement, 7 business
days for initial triage, and a private update every 14 calendar days, explicitly
not guarantees. Remediation timing remains severity- and release-dependent.

Coordinated disclosure covers private synthetic-data validation, a supported
fix release when feasible, advisory and CVE handling where appropriate,
reporter-chosen credit or anonymity, and sanitization before publication. Its
default deadline is 90 calendar days from the initial private report, with
changes only by reporter agreement and a documented status-request, 7-day, and
content-free public-contact escalation path when the maintainer is unresponsive.

The root README links the policy beside its operational security notes and tells
reporters not to use public issues. The GitHub issue chooser also links
`https://github.com/kirahowe/secrets/security/policy` with the same warning.
An unauthenticated Chromium check loaded the public repository and maintainer
profile and resolved the rendered profile contact to
`mailto:contact@kirahowe.com`; no message or vulnerability report was sent.

## Non-goals

- Publishing an active report, exploit payload, reporter identity, credential,
  or other sensitive detail in this backlog.
- Promising a bug bounty, 24-hour remediation, or legal safe-harbor terms the
  maintainer cannot support.
- Treating the reporting policy as a replacement for fixing vulnerabilities.

## Verification

View the repository as an unauthenticated visitor and follow the security-policy
link to the private reporting instructions. Confirm supported alpha versions and
response/disclosure expectations are clear, every contact/link resolves to the
intended maintainer-controlled destination, and no step requires opening a
public issue with sensitive details.

## Dependencies / related files

- [public project documentation](../README.md)
- [repository metadata and workflows](../.github/)
- [security backlog index](README.md)
