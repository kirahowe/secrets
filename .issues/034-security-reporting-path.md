# 034 — Publish security reporting path

Status: `open`
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

- [ ] A root or GitHub-recognized `.github/SECURITY.md` is present and linked
      from the repository's main documentation or contribution path.
- [ ] The policy identifies exactly which released alpha versions/branches are
      supported and how support changes when a new alpha is published.
- [ ] It provides at least one working private channel controlled by the
      maintainer, such as GitHub private vulnerability reporting or a dedicated
      security address, with a safe fallback if the primary channel is
      unavailable.
- [ ] It tells reporters what non-secret reproduction, impact, affected-version,
      and contact information helps triage while warning them not to include
      real credentials or user data.
- [ ] It states acknowledgement, triage/status-update, and remediation/disclosure
      expectations using realistic target windows rather than an unsupported
      guarantee.
- [ ] It defines coordinated disclosure: private validation, fix and supported
      release preparation, advisory/CVE handling where appropriate, reporter
      credit preferences, and public disclosure only after coordination or the
      documented deadline/escalation path.
- [ ] Public issue templates or nearby reporting guidance direct suspected
      vulnerabilities to the private path without revealing report details.
- [ ] The channel and rendered links are checked from an unauthenticated
      repository view without sending a real vulnerability report.

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
