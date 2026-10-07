# Security policy

## Supported versions

This project is in alpha. Security fixes are provided only for the newest
released alpha:

| Version or branch | Supported |
| --- | --- |
| `v0.1.0` | Yes |
| `main` | No; development branch, not a released version |
| Any other version or branch | No |

When a new alpha is published, it becomes the only supported release and
`v0.1.0` stops receiving fixes. This table will be updated as part of that
release. People using an unsupported version should reproduce against the newest
alpha when it is safe to do so and upgrade before applying a published fix.

## Scope

[`doc/threat-model.md`](doc/threat-model.md) defines what is in and out of
scope for a report. A report is out of scope if it depends on replacing the
deployed artifact, on a former recipient's access to values already disclosed,
on a compromised decrypting host, or on a hostile `age` binary.

## Report a vulnerability privately

Do not open a public issue or discussion with vulnerability details. Do not
publish sensitive report details, real secrets, credentials, personal or user
data, proof-of-concept payloads, or instructions for exploiting an unpatched
problem.

Email the maintainer at [contact@kirahowe.com](mailto:contact@kirahowe.com) with
a subject beginning `secrets security report`. This is the private reporting
channel; it is also the contact address published by the maintainer's
[GitHub profile](https://github.com/kirahowe). Do not assume ordinary email is
end-to-end encrypted. Start with sanitized details and ask for another transfer
method before sending material that cannot safely be sent by ordinary email.

If that address rejects the message or is otherwise unavailable, open a public
issue containing only `Security contact unavailable; please provide an alternate
private reporting route.` Do not identify the affected component, impact, or any
other report detail in that issue. Wait for the maintainer to arrange a private
exchange before sharing the report. This fallback is only a contact request, not
a vulnerability report.

## What to include

Share only the non-secret information needed to reproduce and assess the issue:

- the affected version, commit, operating system, Clojure or Babashka version,
  `age` version, and relevant configuration with all values sanitized;
- the affected component and the security impact you believe is possible;
- minimal, deterministic reproduction steps using generated test identities,
  synthetic ciphertext, placeholder paths, and fake data;
- whether exploitation needs repository access, a recipient, an identity, local
  access, or control of an input such as the ciphertext, manifest, or
  configuration file;
- any mitigations you have already confirmed;
- an email address for private follow-up, and whether and how you want to be
  credited in a future advisory.

Never send a real age identity, credential, decrypted secret, user record,
production URL containing a token, or other live data. Replace them with a
minimal synthetic example. If a useful proof of concept cannot be sanitized,
say that it exists and arrange a suitable transfer method with the maintainer
before sending it.

## Response targets

These are good-faith targets, not guarantees or a promise of a particular fix
date:

- acknowledgement within 3 business days;
- an initial validation and severity assessment, or a request for missing
  information, within 7 business days after acknowledgement;
- a private status update at least every 14 calendar days while work remains.

The time to remediate depends on severity, release safety, affected dependencies,
and the ability to prepare a supported release. The maintainer and reporter will
try to agree on a disclosure date after validation rather than promising a fixed
remediation window.

If an acknowledgement or status update misses its target, resend the original
email with `status request` in the subject. If there is still no response after
7 calendar days, use the minimal public contact request above; never use the
public issue to escalate by revealing report details.

## Validation, remediation, and coordinated disclosure

The maintainer will keep the report private while reproducing it with synthetic
data, determining affected supported releases, and preparing and testing a fix.
A supported release will be prepared before public details when a fix is
feasible. The maintainer will use a GitHub security advisory and request a CVE
when the scope and impact make either appropriate; neither is promised for every
report.

The maintainer and reporter should coordinate the advisory text, release timing,
and the amount of technical detail that is safe to publish. Reporter credit will
follow the reporter's stated name, link, and anonymity preference. Before public
disclosure, both sides should remove credentials, user data, and unnecessary
exploit details from examples.

The default disclosure deadline is 90 calendar days after the initial private report is sent. It
may be shortened for active exploitation or extended for release complexity,
an upstream fix, or unavailable release infrastructure, but only by explicit
agreement with the reporter. If no revised date was agreed and the maintainer is
unresponsive after the status request and 7-day escalation period above, the
reporter may disclose after the original 90-day deadline. The reporter should
notify the private address before disclosure and publish no secrets or user data.
Otherwise, public disclosure should wait until the fixed supported release and,
where appropriate, its advisory are ready.

This process does not offer a bug bounty, legal safe harbor, or a guaranteed
remediation date.
