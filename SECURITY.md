# Security policy

## Supported versions

This project is in alpha. The first release is `0.1.0`, tagged `v0.1.0`, and
it is available only as a git dependency. Nothing is published to Clojars at
the time of writing.

| Version or branch | Status |
| --- | --- |
| `0.1.0` | The current alpha. Supported, and reports are accepted. A fix ships in the next alpha, not as a patch to this tag. |
| `main` | Development branch, where fixes land first. Not a release. |
| Anything else | Not supported. |

A fix is released as the next alpha, tagged from `main`. Alphas can break
compatibility, so [CHANGELOG.md](CHANGELOG.md) says what a new alpha changes.
When a new alpha is tagged it becomes the only supported release, and this
table is updated with it.

## Scope

[`doc/threat-model.md`](doc/threat-model.md) defines what is in and out of
scope. A report is out of scope if it depends on replacing the deployed
artifact, on a former recipient's access to values already disclosed, on a
compromised decrypting host, or on a hostile `age` binary.

## Report a vulnerability privately

Do not open a public issue or discussion with vulnerability details.

Email the maintainer at [contact@kirahowe.com](mailto:contact@kirahowe.com)
with a subject beginning `secrets security report`. Ordinary email is not
end-to-end encrypted, so start with sanitized details and ask for another
transfer method before sending anything that cannot safely travel that way.

If that address rejects the message, open a public issue containing only
`Security contact unavailable; please provide an alternate private reporting
route.` Do not name the affected component or the impact there. Wait for the
maintainer to arrange a private exchange.

## What to include

- The affected version or commit, operating system, Clojure or Babashka
  version, `age` version, and the relevant configuration with values removed.
- The affected component and the impact you believe is possible.
- Minimal reproduction steps that use generated test identities and fake data.
- What an attacker needs: repository access, a recipient, an identity, local
  access, or control of an input such as the ciphertext, manifest, or
  configuration.
- An address for private follow-up, and whether and how you want to be
  credited.

Never send a real age identity, credential, decrypted secret, or other live
data. If a proof of concept cannot be sanitized, say that it exists and agree
on a transfer method first.

## What to expect

These are good-faith targets, not guarantees:

- an acknowledgement within 3 business days;
- an initial assessment, or a request for missing information, within 7
  business days after that;
- a private status update at least every 14 calendar days while work remains.

If a target is missed, resend the original email with `status request` in the
subject. If there is still no response after 7 calendar days, use the public
contact request above, without report details.

The maintainer keeps the report private while reproducing it and preparing a
fix, and releases the fix before publishing details when a fix is feasible.
A GitHub security advisory and a CVE are used when the scope and impact make
them appropriate, and neither is promised for every report. Advisory text,
timing, and credit are agreed with the reporter. The default
disclosure deadline is 90 calendar days after the first private report. It can
be shortened for active exploitation or extended by explicit agreement. If no
other date was agreed and the maintainer has not responded to the status
request and the 7-day escalation, the reporter may disclose after the 90 days,
after notifying the private address and without publishing secrets or user
data.

This process offers no bug bounty, legal safe harbor, or guaranteed
remediation date.
