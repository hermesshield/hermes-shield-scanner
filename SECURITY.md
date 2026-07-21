# Security Policy

Hermes Shield is a security tool, so we hold our own code to the standard we scan for. If you find a
vulnerability in the scanner, we want to hear about it.

## Reporting a vulnerability

**Please report privately — do not open a public issue for a security bug.**

Email **security@hermesshield.ai** with:

- a description of the issue and its impact,
- the version (`hermes-shield --version`) and platform,
- steps to reproduce (a minimal proof-of-concept is ideal).

We aim to acknowledge a report within **3 working days** and to give an initial assessment within
**10 working days**. We will keep you updated on remediation and coordinate a disclosure timeline with you.

## Scope

In scope: the scanner package (`hermes_shield`), its CLI, and its optional tiers (`--ai`, `--semgrep`,
`--deps`, `--prove`). Of particular interest:

- any path by which scanning an **untrusted target repository** could read or exfiltrate files outside the
  target, execute code outside the sandbox, or otherwise compromise the operator's machine;
- any way the `--prove` sandbox (network isolation, read-only target, resource limits) could be escaped or
  its network-deny bypassed;
- any way the tool could report a finding as **PROVEN-LIVE** that is not, in fact, empirically demonstrated.

Out of scope: findings the tool reports about *your own scanned code* (that is the tool working as
intended), and issues requiring a malicious operator who already controls the machine.

## Safe harbour

We will not pursue or support legal action against researchers who, in good faith, discover and report a
vulnerability under this policy, provided they avoid privacy violations, data destruction, and service
disruption, and give us reasonable time to remediate before public disclosure.

## Our own assurance

The scanner has had **an independent security review by an industry professional** (unnamed), twice. The
first pass (v0.1.0) raised **2 High + 1 Medium**, all remediated in v0.3.7 and locked in with the reviewer's
own regression tests; the re-review of that fixed build (v0.3.7) found **0 critical / 0 high**. Finding and
fixing real issues in our own code — then publishing the loop — is the assurance we offer, not a claim of a
clean first sheet. **The reviewed builds were v0.1.0 / v0.3.7; re-validation of the current core is
pending.** Findings and remediation are recorded in `CHANGELOG.md`; core changes since the reviewed build
are itemised there too. See `FOR_AUDITORS.md` for scope and reproduction details.

