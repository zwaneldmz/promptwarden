# Security Policy

Wardkeep handles sensitive customer data by design — the entire point of
the project is to keep that data from leaking. We take reports about the
project itself leaking, bypassing its own guardrails, or mishandling data
seriously, and we ask researchers to report privately before disclosing
publicly.

## Reporting a vulnerability

Please use one of these two channels — do not open a public GitHub issue for
security reports:

1. **GitHub private vulnerability reporting** (preferred): open a report via
   the "Security" tab on this repository ("Report a vulnerability"). This
   creates a private advisory visible only to maintainers until it is
   resolved.
2. **Email**: lzwane@abantu.tech. If possible, encrypt sensitive details;
   otherwise a plain-text report is fine — please just avoid pasting real
   customer data as a proof of concept.

Include what you'd normally include: affected version/commit, a description
of the issue, reproduction steps or a PoC, and the impact you believe it has
(e.g., prompt content leaving the browser when it shouldn't, a detector
bypass, managed-policy tampering, a way to defeat the no-egress guarantee).

## What we consider in scope

- The inline policy engine and extension content/background scripts
  (`packages/policy-engine`, `apps/extension`) — especially anything that
  causes prompt content to be logged, transmitted, or exfiltrated when the
  configured policy says it shouldn't be.
- Detector bypasses that let regulated data (card numbers, IBANs, SVNRs,
  API keys) through a policy configured to block or redact it.
- Managed-policy or storage handling that lets an unprivileged actor
  escalate, override, or forge policy.
- Supply-chain issues in the release/signing process
  (`.github/workflows/release.yml`, cosign keyless signing + build
  provenance attestation — see `docs/RELEASING.md`) once the first signed
  release has actually shipped from it. The pipeline exists; no tag has
  been pushed through it yet, so there is nothing signed to attack in the
  meantime.

## What is out of scope

- Findings that require a compromised or malicious admin who already has
  the ability to push managed policy (that's the trust boundary Chrome
  Enterprise itself relies on).
- Missing detectors for data types the policy schema was never asked to
  cover (please file these as normal feature requests instead).
- The console and AI audit tier: not built yet, nothing to report.

## Our commitment

- **Acknowledgment within 72 hours** of a report reaching us through either
  channel above.
- We will work with you to understand and validate the issue, and keep you
  updated as we investigate and fix it.
- **Coordinated disclosure window of 90 days** from acknowledgment, or until
  a fix ships and users have had a reasonable chance to update — whichever
  is sooner by mutual agreement. If a fix needs more time, we'll tell you
  why and propose a revised date rather than go silent.
- We will credit you in the advisory and release notes, unless you'd rather
  stay anonymous.

## Safe harbor

We consider security research conducted under this policy to be authorized:

- Good-faith attempts to find and report vulnerabilities in Wardkeep's
  own code, run against your own installation or test environment.
- We will not pursue legal action against, or report to authorities,
  researchers who make a good-faith effort to comply with this policy —
  including reporting privately first, not accessing or exfiltrating data
  beyond what's needed to demonstrate the issue, and not testing against
  systems or accounts you don't own or have explicit permission to test.

This safe harbor does not extend to testing against a live pilot customer's
deployment, their employees' accounts, or any data that is not yours,
without that customer's separate written permission.

## Supported versions

Pre-1.0: only the latest tagged release is supported. Once we reach 1.0 this
section will list a support matrix.
