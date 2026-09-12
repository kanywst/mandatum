# Security Policy

Mandatum is security infrastructure. A defect in chain verification, in
attenuation, or in sequence evaluation is an authorization bypass, so this
project treats such reports as its highest priority work.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report through GitHub's private vulnerability reporting on this repository
(Security → Report a vulnerability). That channel is monitored by the Security
Response Team listed in [MAINTAINERS.md](MAINTAINERS.md).

Please include, to whatever extent you can:

- the affected version or commit
- a description of the impact, in terms of what authority an attacker gains
- steps to reproduce, ideally a failing test or a minimal chain
- any mitigation you have identified

You do not need a working exploit. A precise description of an unsound
verification step is sufficient and welcome.

## What to expect

| Stage | Target |
| --- | --- |
| Acknowledgement of your report | 3 business days |
| Initial assessment and severity | 10 business days |
| Fix or documented mitigation for critical severity | 30 days |
| Coordinated disclosure | Agreed with you, default 90 days |

If a deadline will be missed, the Security Response Team says so and explains
why rather than letting the report go quiet.

## Disclosure

Mandatum practises coordinated disclosure. When a fix ships:

- a GitHub Security Advisory is published with a CVE where one applies
- the advisory names the reporter unless they ask otherwise
- the release notes link the advisory
- affected released versions are stated explicitly, including versions that
  were never patched

## Scope

In scope:

- unsound chain verification, including any way to make a verifier accept a
  chain that violates a rule in the specification
- privilege escalation through delegation, including attenuation bypass
- chain splicing, replay after revocation, and attribution stripping
- sequence-constraint evasion, including any path that silently degrades
  sequence evaluation to per-call evaluation
- denial of service reachable from an unauthenticated caller
- key handling, signature verification, and algorithm confusion

Out of scope:

- vulnerabilities in a Policy Decision Point, an identity provider, or another
  upstream system, unless Mandatum's use of it is what makes them exploitable
- results from automated scanners without a described impact
- misconfiguration that the documentation warns against, though a report that
  the documentation is misleading is in scope and wanted

## Supported versions

Until v1.0, only the latest release receives security fixes. The support policy
after v1.0 will be recorded here before v1.0 ships.

## Security practices

The project's own supply chain commitments are documented in
`docs/security/supply-chain.md` and enforced in CI: release artifacts are
signed, an SBOM is published with each release, dependencies are license- and
vulnerability-scanned on every pull request, and the verification core is
fuzzed continuously.
