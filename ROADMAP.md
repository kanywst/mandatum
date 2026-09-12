# Roadmap

Last updated: 2026-09-12.

This roadmap has two tracks that run at the same time. The engineering track is the one that produces software. The community track is the one that decides whether the project survives, and it is listed first because it is the harder of the two and the one most likely to be neglected.

Dates are targets, not commitments. Gates are commitments: a release does not ship until its gates are met, including the community gates.

## Community track

A project maintained by one person, with no users, is not a project. Two of the v1.0 gates below are therefore about people rather than code, and they are release-blocking in the same way a failing test is.

| Goal | Target | Status |
| --- | --- | --- |
| Specification published for public review | 2026 Q4 | In progress |
| Design reviewed by at least three people outside the project | 2026 Q4 | Not started |
| Reference implementation contributed to an upstream standards discussion | 2027 Q1 | Not started |
| First external contributor with a merged non-trivial change | 2027 Q1 | Not started |
| First Reviewer appointed | 2027 Q2 | Not started |
| First named entry in `ADOPTERS.md` | 2027 Q2 | Not started |
| Maintainers from a second organization | 2027 Q3 | Not started |
| Three named adopters | 2027 Q4 | Not started |

### Upstream engagement

Mandatum deliberately implements other people's standards rather than inventing its own, which means the specifications it depends on are being written now and the project should be present while that happens. Planned participation:

- **OpenID AuthZEN Working Group** — the COAZ-MCP binding reached Working Group Draft in June 2026 and has few implementers. Mandatum aims to be a conformance-tested implementation and to report interoperability results back.
- **`modelcontextprotocol/ext-auth`** — issue #14 proposes AuthZEN integration and has been open without a maintainer response since February 2026. Mandatum's MCP binding is directly relevant to it.
- **CNCF TAG Workloads Foundation**, TOC initiative #1746, which explicitly solicits work on agent observability schemas and policy interfaces.
- **CNCF TAG Security and Compliance**, TOC initiative #1890, on MCP authentication and authorization standards.
- **IETF WIMSE** — Mandatum's workload identity half builds on WIMSE drafts and should report implementation status.

## Engineering track

### v0.1 — Specification and verifier (2026 Q4)

The verifier is the security core. It ships first, alone, so that it can be reviewed and attacked before anything depends on it.

- Delegation Assertion format, frozen for v0
- Chain verification implementing rules V1 through V9
- Attenuation checking over the decidable condition fragment
- Continuous fuzzing of parsing and verification
- A negative-test corpus: every rule in the specification has a test that proves a chain violating it is rejected

Gates: fuzzing runs clean for 24 hours; every specification rule has a corresponding negative test; the threat model is published.

### v0.2 — AuthZEN and MCP binding (2027 Q1)

- ~~AuthZEN Authorization API 1.0 client~~ done
- ~~Mapping from a verified chain to an evaluation request~~ done
- ~~Conformance against the COAZ-MCP working group draft, with divergences documented rather than hidden~~ done, for the `tools/call` default mapping only
- MCP tool-call enforcement middleware: the mapping exists, the middleware that calls it does not
- Declared mappings and CEL, which the binding defines and this does not read
- Interoperability tested against at least three independent PDP implementations

Gates: works against three PDPs from different vendors with no implementation-specific code paths.

### v0.3 — Sequence evaluation and audit (2027 Q2)

- ~~Constraint compilation, with rejection of constraints that do not compile~~ done
- ~~Bounded per-chain sequence state~~ done
- ~~Fail-closed behaviour on state loss, with a test that proves it~~ done
- A replicated sequence store, since the in-process one is single-PEP only
- Tamper-evident audit log with inclusion and consistency proofs
- Replay: re-evaluate a logged decision against its recorded policy revision

Gates: an operator can answer "why was this denied?" for any logged decision, and can prove the log has not been altered.

### v0.4 — Integrations (2027 Q3)

Mandatum runs inside existing infrastructure rather than replacing it.

- Plugin for agentgateway
- Integration with ToolHive
- Middleware for the reference MCP server implementations
- Revocation distribution suitable for multiple enforcement points
- Deployment documentation for Kubernetes

Gates: at least one integration merged or endorsed upstream by that project's maintainers.

### v1.0 — Production (2027 Q4 to 2028 Q1)

- Stability commitment for the wire format and the Go API
- Documented upgrade and deprecation policy
- Third-party security review
- Performance characterized and published, including verification latency at the enforcement point

Gates, all required:

1. Third-party security review completed and findings addressed.
2. Wire format unchanged for two consecutive minor releases.
3. **Maintainers from at least two organizations.**
4. **At least three named adopters in `ADOPTERS.md`.**

Gates 3 and 4 are not negotiable and will not be waived to hit a date. A v1.0 without them would be a version number rather than a project.

## Donation to a foundation

The project intends to apply to the CNCF Sandbox. The application will be made when the v1.0 gates are met and not before, because the CNCF's own published reasons for declining applications in 2026 are precisely the conditions those gates describe: too few maintainers, no adopters, and insufficient community activity.

Preparatory work already done or planned:

- Apache 2.0 from the first commit, with transitive dependency licenses enforced against the CNCF allowlist in CI
- Governance with an organizational-balance mechanism from the start, rather than added at Graduation when it is required
- Project infrastructure held so that it can transfer with the project
- A project name chosen to be free of conflicting trademarks

## Explicitly out of scope

These are recorded so the project can say no consistently:

- A policy engine or policy language
- An MCP gateway, registry, or agent runtime
- An agent sandbox
- A general-purpose identity provider
- Anything requiring a distributed ledger

## Changing this roadmap

Roadmap changes follow [GOVERNANCE.md](GOVERNANCE.md) §3: a public proposal and a seven-day comment period. Changes that remove a v1.0 gate require a supermajority vote.
