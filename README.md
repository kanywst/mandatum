# Mandatum

[![ci](https://github.com/kanywst/mandatum/actions/workflows/ci.yml/badge.svg)](https://github.com/kanywst/mandatum/actions/workflows/ci.yml)
[![security](https://github.com/kanywst/mandatum/actions/workflows/security.yml/badge.svg)](https://github.com/kanywst/mandatum/actions/workflows/security.yml)
[![licenses](https://github.com/kanywst/mandatum/actions/workflows/licenses.yml/badge.svg)](https://github.com/kanywst/mandatum/actions/workflows/licenses.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/kanywst/mandatum/badge)](https://scorecard.dev/viewer/?uri=github.com/kanywst/mandatum)
[![Go Reference](https://pkg.go.dev/badge/github.com/kanywst/mandatum.svg)](https://pkg.go.dev/github.com/kanywst/mandatum)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**Verifiable delegation for AI agents.** An agent's authority to act becomes a
signed chain rooted in a named human — attenuating at every hop, revocable at
any link, evaluated across whole action sequences, and recorded in a
tamper-evident log.

> **Status: design.** The specification is drafted and open for review. There
> is no usable implementation yet. See [ROADMAP.md](ROADMAP.md).
> The specification is the thing to read and argue with:
> [`docs/spec/delegation-assertion.md`](docs/spec/delegation-assertion.md).

---

## The problem

An AI agent acting for a person almost always does so by inheriting a
credential — a service account, an API key, a shared token, the human's own
session. Three failures follow from that, and they are measured, not predicted.

**You cannot say who is responsible.** Only 28% of organizations can trace an
agent's actions back to a human sponsor across all environments, and 68% cannot
reliably tell agent activity from human activity ([1](#references)).

**You cannot revoke one agent.** Agents share the credential they inherited, so
cutting off a misbehaving agent cuts off everything else using it. Nobody pulls
that lever, so the agent keeps its access.

**You cannot constrain a sequence.** Authorization is decided one call at a
time. An agent reads untrusted external content, then writes to an internal
system. Both calls are legitimately authorized. The pair is an exfiltration,
and no per-call check can see it.

The Model Context Protocol says where its own authorization stops: it is
defined at the transport level, and per-tool authorization, agent identity,
delegation, and consent are out of scope. The Enterprise-Managed Authorization
extension, stable since June 2026, is explicit that it governs the connection
and not the individual tool call.

That gap is what Mandatum fills. Nothing else.

## The shape of it

```text
  human sponsor  ──── authenticated, named, at the root of everything
       │
       ├─ MDA₀   grants: search.query on {public, docs}, 1h, max_depth 3
       │
       └─ agent A
            │
            ├─ MDA₁   grants: search.query on {public}, 40m, max_depth 2
            │         ↑ narrower than its parent. It cannot be wider.
            │
            └─ agent B
                 │
                 └─ MCP tool call ──▶ [ PEP ]
                                        │  1. verify the chain, offline
                                        │  2. check the sequence so far
                                        │  3. ask an AuthZEN PDP
                                        │  4. append to the audit log
                                        ▼
                                    allow / deny + a reason you can act on
```

Revoke `MDA₁` and agent B loses its authority immediately, along with anything
B delegated onward — because every descendant commits to its parent by hash.
Agent A and every sibling chain are untouched.

## What this is not

The failure mode for a project in this space is drifting into categories that
are already occupied. Mandatum stays out of them by design:

- **Not an authorization engine.** Mandatum never decides. It establishes facts
  and hands them to a Policy Decision Point that already exists — OPA, Cedar,
  OpenFGA, SpiceDB, Cerbos, or anything conformant with the OpenID AuthZEN
  Authorization API. Engines are not the gap.
- **Not a new protocol.** JOSE for the assertions, RFC 8693 for issuance,
  SPIFFE for workload identity, AuthZEN for decisions, RFC 6962 for the log.
  Where a standard fits, Mandatum uses it unchanged.
- **Not a gateway, registry, sandbox, or agent runtime.** Those categories are
  crowded. Mandatum is a library and middleware meant to run *inside*
  agentgateway, ToolHive, or an MCP server.
- **Not a blockchain.** The audit log is a Merkle tree. No consensus, no
  network, no token.

## Prior art, honestly

Attenuated capabilities with offline verification are the contribution of
macaroons and, in modern form, Biscuit. SPIFFE established workload identity.
RFC 8693 established delegation semantics for token exchange. Mandatum builds
on all of it and claims none of it.

What is new here is narrow: a chain **rooted in an authenticated human** that
survives arbitrary sub-delegation, **constraints evaluated over a sequence** of
actions rather than one call, and a **binding to AuthZEN** so the chain is
input to any conformant engine instead of one vendor's.

If something already does those three things, that is worth knowing before more
gets built. Please open an issue — see [`docs/alternatives.md`](docs/alternatives.md).

## Documentation

| Document | What it covers |
| --- | --- |
| [Delegation Assertion specification](docs/spec/delegation-assertion.md) | Format, attenuation rules, verification, AuthZEN binding, sequence evaluation, threat model |
| [`docs/alternatives.md`](docs/alternatives.md) | What else exists and why it does not close this gap |
| [ROADMAP.md](ROADMAP.md) | Both tracks, with gates |
| [GOVERNANCE.md](GOVERNANCE.md) | Roles, voting, organizational balance |
| [VERSIONING.md](VERSIONING.md) | Semantic versioning, wire-format versioning, deprecation |
| [CHANGELOG.md](CHANGELOG.md) | What changed, and the known limitations of each release |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to get a change merged |
| [SECURITY.md](SECURITY.md) | Reporting a vulnerability |
| [Supply chain](docs/security/supply-chain.md) | How to verify a release, what CI enforces, and the known gaps |

## Contributing

The most useful contribution right now is not code. It is disagreement with the
design from someone who has run agent systems in production, or a concrete
scenario that the specification cannot express. The specification has an
[open-questions section](docs/spec/delegation-assertion.md#12-open-questions)
that is genuinely open.

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache License 2.0](LICENSE).

---

## References

1. Cloud Security Alliance, *State of NHI and AI Security*, January 2026.
