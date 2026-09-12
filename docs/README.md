# Documentation

## Available now

| Document | What it covers |
| --- | --- |
| [Delegation Assertion specification](spec/delegation-assertion.md) | The wire format, attenuation rules, chain verification, the AuthZEN binding, sequence evaluation, and a summary threat model. This is the document to review and argue with. |
| [Alternatives](alternatives.md) | What else exists, and why it does not close this gap. Maintained adversarially. |
| [Threat model](security/threat-model.md) | What is defended, from whom, what is assumed rather than enforced, and what is not yet covered. |
| [Supply chain](security/supply-chain.md) | How to verify a release, what CI enforces, and the known gaps. |
| [Translations](i18n.md) | Which documents are translated, and why English stays normative. |

## Planned

The specification references these documents. They are not written yet, and are listed here so that a reader can tell a deliberate gap from an oversight. Each is tied to a release in [ROADMAP.md](../ROADMAP.md).

| Document | Contents | Due |
| --- | --- | --- |
| `spec/coaz-mcp-conformance.md` | Conformance against the AuthZEN COAZ-MCP working group draft, and any divergence, stated rather than hidden. | v0.2 |
| `spec/sequence-store.md` | The interface a sequence-state store must satisfy, and what a store must guarantee for fail-closed behaviour to hold. | v0.3 |
| `compliance/eu-ai-act.md` | How the audit trail maps to the high-risk logging and traceability obligations applicable since 2026-08-02. Written by engineers, not lawyers, and says so. | v0.3 |
| `project/infrastructure.md` | Who currently holds each piece of project infrastructure, per GOVERNANCE.md §5.4. | v0.2 |

If you need one of these sooner than its release, say so in an issue. Ordering is a guess about what matters and is easy to change.
