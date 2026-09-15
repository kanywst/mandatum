# Documentation

## Available now

| Document | What it covers |
| --- | --- |
| [Delegation Assertion specification](spec/delegation-assertion.md) | The wire format, attenuation rules, chain verification, the AuthZEN binding, sequence evaluation, and a summary threat model. This is the document to review and argue with. |
| [Alternatives](alternatives.md) | What else exists, and why it does not close this gap. Maintained adversarially. |
| [Threat model](security/threat-model.md) | What is defended, from whom, what is assumed rather than enforced, and what is not yet covered. |
| [COAZ-MCP conformance](spec/coaz-mcp-conformance.md) | What of the AuthZEN COAZ-MCP binding is implemented, what is not, and the one place the output goes beyond it. |
| [Infrastructure](project/infrastructure.md) | Who holds each piece of project infrastructure today, per GOVERNANCE.md §5.4. |
| [Supply chain](security/supply-chain.md) | How to verify a release, what CI enforces, and the known gaps. |
| [Translations](i18n.md) | Which documents are translated, and why English stays normative. |

## Planned

The specification references these documents. They are not written yet, and are listed here so that a reader can tell a deliberate gap from an oversight. Each is tied to a release in [ROADMAP.md](../ROADMAP.md).

| Document | Contents | Due |
| --- | --- | --- |
| `spec/sequence-store.md` | What a replicated sequence store must guarantee for fail-closed behaviour to hold. The interface itself is `sequence.Store`; this is the prose a second implementation would need. | v0.3 |
| `compliance/eu-ai-act.md` | How the audit trail maps to the EU AI Act's Article 12 record-keeping and traceability obligations, which apply to Annex III systems from 2027-12-02 and Annex I ones from 2028-08-02. Written by engineers, not lawyers, and says so. | v0.3 |

If you need one of these sooner than its release, say so in an issue. Ordering is a guess about what matters and is easy to change.
