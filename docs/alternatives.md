# Alternatives

Last updated: 2026-09-12.

This document exists to answer one question honestly: **does something already
solve this, and should Mandatum exist?**

It is maintained adversarially. If an entry below becomes wrong — because a
project ships the missing capability — the right response is to update this
file and reconsider whether Mandatum should continue, not to defend the
project's existence. Corrections are welcome as issues or pull requests.

The three capabilities Mandatum claims are missing in combination:

- **R — Rooted attribution.** Every action traces to an authenticated human
  sponsor, and that binding survives arbitrary sub-delegation.
- **S — Sequence constraints.** Policy can constrain a series of actions, not
  only individual calls.
- **N — Engine neutrality.** The decision goes to any conformant Policy
  Decision Point rather than one vendor's engine.

## Summary

| Project or standard | R | S | N | Why it does not close the gap |
| --- | --- | --- | --- | --- |
| MCP core authorization (2026-07-28) | no | no | n/a | Scoped to transport. Per-tool authorization, agent identity, delegation and consent are explicitly out of scope. |
| MCP Enterprise-Managed Authorization | partial | no | no | Stable 2026-06-18. Governs the connection, not the tool call — it says so itself. IdP-issued, so attribution exists at connect time but does not follow sub-delegation. |
| OpenID AuthZEN Authorization API 1.0 | n/a | no | yes | The decision interface Mandatum targets, not a competitor. Defines PEP-to-PDP; says nothing about how a subject came to hold authority. |
| AuthZEN COAZ-MCP Binding | n/a | no | yes | Working Group Draft, June 2026. Specifies the MCP-to-AuthZEN mapping. Mandatum implements it. Few implementers exist. |
| ToolHive | no | no | no | Real per-tool authorization, but wired directly to Cedar. Engine lock-in, no delegation chain, no sequence state. |
| agentgateway | no | no | partial | Gateway and data plane. The natural host for Mandatum, not a substitute — it enforces what something else decides. |
| Microsoft Entra Agent ID | yes | no | no | Solves attribution well, inside the Microsoft ecosystem. Not vendor-neutral, not deployable elsewhere. |
| AWS Bedrock AgentCore Gateway | partial | no | no | Cedar-based, AWS-bound. |
| SPIFFE / SPIRE | no | no | n/a | Workload identity. Answers "what is this workload", not "on whose authority does it act". Mandatum builds on it. |
| IETF WIMSE drafts | no | no | n/a | The workload-identity half. Mandatum's chain rides on it. |
| RFC 8693 token exchange | partial | no | n/a | The `act` claim expresses one delegation hop. No attenuation rules, no depth limit, no chain verification, no sequence. Mandatum uses it for issuance. |
| Macaroons | no | no | n/a | The origin of attenuated capabilities with offline verification. No human root, no sequence constraints, no authorization-API binding. Direct prior art. |
| Biscuit | no | partial | no | Modern attenuated tokens with an embedded Datalog policy language. Closest technical relative. Attenuation is per-token; there is no sponsor root and no cross-call sequence state, and the policy language is Biscuit's own rather than a decision handed to an external PDP. |
| OpenFGA / SpiceDB / Cerbos / OPA / Cedar | n/a | no | n/a | Engines. They answer a question. Mandatum decides what question to ask and proves the asker's authority. |
| Guardrails libraries (guardrails-ai, NeMo) | no | partial | no | Content filtering on model input and output. Different layer; no identity, no authority, no audit of authorization decisions. |
| SIEM and audit platforms | no | no | n/a | Record the terminal API call. Miss the decision chain that produced it. |

## The entries worth arguing about

Most rows above are clear. Three are not, and the case for Mandatum depends on
them being right.

### Biscuit

Biscuit is the strongest counterargument to building Mandatum. It has offline
attenuation, cryptographic soundness, a real policy language, and an existing
community.

The distinction claimed here is that Biscuit attenuates *a token* while
Mandatum attenuates *a chain rooted in a person*, and that Biscuit's policy
evaluation is internal to the token rather than delegated to an external PDP
that an organization already runs. Sequence-level constraints have no Biscuit
equivalent that we found.

If those distinctions are thinner than claimed, the better path is a Biscuit
profile rather than a new format. This is an open question the project would
like answered by people who know Biscuit well.

### Enterprise-Managed Authorization

EMA is recent, well designed, and backed by real deployments. It uses ID-JAG so
an identity provider issues agent authority based on organizational policy,
which is genuine rooted attribution at the point of connection.

It is listed as not closing the gap because the specification states its own
limit: it governs a connection, not individual tool calls, and it does not
model sub-delegation. An agent that spawns a sub-agent is outside its model.
Mandatum aims to compose with EMA — EMA to establish the connection, Mandatum
to carry authority through the tool calls made over it — rather than to
replace it.

### agentgateway

agentgateway is the Agentic AI Foundation's gateway and handles MCP and A2A at
the data plane. It could implement rooted delegation itself, and if it does,
Mandatum's enforcement middleware becomes redundant.

The project's answer is to ship as a plugin for agentgateway rather than
compete with it, and to treat upstream absorption of the library as a success
rather than a loss. The specification and the verifier are the durable part;
the middleware is a delivery mechanism.

## Standards work in flight

Adjacent efforts that Mandatum should track and, where possible, feed rather
than duplicate:

- **draft-klrc-aiagent-auth-03** (July 2026) — authors from Okta, AWS, Ping,
  Zscaler, OpenAI, Defakto. Takes the position that agent authentication should
  compose WIMSE and OAuth rather than invent a new protocol. Mandatum agrees
  with that position and should align with the draft rather than diverge.
- **draft-sharif-agent-audit-trail-00** (March 2026) — tamper-evident audit
  chaining for agents. Overlaps Mandatum's log section. If it matures,
  Mandatum should adopt it rather than define a parallel format.
- **`modelcontextprotocol/ext-auth` issue #14** — proposes AuthZEN integration
  for MCP. Open since February 2026 without a maintainer response.
- **CNCF TOC #1746** — TAG Workloads Foundation, solicits agent observability
  schemas and policy interfaces.
- **CNCF TOC #1890** — TAG Security and Compliance, MCP authentication and
  authorization standards whitepaper.

## Telling us we are wrong

If you believe an existing project already provides R, S and N together, open
an issue titled `alternatives: <project>` with a pointer to the capability. A
report that makes this project unnecessary is a good outcome and will be
credited as such.
