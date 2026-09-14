# Alternatives

Last updated: 2026-09-13.

This document exists to answer one question honestly: **does something already solve this, and should Mandatum exist?**

It is maintained adversarially. If an entry below becomes wrong — because a project ships the missing capability — the right response is to update this file and reconsider whether Mandatum should continue, not to defend the project's existence. Corrections are welcome as issues or pull requests.

The three capabilities Mandatum claims are missing in combination:

- **R — Rooted attribution.** Every action traces to an authenticated human sponsor, and that binding survives arbitrary sub-delegation.
- **S — Sequence constraints.** Policy can constrain a series of actions, not only individual calls.
- **N — Engine neutrality.** The decision goes to any conformant Policy Decision Point rather than one vendor's engine.

## Summary

| Project or standard | R | S | N | Why it does not close the gap |
| --- | --- | --- | --- | --- |
| MCP core authorization (2026-07-28) | no | no | n/a | Scoped to transport: how a client obtains a token for a server. Defines nothing about per-tool authorization, agent identity, delegation or consent — it does not declare them out of scope, it does not address them, and MCP's authorization interest group has open work on the first and last. |
| MCP Enterprise-Managed Authorization | partial | no | no | Stable 2026-06-18. Defines how a client turns an enterprise identity assertion into an access token, so what it produces is scoped to a server rather than a tool call. Attribution exists at connect time and does not follow sub-delegation. |
| OpenID AuthZEN Authorization API 1.0 | n/a | no | yes | The decision interface Mandatum targets, not a competitor. Defines PEP-to-PDP; says nothing about how a subject came to hold authority. |
| AuthZEN COAZ-MCP Binding | n/a | no | yes | Working Group Draft, June 2026. Specifies the MCP-to-AuthZEN mapping. Mandatum implements it. Few implementers exist. |
| ToolHive | no | no | no | Real per-tool authorization, but wired directly to Cedar. Engine lock-in, no delegation chain, no sequence state. |
| agentgateway | no | no | partial | Gateway and data plane. The natural host for Mandatum, not a substitute — it enforces what something else decides. |
| Microsoft Entra Agent ID | yes | no | no | Solves attribution well, inside the Microsoft ecosystem. Not vendor-neutral, not deployable elsewhere. |
| AWS Bedrock AgentCore Gateway | partial | no | no | Cedar-based, AWS-bound. |
| SPIFFE / SPIRE | no | no | n/a | Workload identity. Answers "what is this workload", not "on whose authority does it act". Mandatum builds on it. |
| IETF WIMSE drafts | no | no | n/a | The workload-identity half. Mandatum's chain rides on it. |
| RFC 8693 token exchange | no | no | n/a | Nested `act` claims record prior actors, but §4.1 puts them out of reach: a consumer "MUST only consider the token's top-level claims and the party identified as the current actor". Prior actors are informational. See "RFC 8693 and §4.1" below. |
| Macaroons | no | no | n/a | The origin of attenuated capabilities that can be delegated offline, without contacting the issuer. Verification is not offline: it is HMAC-chained, so the verifier needs the root secret, and third-party caveats need discharge macaroons. No human root, no sequence constraints, no authorization-API binding. Direct prior art. |
| `draft-mcguinness-oauth-actor-profile-00` | no | no | n/a | Identifies the current delegated actor at the resource server, with `(act.iss, act.sub)` as the canonical identifier. Says in its own words that it does not provide per-hop cryptographic provenance, and never mentions attenuation. See "The OAuth Actor Profile drafts" below. |
| `draft-mcguinness-oauth-actor-proofs-00` | no | no | n/a | Layers signed, hash-chained per-hop proofs on the profile above. Authenticity of participation, not evidence that authority did not widen. |
| Biscuit | no | partial | no | Modern attenuated tokens with an embedded Datalog policy language. Closest technical relative. Attenuation is per-token; there is no sponsor root and no cross-call sequence state, and the policy language is Biscuit's own rather than a decision handed to an external PDP. |
| OpenFGA / SpiceDB / Cerbos / OPA / Cedar | n/a | no | n/a | Engines. They answer a question. Mandatum decides what question to ask and proves the asker's authority. |
| Guardrails libraries (guardrails-ai, NeMo) | no | partial | no | Content filtering on model input and output. Different layer; no identity, no authority, no audit of authorization decisions. |
| SIEM and audit platforms | no | no | n/a | Record the terminal API call. Miss the decision chain that produced it. |

## RFC 8693 and §4.1

Worth its own section, because the obvious reading of Mandatum is "a chain of prior actors, which is what `act` is for", and that reading makes it look like a violation.

RFC 8693 §4.1 says a consumer of a token "MUST only consider the token's top-level claims and the party identified as the current actor by the `act` claim", and that "Prior actors identified by any nested `act` claims are informational only and are not to be considered in access control decisions". The `MUST` sits on the positive obligation; the sentence about prior actors carries no RFC 2119 keyword of its own and follows from it.

That is a deliberate model rather than an omission. The paragraph before it says the current actor "is considered to include the entire authorization/delegation history", and §4.4 gives the authorization server `may_act` as the gate on whether a delegation may happen at all. The chain's weight is spent when the token is issued. The resource server authorizes the current actor and nothing behind it.

**Mandatum does not use nested `act`, and is not an attempt to make it authoritative.** A Delegation Assertion chain is a separate credential: each link is independently signed, commits to its parent by hash, and is checked to have narrowed. Those are properties `act` does not carry and was not built to, which is why reading one as the other gets the comparison wrong in both directions.

What follows honestly from §4.1 is that authorizing on a delegation history at the resource server is an extension of the RFC 8693 model, not a gap in it. Mandatum is that extension. A deployment doing both should know it is relying on Mandatum's verification for the chain, and on RFC 8693 only for issuance.

This section exists because @arjun2075 corrected the project's earlier reading in [openid/authzen#612](https://github.com/openid/authzen/issues/612), where these documents had described the RFC as silent on what a resource server should do with a chain.

## The entries worth arguing about

Most rows above are clear. Three are not, and the case for Mandatum depends on them being right.

### Biscuit

Biscuit is the strongest counterargument to building Mandatum. It has offline attenuation, cryptographic soundness, a real policy language, and an existing community.

The distinction claimed here is that Biscuit attenuates *a token* while Mandatum attenuates *a chain rooted in a person*, and that Biscuit evaluates policy in-process in its own Datalog rather than over a standard protocol to a PDP an organization already runs. To be precise about Biscuit, because an earlier version of this file was not: a token carries *checks*, and only the authorizer — the application — supplies `allow`/`deny` policies and runs the engine. So the token restricts; it does not decide. Sequence-level constraints have no Biscuit equivalent that we found.

If those distinctions are thinner than claimed, the better path is a Biscuit profile rather than a new format. This is an open question the project would like answered by people who know Biscuit well.

### Enterprise-Managed Authorization

EMA is recent, well designed, and backed by real deployments. It uses ID-JAG so an identity provider issues agent authority based on organizational policy, which is genuine rooted attribution at the point of connection.

It is listed as not closing the gap for a reason inferred here rather than stated there: an access token derived from an identity assertion is scoped to a server, so it governs a connection rather than individual tool calls, and nothing in the extension models sub-delegation. An agent that spawns a sub-agent is outside its model. Mandatum aims to compose with EMA — EMA to establish the connection, Mandatum to carry authority through the tool calls made over it — rather than to replace it.

### The OAuth Actor Profile drafts

Of everything in the summary table, `draft-mcguinness-oauth-actor-profile` most deserves scrutiny, because it occupies the same ground: identifying who is acting in a delegated call, at the resource server, in a standards-track document.

Where it stops is stated in the draft rather than inferred here. Section 3.5:

> This structure records delegated-actor history within the trust model of the issuer that conveys it; it does not, by itself, provide independent cryptographic provenance for each prior hop.

And on why that is deliberate rather than an omission, section 3.7:

> This profile does not define per-actor confirmation members within nested `act` objects. Stronger prior-hop key provenance, if needed, would require another profile layered on top of this one...

The words "attenuation", "narrow" and "least privilege" do not appear in the document at all. It is a profile for identifying and classifying the current actor, not for constraining what that actor may do relative to whoever delegated to it.

`draft-mcguinness-oauth-actor-proofs` is the layered profile that answers the provenance half: each visible hop signs its own participation, hash-chained. That is authenticity of participation. It is still not a proof that authority did not widen — an actor can sign truthfully that it participated while granting onward more than it held.

So the comparison is narrow and worth stating precisely. These drafts answer "who acted, and can we trust the record of who acted". Mandatum answers "and did any of them widen". If the actor-proofs work grows a non-widening property, that would be a reason to build on it rather than beside it, and this file should record that rather than defend the separation.

### agentgateway

agentgateway is the Agentic AI Foundation's gateway and handles MCP and A2A at the data plane. It could implement rooted delegation itself, and if it does, Mandatum's enforcement middleware becomes redundant.

The project's answer is to ship as a plugin for agentgateway rather than compete with it, and to treat upstream absorption of the library as a success rather than a loss. The specification and the verifier are the durable part; the middleware is a delivery mechanism.

## Standards work in flight

Adjacent efforts that Mandatum should track and, where possible, feed rather than duplicate:

- **draft-klrc-aiagent-auth-03** (July 2026) — authors from Okta, AWS, Ping, Zscaler, OpenAI, Defakto. Takes the position that agent authentication should compose WIMSE and OAuth rather than invent a new protocol. Mandatum agrees with that position and should align with the draft rather than diverge.
- **draft-sharif-agent-audit-trail** — tamper-evident audit chaining for agents; -00 in March 2026, -03 in September 2026. Overlaps Mandatum's log section. If it matures, Mandatum should adopt it rather than define a parallel format.
- **`modelcontextprotocol/ext-auth` issue #14** — proposed AuthZEN integration for MCP in February 2026. Maintainers replied that nothing in it needs to go into the protocol itself, and the discussion moved on. An earlier version of this file said the issue had gone unanswered, which was simply wrong. The live thread is issue #15, a SEP for parameter-level authorization mapping, last active June 2026.
- **draft-mcguinness-oauth-actor-profile-00** (30 April 2026, individual, intended Standards Track) — the closest standards work to what Mandatum does with a chain. Distinguishes the represented subject (`sub`), the OAuth client registration (`client_id`) and the current delegated actor, making `(act.iss, act.sub)` the canonical actor identifier and requiring `act.iss`, which RFC 8693 leaves optional. Unlike RFC 8693 it gives the resource server processing rules. It is worth reading before assuming Mandatum's model is unprecedented; see "The OAuth Actor Profile drafts" above for where it stops.
- **draft-mcguinness-oauth-actor-proofs-00** (4 July 2026) — layers signed per-hop proofs on the profile above, hash-chained. Structurally the nearest thing to a Mandatum chain in the IETF space.
- **draft-mw-oauth-actor-chain** — actor chains over RFC 8693; -01 as of June 2026. It defines actor-signed step proofs with cumulative commitment state, which is close enough to Mandatum's model that reading it closely is overdue rather than optional. Doing so is the next entry to rewrite in this file.
- **CNCF TOC #1746** — TAG Workloads Foundation, solicits agent observability schemas and policy interfaces.
- **CNCF TOC #1890** — TAG Security and Compliance, MCP authentication and authorization standards whitepaper.

## Telling us we are wrong

If you believe an existing project already provides R, S and N together, open an issue titled `alternatives: <project>` with a pointer to the capability. A report that makes this project unnecessary is a good outcome and will be credited as such.
