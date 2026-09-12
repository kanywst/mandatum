# Mandatum Delegation Assertion (MDA)

**English** | [日本語](delegation-assertion.ja.md)

Status: **Draft 0.1** — design document, not yet implemented. Last updated: 2026-09-12

## 1. Problem

An AI agent that acts for a person today almost always does so by *inheriting a credential*: a service account, an API key, a shared OAuth token, or the human's own session. Three failures follow directly from that, and all three are measured, not hypothetical.

1. **No attribution.** Only 28% of organizations can trace an agent's actions back to a human sponsor across all environments, and 68% cannot reliably distinguish agent activity from human activity (Cloud Security Alliance, *State of NHI and AI Security*, January 2026).
2. **No selective revocation.** Because agents share the credential they inherited, revoking one agent revokes every principal using that credential. This is the *credential piggybacking* failure mode.
3. **No sequence-level control.** Authorization is evaluated per call. An agent can be individually authorized for every request in a series while the *series* produces an outcome nobody authorized. Current protocols cannot express a constraint over a sequence of actions, only over one action.

The Model Context Protocol's own authorization layer states its scope limit explicitly: authorization is defined at the transport level, and per-tool authorization, agent identity, delegation and consent are out of scope. The Enterprise-Managed Authorization extension (stable, 2026-06-18) says the same in its own words — it governs the connection, not the individual tool call.

Mandatum addresses exactly that gap and nothing else.

## 2. Non-goals

Stating these first, because the failure mode for a project in this space is scope creep into territory that is already occupied.

- **Not a new authorization engine.** Mandatum never decides. It carries the facts a decision needs and calls a Policy Decision Point that already exists (OPA, Cedar, OpenFGA, SpiceDB, Cerbos, or any AuthZEN-conformant PDP).
- **Not a new wire protocol.** Delegation is expressed with JOSE, issued with RFC 8693 token exchange, and evaluated with the OpenID AuthZEN Authorization API 1.0. Where an existing standard fits, Mandatum uses it unchanged.
- **Not a gateway.** Mandatum ships as a library and as middleware. It is meant to run *inside* agentgateway, ToolHive, an MCP server, or an agent runtime — not to replace any of them.
- **Not a registry, sandbox, or agent runtime.** Those categories are occupied.
- **Not a blockchain.** The audit log is an RFC 6962-style Merkle tree. There is no consensus protocol, no network, and no token.

## 3. Prior art

Mandatum's attenuation model is not novel and does not claim to be. Capability attenuation with offline verification is the contribution of macaroons (Birgisson et al., 2014) and, in a modern form, Biscuit. SPIFFE established cryptographic workload identity. RFC 8693 established token exchange with delegation semantics (`actor_token`, the `act` claim). RFC 6962 established tamper-evident logging.

What Mandatum adds to that body of work is narrow and specific:

- a chain **rooted in an authenticated human sponsor**, carried unmodified to every leaf, so attribution survives arbitrary sub-delegation;
- **sequence-scoped constraints** evaluated across a chain's whole action history, not per call;
- a **binding to the AuthZEN Authorization API**, so the chain becomes input to any conformant PDP rather than to one vendor's engine.

If a reviewer concludes that an existing project already does these three things, that is a reason to contribute there instead. See `docs/alternatives.md`.

## 4. Terminology

| Term | Meaning |
| --- | --- |
| Sponsor | The authenticated human principal at the root of a chain. |
| Agent | A non-human principal holding a delegated capability set. |
| MDA | Mandatum Delegation Assertion — one signed link in a chain. |
| Chain | An ordered list of MDAs from sponsor to the acting agent. |
| Leaf | The last MDA in a chain; identifies the agent performing the action. |
| PEP | Policy Enforcement Point; verifies the chain and calls the PDP. |
| PDP | Policy Decision Point; an AuthZEN-conformant authorization service. |
| Attenuation | Narrowing of a capability set from parent to child. |

## 5. Delegation Assertion format

An MDA is a JWS in compact serialization (RFC 7515) whose payload is a JWT claims set (RFC 7519). Registered claims carry their normal meaning. All Mandatum-specific claims live under a single `mdt` claim to avoid collisions.

```json
{
  "iss": "spiffe://example.org/ns/agents/planner",
  "sub": "spiffe://example.org/ns/agents/retriever",
  "aud": "https://mcp.example.org",
  "iat": 1789200000,
  "exp": 1789203600,
  "jti": "01JB2X9K7P4Q8R3N6M0V5T2Y7C",
  "mdt": {
    "v": 1,
    "root": {
      "iss": "https://idp.example.org",
      "sub": "u-8f31c02e",
      "amr": ["pwd", "hwk"],
      "auth_time": 1789199400
    },
    "parent": "sha-256:UNhY4JhezH9gQYqvDMWrWH9CwlcKiECVqejMrND2VFw",
    "depth": 1,
    "max_depth": 2,
    "cap": [
      {
        "resource": { "type": "mcp_tool", "id": "search.query" },
        "action": { "name": "invoke" },
        "conditions": { "args.index": { "in": ["public", "docs"] } }
      }
    ],
    "seq": {
      "max_invocations": 200,
      "constraints": [
        { "id": "no-write-after-external-read",
          "forbid": { "action": "invoke", "resource.type": "mcp_tool",
                      "resource.tags": ["mutating"] },
          "after": { "resource.tags": ["external-content"] } }
      ]
    }
  }
}
```

### 5.1 Digest encoding

Every digest in this specification is written `sha-256:<value>`, where `<value>` is the base64url encoding of the raw 32-byte SHA-256 output **without padding**, as defined by RFC 7515 §2 (`BASE64URL`). This is the encoding JOSE already uses, so an implementation handling JWS has it available.

Stating this is not pedantry. `mdt.parent` is the commitment that makes chain splicing detectable, and two implementations that encode the same hash differently reject every chain the other produces.

Test vectors, so an implementer can check an encoder against this document rather than against prose:

| Input | Digest |
| --- | --- |
| `the empty string` | `sha-256:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU` |
| `example` | `sha-256:UNhY4JhezH9gQYqvDMWrWH9CwlcKiECVqejMrND2VFw` |
| `mandatum` | `sha-256:jUMrViVq7f3wcuQ44n0wJz5BNoNwIcxeu0MS7PGfEZI` |

Every digest appearing in the examples in this document is a real value computed this way, not a placeholder.

A verifier MUST compare digests as exact strings after checking the `sha-256:` prefix. It MUST NOT decode and re-encode before comparing, and MUST NOT accept a different encoding of the same hash: accepting several spellings of one value reintroduces the ambiguity this section exists to remove.

Only `sha-256` is defined. A verifier MUST reject any other prefix rather than attempt it, so that a future algorithm is a deliberate version bump rather than something an old verifier silently tolerates.

### 5.2 Claim semantics

| Claim | Required | Meaning |
| --- | --- | --- |
| `iss` | yes | The delegator. For depth 0 this is the sponsor's issuing authority. |
| `sub` | yes | The delegatee. A SPIFFE ID or other stable agent identifier. |
| `exp` | yes | Expiry. Must not exceed the parent's `exp`. |
| `jti` | yes | Unique identifier. The unit of revocation. |
| `mdt.v` | yes | Format version. `1` for this document. |
| `mdt.root` | yes | The human sponsor. Byte-identical across every link in a chain. |
| `mdt.parent` | yes | Hash of the parent MDA, or `null` at depth 0. |
| `mdt.depth` | yes | Zero-based index of this link. It orders the chain; it does not bound it. |
| `mdt.max_depth` | yes | How many further delegations are permitted below this assertion. Zero means the holder may act but may not sub-delegate. Falls by at least one per hop, so the sponsor's value bounds the whole chain. Never negative. |
| `mdt.cap` | yes | Capability set. May be empty, meaning no authority. |
| `mdt.seq` | no | Sequence-scoped constraints. Absent means no sequence limits. |

### 5.3 Why depth and max_depth are separate

`depth` says where a link sits; `max_depth` says how much further delegation may go. Tying the two together — for instance requiring `max_depth` to exceed `depth` — looks tidier and is wrong: combined with the per-hop decrease in §6 it halves the usable budget, because the limit falls as the position rises and they meet in the middle.

Keeping them independent means a sponsor granting `max_depth` of *n* gets exactly *n* sub-delegations, which is what an operator writing that number expects.

### 5.4 Why the sponsor is copied, not referenced

`mdt.root` is duplicated into every link rather than resolved by following the chain. A verifier that receives a partial chain, or that wants to index audit records by sponsor without a full verification pass, can then still attribute the action. The duplication is checked for consistency during verification (rule V6), so it cannot be used to forge attribution.

## 6. Attenuation rules

For every link *i* > 0, all of the following MUST hold. Together these make the chain monotonically non-widening.

1. `cap(i)` ⊆ `cap(i-1)` — every capability in the child is entailed by some capability in the parent. Entailment is defined in §6.1.
2. `exp(i)` ≤ `exp(i-1)`
3. `max_depth(i)` ≤ `max_depth(i-1) − 1`, and `max_depth(i)` ≥ 0. Together these make the budget strictly decreasing and finite, which is what bounds chain length.
4. `depth(i)` = `depth(i-1) + 1`
5. `seq(i)` is at least as restrictive as `seq(i-1)`: numeric budgets do not increase, and the constraint set is a superset.
6. `root(i)` is byte-identical to `root(i-1)`.

A child that violates any rule is not a valid delegation. There is no "escalation with approval" path in the format; raising authority requires a new chain issued from the sponsor.

### 6.1 Capability entailment

Capability `c` is entailed by parent capability `p` when the resource pattern of `c` is a subset of `p`'s, the action set of `c` is a subset of `p`'s, and `c`'s conditions are at least as restrictive as `p`'s. Condition comparison is performed on a decidable fragment only: set membership, string equality, prefix match, and numeric ranges. Conditions outside that fragment are rejected at issuance rather than approximated at verification, so that entailment is never decided by an incomplete check.

This is a deliberate limitation. An undecidable condition language would force verifiers to fail open or fail closed on inputs the issuer believed were valid.

Two edge cases, stated because implementations otherwise guess at them:

- An `in` condition with an empty list matches nothing. It is therefore the narrowest restriction expressible, and any parent condition entails it. Such a capability can never apply, which is useless but not unsafe; rejecting it would mean a delegator could not explicitly grant nothing on a key.
- A condition with no comparison set, or with more than one, is invalid and MUST be rejected at issuance. A condition with none set would restrict nothing, and one with several would require a combination rule this fragment deliberately does not define.

## 7. Chain verification

Input: an ordered chain `[MDA₀ … MDAₙ]`, a trust bundle, a revocation oracle, and the current time.

- **V1 Structure.** `MDA₀.mdt.parent` is `null` and `MDA₀.mdt.depth` is 0. For every *i* > 0, `MDA(i).mdt.parent` equals `sha-256` over the compact serialization of `MDA(i-1)`.
- **V2 Custody.** For every *i* > 0, `MDA(i).iss` equals `MDA(i-1).sub`. A delegator may only delegate authority it holds.
- **V3 Signatures.** Every MDA verifies against a key resolved for its `iss` through the SPIFFE trust bundle or the issuer's JWKS. Algorithm is taken from a fixed allowlist; `none` and symmetric algorithms are rejected.
- **V4 Time.** For every link, `iat` ≤ now < `exp`, with a bounded skew.
- **V5 Attenuation.** Every rule in §6 holds.
- **V6 Root consistency.** `mdt.root` is byte-identical across all links.
- **V7 Depth.** `n` ≤ `MDA₀.mdt.max_depth`, where `n` is the number of delegation hops, one fewer than the number of links.
- **V8 Revocation.** No `jti` in the chain appears in the revocation set.
- **V9 Audience.** The leaf's `aud` matches the verifying resource server.

Verification is offline except for V3 key resolution and V8, both of which are cacheable. A verifier MUST NOT accept a chain on partial verification.

V7 is redundant in the current rule set: V5 forces `max_depth` to fall by at least one per hop and §5.2 forbids it going negative, so any chain that would violate V7 is already rejected by V5. It is retained as defence in depth against a later relaxation of V5. Implementations should test it directly rather than leave it as an unreachable branch.

### 7.1 Revocation semantics

Revoking any `jti` invalidates that link **and every chain that descends from it**, because descendants commit to it through `mdt.parent`. This is the property that answers credential piggybacking: a sponsor can kill one agent's authority, including everything it sub-delegated, without touching sibling chains or any other principal.

Revocation state is distributed as a compact set (a Bloom filter with a published false-positive rate, plus an exact fallback lookup) so that PEPs can evaluate V8 locally. A false positive denies rather than allows.

## 8. AuthZEN binding

A verified chain becomes the subject context of an OpenID AuthZEN Authorization API 1.0 evaluation request. Mandatum does not extend the API; it populates it.

```json
{
  "subject": {
    "type": "identity",
    "id": "u-8f31c02e",
    "properties": { "iss": "https://idp.example.org" }
  },
  "action": { "name": "tools/call" },
  "resource": {
    "type": "tool",
    "id": "search.query",
    "properties": {
      "server": "https://mcp.example.org",
      "arguments": { "index": "public" }
    }
  },
  "context": {
    "agent": "spiffe://example.org/ns/agents/retriever",
    "mandatum.delegation": {
      "sponsor": {
        "iss": "https://idp.example.org",
        "sub": "u-8f31c02e",
        "amr": ["pwd", "hwk"],
        "auth_time": 1789199400
      },
      "chain": "sha-256:LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ",
      "actors": [
        "spiffe://example.org/ns/agents/planner",
        "spiffe://example.org/ns/agents/retriever"
      ],
      "depth": 1,
      "leaf": "01JB2XA4M0RN5S8Q2K7T3W1Y9D"
    }
  }
}
```

The shape of `subject`, `action`, `resource` and `context.agent` is the COAZ-MCP default mapping for `tools/call`, unchanged. Under that binding `subject` is the principal on whose behalf access is requested and `context.agent` is the acting client, which is exactly the split a sponsor-rooted chain already has: the human goes in `subject`, the leaf agent in `context.agent`.

`context.agent` carries one hop and never a chain. The binding says upstream actors are separately addressable and leaves where they go undefined, so Mandatum puts them under a vendor-prefixed key rather than inventing a name inside the binding's namespace. Its presence is itself a claim: a PEP populates it only from a chain that passed every rule in §7, so a PDP may rely on it for the same reason it may rely on `subject.id`.

`actors` answers "who was upstream". `chain` is what makes it more than a list — it commits to the exact links, so a sequence of actors cannot be reassembled from pieces of other chains. Whether the commitment is necessary, or a verified list is enough, is genuinely open; see §12.

The chain is verified **before** the PDP is called. The PDP receives a statement of fact ("this agent holds a valid chain rooted in this human") and applies organizational policy on top. Separating the two means an operator can change policy without changing credential handling, and a compromised PDP cannot manufacture authority that no sponsor granted.

Where the OIDF COAZ-MCP binding (WG draft, June 2026) specifies a mapping from MCP tool calls to AuthZEN requests, Mandatum follows it rather than defining a parallel one. Divergences are tracked in `docs/spec/coaz-mcp-conformance.md`.

## 9. Sequence-level evaluation

This is the part with no existing implementation, so it is specified carefully.

A **sequence** is the ordered history of actions performed under one chain root. The PEP maintains, per chain root, an append-only history and a derived state:

```text
  state = fold(evaluate_constraint, initial, history)
```

Each constraint in `mdt.seq.constraints` is a predicate over the history that must hold *after* appending the candidate action. If appending would falsify any constraint, the action is denied with a reason naming the constraint `id`.

The worked example in §5 encodes the lethal pattern that per-call authorization structurally cannot catch: an agent reads untrusted external content, then performs a mutating action. Each step is individually authorized. The pair is the exfiltration.

Two properties are required and shape the implementation:

- **Bounded state.** History cannot grow without limit. Constraints are compiled to a finite automaton over action *tags*, so per-chain state is a fixed-size vector regardless of history length. Constraints that do not compile are rejected at issuance.
- **Fail-closed on state loss.** If a PEP cannot read the sequence state for a chain that declares `mdt.seq`, it denies. Sequence constraints that silently degrade to per-call checks are worse than no constraints, because operators would believe they are protected.

Sequence state is per chain root and is therefore shared across PEPs. The reference implementation supports a single-process store for development and a replicated store for production; the interface is defined in `docs/spec/sequence-store.md`.

## 10. Audit trail

Every decision — allow and deny — appends one record to a tamper-evident log:

| Field | Purpose |
| --- | --- |
| `root` | The human sponsor. Enables the attribution query. |
| `chain` | Digest of the full verified chain. |
| `leaf_jti` | The acting agent's link. The revocation handle. |
| `action`, `resource` | What was attempted. |
| `decision` | Allow or deny. |
| `reason` | Structured reason code, including the constraint `id` on denial. |
| `policy_revision` | The PDP's policy or bundle version. |
| `seq_index` | Position in the chain's action sequence. |
| `ts` | Timestamp. |

`policy_revision` is mandatory because without it a decision cannot be replayed: re-evaluating against today's policy answers a different question than the one the log records. The absence of this field in existing decision logs is the reason "why was this denied?" is currently unanswerable in practice.

The log is an RFC 6962-style Merkle tree. Inclusion and consistency proofs let an auditor verify that no record was altered or removed. The EU AI Act's high-risk obligations, applicable since 2026-08-02, require immutable logging and traceable delegation chains; this section exists to satisfy that requirement, and the mapping is documented in `docs/compliance/eu-ai-act.md`.

## 11. Threat model

Summarized here; the full model is in `docs/security/threat-model.md`.

| Threat | Mitigation |
| --- | --- |
| Forged delegation | V3 signature verification against a trust bundle. |
| Chain splicing | V1 parent hash commitment; links are not interchangeable. |
| Privilege escalation via sub-delegation | §6 attenuation, enforced at verify time, not issue time. |
| Replay after revocation | V8 with fail-closed distribution. |
| Confused deputy | V2 custody rule plus V9 audience binding. |
| Attribution stripping | V6 root consistency; `root` cannot be dropped or rewritten. |
| Log tampering | Merkle inclusion and consistency proofs. |
| Sequence-state evasion | Fail-closed on state loss; state keyed by chain root, not by PEP. |
| PDP compromise | A PDP can deny, and can allow only within the chain's capability set. It cannot widen authority. |

The last row is a deliberate design property: verification precedes and constrains the policy decision, so the PDP is not fully trusted.

## 12. Open questions

Honest list. These are unresolved and feedback is wanted.

1. Should `mdt.root` carry an assurance level (`acr`) so policy can require step-up authentication for high-impact sequences?
2. Is the finite-automaton constraint language expressive enough for real operator needs, or does it need bounded counting beyond simple budgets?
3. Should Mandatum define its own revocation distribution, or adopt an existing status mechanism (OAuth Status Lists) unchanged?
4. How should chains behave across trust domains? SPIFFE federation gives a key resolution answer but not a policy answer for cross-domain sponsorship.
5. Is a delegation chain the right shape for multi-sponsor scenarios — an agent acting for two people at once — or does that need a different structure?

## 13. References

- OpenID AuthZEN Authorization API 1.0 (Final Specification, 2026-01-11)
- OpenID AuthZEN COAZ-MCP Binding 1.0 (Working Group Draft, 2026-06)
- Model Context Protocol specification 2026-07-28, Authorization
- MCP Enterprise-Managed Authorization (stable, 2026-06-18)
- RFC 6962 — Certificate Transparency
- RFC 7515 — JSON Web Signature
- RFC 7519 — JSON Web Token
- RFC 8693 — OAuth 2.0 Token Exchange
- RFC 9728 — OAuth 2.0 Protected Resource Metadata
- SPIFFE ID and SVID specifications
- draft-ietf-wimse-arch, draft-ietf-wimse-s2s-protocol
- draft-klrc-aiagent-auth-03 — AI Agent Authentication and Authorization
- Birgisson et al., *Macaroons: Cookies with Contextual Caveats* (2014)
- Cloud Security Alliance, *State of NHI and AI Security* (2026-01)
- Regulation (EU) 2024/1689 (AI Act), high-risk obligations applicable 2026-08-02
