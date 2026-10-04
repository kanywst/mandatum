# COAZ-MCP conformance

Last checked against the AuthZEN COAZ-MCP Binding 1.0 Working Group Draft (June 2026): 2026-10-04, at the draft's revision of 2026-09-10. That date is when the mapping was last read against the draft, which is the claim worth dating; it is not when this file was last edited, and `git log` has that.

[The specification](delegation-assertion.md) §8 says Mandatum follows the COAZ-MCP binding rather than defining a parallel mapping. This is where that claim is made checkable: what is implemented, what is not, and the one place the output goes beyond what the binding defines.

The binding is a working group draft and will move. Anything here can become wrong without this project changing, which is why the date at the top matters.

## What is implemented

Two things are implemented: the binding's default mapping for `tools/call`, and declared mappings for `tools/call`, with the CEL the binding requires to evaluate them.

### The default mapping

`authzen.ToolCallRequest` produces the binding's default mapping for `tools/call`. The authority for what it emits is the test named at the foot of this document, which asserts each field; the table renders that test in prose, and the worked JSON in [the specification](delegation-assertion.md) §8 renders it as an example. If the three ever disagree, the test is right and the other two are stale.

| Binding | Mandatum |
| --- | --- |
| `subject.type` | `identity` |
| `subject.id`, from the subject-identity claim | the chain's sponsor, the human at the root |
| `context.agent`, from `$token.?client_id` | the leaf agent: the principal actually acting |
| `action.name` | `tools/call` |
| `resource.type` | `tool` |
| `resource.id`, from `$params.name` | the tool name |

The subject-identity claim deserves a note. The binding says `subject.id` is conventionally `$token.sub`, and that a deployment issuing tokens with the agent as principal MAY designate an on-behalf-of claim instead so that `subject.id` carries the human. A Mandatum chain has the human at its root by construction, so the sponsor is used directly and no claim designation is needed. A deployment that also uses OAuth for the same call should make sure the two agree on who the subject is.

Arguments and the server identifier go in `resource.properties`. The binding does not define them there. Its default `tools/call` mapping is a fixed object with no `properties` on either subject or resource, and the place it provides for projecting `$params.arguments` is a declared mapping. So these fields are ours, and §Divergences says so. A tool that declares a mapping does not get them: its mapping is the projection.

### Declared mappings

`authzen.ParseMapping` reads a tool's `x-authzen-mapping`, and `authzen.MappingFromInputSchema` finds one in a tool's `inputSchema` as a `tools/list` response carries it. Every expression is compiled when the mapping is parsed, so a mapping that cannot work is refused when the deployment loads it rather than on the first call. `pkg/mcp` uses a mapping when the deployment's catalog returns one for the tool in `Facts.Mapping`, and the default mapping otherwise.

What follows the binding as written:

- Both envelopes, `evaluation` and `evaluations`. Anything else at the top level is a mapping error.
- Literals verbatim, a leading `$` for a CEL expression, `$$` for a literal `$`.
- Optional selection (`.?`) omits a field whose key is missing; plain selection on a missing key is an error, as is an absent or null required field.
- No `subject` inside an `evaluations` entry. That is refused when the mapping is parsed, not when it is used.
- Under `evaluations`, the top-level members are defaults that an entry's member replaces whole, as the Authorization API defines them, and the call is allowed only if every decision is a permit.
- Fail-closed: a mapping error refuses the call, and the PDP is not asked.

The binding exposes two variables to expressions, `params` and `token`. `params` is `{"name": …, "arguments": …}` from the call; `_meta` is not in it, because the chain travels there and a server's expressions have no business reading it. `token` is the binding's word for "the validated access token", and Mandatum has no access token. What it has is a verified chain, which establishes the same facts and is checked at least as hard. So `token` is those facts, under the claim names the binding's expressions read: `sub` and `iss` are the sponsor, `client_id` is the acting agent, and `amr` and `auth_time` are present when the sponsor's grant carries them. `$token.sub`, `$token.?client_id` and the other expressions in the binding's examples resolve to what they mean there.

Three values in every request are pinned to verification rather than taken from the mapping: `subject.id` is the sponsor, `subject.properties.iss` is the sponsor's issuer, and `context.agent` is the acting agent. A mapping that leaves one out has it supplied. A mapping that sets one to anything else is a mapping error. The first of the three is stricter than the binding, and §Divergences says why.

Two more things are not in the binding:

- **The grant is checked first.** A declared mapping decides what the PDP is asked and nothing else. The chain's own capability check, §8 step 2 of [the specification](delegation-assertion.md), runs before the mapping is resolved and against the deployment's description of the tool, not the mapping's. A server that declares a mapping can change the question the PDP answers; it cannot change what the sponsor delegated.
- **Expressions are bounded.** A declared mapping is written by the server being authorized, so its expressions are untrusted code on the enforcement point's path. Each one runs under a CEL cost limit, `authzen.MaxExpressionCost`, and what they produce for one call is bounded separately, by `authzen.MaxResolvedValues` and `authzen.MaxResolvedBytes`, because CEL charges for referencing a value and not for its size: an expression that maps a long list onto another is cheap to evaluate and enormous once it is JSON. Exceeding either bound is a mapping error. A key in `subject.properties` or `context` that is not one of the pinned keys but folds to one, such as `iſſ` for `iss`, is a mapping error too, since a PDP decoding JSON case-insensitively would read it in place of the pinned value.

## What is not implemented

- **Only `tools/call`.** The binding gives default mappings for `tools/list`, `resources/list`, `resources/read`, `resources/subscribe`, `resources/unsubscribe`, `prompts/list`, `prompts/get`, `completion/complete`, `logging/setLevel`, and the four `tasks/*` methods as well. None of those are mapped.
- **Neither of the binding's two catch-all behaviours.** `ping` and `notifications/*` are pass-through: "the PEP MUST NOT call the PDP for them and MUST allow them to proceed". A method with neither a default nor a declared mapping "MUST be denied". Both are normative PEP requirements rather than mappings, and a PEP built on this library has to implement them itself, fail-closed included.

  `pkg/mcp.Enforcer.Middleware` is now such a PEP, and it does not implement them: it enforces `tools/call` and forwards every other method to the server behind it. That is deliberate and it is a divergence, not an oversight — a delegation chain says nothing about `tools/list`, and this middleware is a per-call layer above MCP's own transport authorization rather than a replacement for it. A deployment that needs the binding's deny-by-default over unmapped methods has to add it, and should not read "Mandatum follows the COAZ-MCP binding" as saying it is already there. Server-initiated requests need nothing: the binding puts them out of scope for this version.
- **Declared mappings are not learned from `tools/list`.** The binding's gateway shape has the PEP observe the `tools/list` response it proxies and take each tool's mapping from there. `pkg/mcp.Enforcer.Middleware` does not read responses; a deployment supplies mappings through its catalog, from wherever it obtained them, and `authzen.MappingFromInputSchema` reads one out of a tool's `inputSchema` for that purpose.
- **The Access Evaluations API is not called.** An `evaluations` mapping is resolved into one Access Evaluation request per entry, which is the fallback the binding allows a PEP whose PDP lacks the batch API. It is used unconditionally, so it works against every PDP, at the cost of a round trip per entry.
- **Only the binding's CEL.** The environment is CEL's standard library with optional types. No extension library is loaded, so an expression using, say, string functions from an extension does not compile and the mapping is refused.

## The one addition

`context` carries a vendor-prefixed `mandatum.delegation` object alongside `context.agent`.

What the binding says about `context.agent` is that it carries the agent identity, typically `$token.?client_id`, and that separating it from `subject` lets a policy judge the user and the agent independently. It defines no place for the hops in between. It does not say one exists, or that a chain does not belong in `context.agent`; it simply does not address the question, and this project should not put words in it. The prefixed key stays out of the binding's namespace so a future version cannot collide with it, and so a PDP reading only what the binding defines is unaffected.

Whether the binding should define a place for it is open, and being discussed in the `context.agent` trust-semantics thread, [openid/authzen#612](https://github.com/openid/authzen/issues/612). The editor has proposed there that `context.agent` "never carries a delegation chain" and that "upstream actors are separately addressable", which is the reading this document assumed before checking. That is a proposal in an open issue awaiting a chair's read, not binding text and not a resolution. If it lands, this object moves wherever the binding names, and this document records the move.

## Divergences

All of these are ours rather than the binding's.

The `_meta` key a chain travels in, specification §8.1, is defined by this project. The binding maps an MCP request onto an evaluation request; it says nothing about how a delegation chain reaches the PEP, because it has no delegation chain. The key sits under a reverse-DNS prefix MCP's own rules mark as third-party, so nothing here occupies a name either specification might later want.

`resource.properties` and `subject.properties` in the emitted request are not part of the default `tools/call` mapping, which is a fixed object with neither. The binding's own mechanism for projecting arguments into a request is a declared mapping, and the section on omitted inputs is explicit that a decision covers only the request the selected mapping constructed. Sending more than the mapping defines does not break a PDP that ignores unknown members, but it is a wider request than the binding specifies, and a policy written against these fields would not port to a conforming PEP.

A declared mapping cannot override `subject.id`. The binding lets it, as a SHOULD-warn edge case for "an agentic deployment whose access token is issued to the agent while the identity of the acting user is carried outside the token". A chain always carries the user — at its root, signed — so the case the override exists for does not arise, and allowing it would let the server being authorized assert whose call this is. Mandatum refuses it as a mapping error. It does the same for `context.agent`, which the binding says a mapping must include and does not say must be the token's agent, and for `subject.properties.iss`, which is ours to begin with.

`pkg/mcp.Enforcer.Middleware` answers every refusal with JSON-RPC error code `403` and HTTP status 403. The binding's codes are `-32602` for a mapping error, `-32001` for a denial and `-32603` for a PDP failure. The middleware's reason for its own code is recorded where the constant is defined: MCP asks that new codes for purposes it does not define be allocated outside the JSON-RPC reserved range, and the binding's `-32001` is inside it. The refusing stage, including `mapping`, is in the error's `data`.

The mapping's six defined fields match field for field. That has not been checked against an interoperability suite, and the AuthZEN conformance program does not yet cover this binding. Until it does, the claim means the mapping was read from the draft and implemented field by field, with a test asserting each field, and nothing more.

## How to check

```bash
go test -run TestToolCallRequestFollowsTheCoazMapping ./pkg/authzen/ -v
```

This is the authoritative statement of the mapping. It asserts each field above, including the two that are easiest to get backwards: the human in `subject` and the acting agent in `context.agent`. A change to the mapping that does not break this test is a change nobody checked.

For declared mappings, the binding's own examples are the tests:

```bash
go test -run 'TestTheBindings|TestAMappingCannotNameAnotherIdentity|TestMalformedMappingsAreRefusedAtParse' ./pkg/authzen/ -v
```

`TestTheBindingsSingleEvaluationExample` and `TestTheBindingsMultiEvaluationExample` resolve the `get_customer` and `copy_object` mappings from the draft and assert the requests the draft shows, with the chain in place of the token. `FuzzDeclaredMapping` holds the anchoring as an invariant over arbitrary mappings: whatever a mapping says, a request it resolves to names the sponsor, the sponsor's issuer and the acting agent, or there is no request.
